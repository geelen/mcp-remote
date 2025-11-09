import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import {
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
  refreshAuthorization,
  selectResourceURL,
} from '@modelcontextprotocol/sdk/client/auth.js'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import {
  listServerHashesWithTokens,
  readServerRegistration,
  readTokenState,
  releaseRefreshLock,
  ServerRegistration,
  TokenState,
  tryAcquireRefreshLock,
  writeTokenState,
} from './mcp-auth-config'
import { debugLog, log } from './utils'

/**
 * Periodically scans persisted OAuth sessions and proactively refreshes their access tokens
 * using the stored refresh tokens. This keeps both the CLI and proxy processes authenticated
 * without forcing users back through the interactive browser flow when tokens expire.
 */

const DEFAULT_INTERVAL_MS = 60_000
const DEFAULT_LEAD_MS = 10 * 60_000
const DEFAULT_LOCK_TTL_MS = 2 * 60_000
const DEFAULT_FAILURE_BACKOFF_MS = 5 * 60_000

export interface TokenRefreshManagerOptions {
  enabled?: boolean
  intervalMs?: number
  leadTimeMs?: number
  lockTtlMs?: number
  failureBackoffMs?: number
}

export class TokenRefreshManager {
  private timer: NodeJS.Timeout | null = null
  private stopped = true
  private readonly intervalMs: number
  private readonly leadTimeMs: number
  private readonly lockTtlMs: number
  private readonly failureBackoffMs: number
  private readonly enabled: boolean
  private failureBackoff = new Map<string, number>()

  constructor(options: TokenRefreshManagerOptions = {}) {
    this.intervalMs = options.intervalMs ?? DEFAULT_INTERVAL_MS
    this.leadTimeMs = options.leadTimeMs ?? DEFAULT_LEAD_MS
    this.lockTtlMs = options.lockTtlMs ?? DEFAULT_LOCK_TTL_MS
    this.failureBackoffMs = options.failureBackoffMs ?? DEFAULT_FAILURE_BACKOFF_MS
    this.enabled = options.enabled ?? false
  }

  /**
   * Begins running the background scan loop if auto-refresh is enabled.
   */
  start() {
    if (!this.enabled) {
      debugLog('Token refresh manager disabled')
      return
    }
    if (!this.stopped) {
      return
    }
    this.stopped = false
    this.scheduleNextScan(0)
  }

  /**
   * Stops the background scan loop and clears any pending timers.
   */
  stop() {
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    this.stopped = true
  }

  /**
   * Queues the next scan after the provided delay. No-op when the manager has been stopped.
   */
  private scheduleNextScan(delayMs: number) {
    if (this.stopped) {
      return
    }
    this.timer = setTimeout(() => {
      this.runScan()
        .catch((error) => {
          log('Token refresh manager error:', error)
        })
        .finally(() => {
          this.scheduleNextScan(this.intervalMs)
        })
    }, delayMs)
  }

  /**
   * Iterates over every server hash that currently has saved tokens and attempts a refresh
   * when the tokens are nearing expiration.
   */
  private async runScan() {
    const serverHashes = await listServerHashesWithTokens()
    if (serverHashes.length === 0) {
      debugLog('Token refresh manager: no servers with stored tokens')
      return
    }

    for (const serverUrlHash of serverHashes) {
      try {
        await this.refreshIfNeeded(serverUrlHash)
      } catch (error) {
        log(`Token refresh failed for server hash ${serverUrlHash}: ${this.formatError(error)}`)
        debugLog('Token refresh failure details', {
          serverUrlHash,
          stack: (error as Error).stack,
        })
      }
    }
  }

  /**
   * Checks a single server entry and refreshes its tokens when it is close to expiration,
   * respecting inter-process locks and failure backoff windows.
   */
  private async refreshIfNeeded(serverUrlHash: string) {
    const now = Date.now()
    debugLog('Refresh scan evaluating server', { serverUrlHash, isoNow: new Date(now).toISOString() })
    const failureUntil = this.failureBackoff.get(serverUrlHash)
    if (failureUntil && failureUntil > now) {
      debugLog('Skipping refresh due to backoff', {
        serverUrlHash,
        isoNow: new Date(now).toISOString(),
        nextEligibleAt: new Date(failureUntil).toISOString(),
        millisUntilRetry: failureUntil - now,
      })
      return
    }

    const registration = await readServerRegistration(serverUrlHash)
    if (!registration) {
      debugLog('Skipping refresh - server registration missing', { serverUrlHash })
      return
    }

    const provider = this.createProvider(serverUrlHash, registration)
    const tokens = await provider.tokens()

    if (!tokens) {
      debugLog('No tokens available for refresh', { serverUrlHash })
      return
    }

    if (!tokens.refresh_token) {
      debugLog('Stored tokens do not include a refresh_token', { serverUrlHash })
      return
    }

    const state = await readTokenState(serverUrlHash)
    if (!isTokenExpiringSoon(state, this.leadTimeMs)) {
      if (state?.expiresAt) {
        debugLog('Token not yet within refresh window', {
          serverUrlHash,
          ...formatTimingDebug(state.expiresAt, this.leadTimeMs, now),
        })
      } else {
        debugLog('Token state unavailable or missing expiry, skipping refresh window check', {
          serverUrlHash,
          isoNow: new Date(now).toISOString(),
        })
      }
      return
    }

    if (state?.expiresAt) {
      debugLog('Token requires refresh', {
        serverUrlHash,
        ...formatTimingDebug(state.expiresAt, this.leadTimeMs, now),
      })
    } else {
      debugLog('Token marked for refresh despite missing expiry metadata', {
        serverUrlHash,
        isoNow: new Date(now).toISOString(),
      })
    }

    const acquired = await tryAcquireRefreshLock(serverUrlHash, this.lockTtlMs)
    if (!acquired) {
      debugLog('Skipped refresh because another process holds the lock', { serverUrlHash })
      return
    }

    if (state?.expiresAt) {
      log(`Refreshing OAuth tokens for ${registration.serverUrl}`, formatTimingDebug(state.expiresAt, this.leadTimeMs, now))
    } else {
      log(`Refreshing OAuth tokens for ${registration.serverUrl}`, { isoNow: new Date(now).toISOString() })
    }

    try {
      await this.performRefresh(serverUrlHash, registration, provider, tokens.refresh_token)
      this.failureBackoff.delete(serverUrlHash)
      log(`Refreshed OAuth tokens for ${registration.serverUrl}`)
    } catch (error) {
      this.failureBackoff.set(serverUrlHash, Date.now() + this.failureBackoffMs)
      const message = this.formatError(error)
      log(`Failed to refresh OAuth tokens for ${registration.serverUrl}: ${message}`)
      await writeTokenState(serverUrlHash, {
        lastRefreshAttempt: Date.now(),
        lastRefreshError: message,
      })
      debugLog('Token refresh attempt failed', {
        serverUrlHash,
        error: message,
        stack: (error as Error).stack,
      })
      return
    } finally {
      await releaseRefreshLock(serverUrlHash)
    }
  }

  /**
   * Constructs a minimal OAuth client provider used solely for the refresh exchange.
   */
  private createProvider(serverUrlHash: string, registration: ServerRegistration) {
    return new NodeOAuthClientProvider({
      serverUrl: registration.serverUrl,
      callbackPort: registration.callbackPort ?? 0,
      host: registration.host ?? 'localhost',
      authorizeResource: registration.authorizeResource,
      staticOAuthClientMetadata: registration.staticOAuthClientMetadata,
      staticOAuthClientInfo: registration.staticOAuthClientInfo,
      serverUrlHash,
      clientName: 'MCP CLI Auto Refresh',
    })
  }

  /**
   * Executes the OAuth refresh token grant and persists any returned credentials/metadata.
   */
  private async performRefresh(
    serverUrlHash: string,
    registration: ServerRegistration,
    provider: NodeOAuthClientProvider,
    refreshToken: string,
  ) {
    const clientInformation = await provider.clientInformation()
    if (!clientInformation) {
      throw new Error('Missing OAuth client registration information')
    }

    const { authorizationServerUrl, metadata, resource } = await this.resolveAuthorizationContext(registration.serverUrl, provider)

    debugLog('Attempting token refresh', {
      serverUrlHash,
      authorizationServerUrl: authorizationServerUrl.toString(),
      resource: resource?.toString(),
    })

    const newTokens = await refreshAuthorization(authorizationServerUrl, {
      metadata,
      clientInformation,
      refreshToken,
      resource,
      addClientAuthentication: provider.addClientAuthentication,
    })

    await provider.saveTokens(newTokens)
    await writeTokenState(serverUrlHash, {
      lastRefreshAttempt: Date.now(),
      lastRefreshError: undefined,
    })
  }

  /**
   * Discovers the relevant authorization server metadata and resource indicators to reuse
   * during refresh exchanges.
   */
  private async resolveAuthorizationContext(serverUrl: string, provider: NodeOAuthClientProvider) {
    let resourceMetadata: Awaited<ReturnType<typeof discoverOAuthProtectedResourceMetadata>> | undefined
    let authorizationServerUrl: string | URL | undefined

    try {
      resourceMetadata = await discoverOAuthProtectedResourceMetadata(serverUrl)
      if (resourceMetadata?.authorization_servers?.length) {
        authorizationServerUrl = resourceMetadata.authorization_servers[0]
      }
    } catch (error) {
      debugLog('Failed to load protected resource metadata', {
        serverUrl,
        error: (error as Error).message,
      })
    }

    if (!authorizationServerUrl) {
      authorizationServerUrl = serverUrl
    }

    const metadata = await discoverAuthorizationServerMetadata(authorizationServerUrl, {})
    const resource = await selectResourceURL(serverUrl, provider, resourceMetadata)

    return { authorizationServerUrl, metadata, resource }
  }

  /**
   * Produces a concise error string for logging/backoff bookkeeping.
   */
  private formatError(error: unknown): string {
    if (error instanceof OAuthError) {
      const code = (error as any).errorCode ? ` (${(error as any).errorCode})` : ''
      return `${error.name}${code}: ${error.message}`
    }
    if (error instanceof Error) {
      return error.message
    }
    return String(error)
  }
}

function formatTimingDebug(expiresAt: number, leadTimeMs: number, now: number) {
  const refreshThreshold = expiresAt - leadTimeMs
  const millisUntilExpiry = expiresAt - now
  const millisUntilRefreshWindow = refreshThreshold - now

  return {
    isoNow: new Date(now).toISOString(),
    isoExpiresAt: new Date(expiresAt).toISOString(),
    isoRefreshThreshold: new Date(refreshThreshold).toISOString(),
    millisUntilExpiry,
    millisUntilRefreshWindow,
    secondsUntilExpiry: Math.max(0, Math.round(millisUntilExpiry / 1000)),
    secondsUntilRefreshWindow: Math.max(0, Math.round(millisUntilRefreshWindow / 1000)),
  }
}

/**
 * Helper that determines whether a token is expired or will expire within the provided lead time.
 */
export function isTokenExpiringSoon(state: TokenState | undefined, leadTimeMs: number, now: number = Date.now()): boolean {
  if (!state || typeof state.expiresAt !== 'number') {
    return false
  }
  if (state.expiresAt <= now) {
    return true
  }
  return state.expiresAt - now <= leadTimeMs
}
