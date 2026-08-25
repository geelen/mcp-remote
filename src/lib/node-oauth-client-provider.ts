import open from 'open'
import { z } from 'zod'
import { OAuthClientProvider, refreshAuthorization, selectResourceURL } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { log, debugLog, buildRedirectUrl, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import { getAuthorizationServerUrl, type ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * The OAuth token response only carries the relative `expires_in`, which is
 * useless once persisted to disk. We extend the SDK token schema with an
 * absolute `expires_at` timestamp so later reads can detect imminent expiry
 * and refresh proactively. The base schema uses `.strip()`, which would
 * otherwise drop `expires_at` on read, so we parse and serialize tokens with
 * this extended schema instead.
 */
export const OAuthTokensWithExpiresAtSchema = OAuthTokensSchema.extend({
  expires_at: z.coerce.number().optional(),
})
type OAuthTokensWithExpiresAt = z.infer<typeof OAuthTokensWithExpiresAtSchema>

/** The shape of the state we issue, and the only shape accepted into a config filename. */
const ISSUED_STATE = /^[A-Za-z0-9-]{1,64}$/

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull
  private authorizeResource: string | undefined
  private skipResourceParameter: boolean
  /**
   * Overrides how the SDK picks the RFC 8707 `resource` indicator. Only defined when we have
   * an opinion; otherwise the SDK derives it from Protected Resource Metadata as usual.
   */
  validateResourceURL?: (defaultResource: URL, discoveredResource?: string) => Promise<URL | undefined>
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private incomingState: string | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  /** In-flight proactive refresh, so concurrent requests share one refresh_token use */
  private refreshInFlight: Promise<OAuthTokensWithExpiresAt | undefined> | null = null

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    const trimmedAuthorizeResource = options.authorizeResource?.trim()
    this.authorizeResource = trimmedAuthorizeResource ? trimmedAuthorizeResource : undefined
    this.skipResourceParameter = options.skipResourceParameter ?? false
    this._state = randomUUID()
    this._clientInfo = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope

    // The SDK feeds one `resource` value into the authorization, token and refresh requests
    // (selectResourceURL -> startAuthorization / fetchToken / refreshAuthorization). Deciding
    // it here keeps those three in agreement, which RFC 8707 §2.2 requires - previously the
    // authorize URL was rewritten after the fact, so it could disagree with the token request.
    if (this.skipResourceParameter) {
      this.validateResourceURL = async () => {
        debugLog('Resource parameter disabled; omitting it from authorization and token requests')
        return undefined
      }
    } else if (this.authorizeResource) {
      const resourceUrl = new URL(this.authorizeResource)
      this.validateResourceURL = async () => resourceUrl
    }
    // Otherwise left undefined so the SDK applies its default resource selection.
  }

  setCallbackPort(port: number): void {
    this.options.callbackPort = port
  }

  get redirectUrl(): string {
    return buildRedirectUrl(this.options.host, this.options.callbackPort, this.callbackPath)
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
      ...(effectiveScope ? { scope: effectiveScope } : {}),
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    const resourceScopes = this.protectedResourceMetadata?.scopes_supported
    if (resourceScopes !== undefined) {
      if (resourceScopes.length === 0) {
        debugLog('Protected resource advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = resourceScopes.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: resourceScopes,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if advertised
    const authScopes = this.authorizationServerMetadata?.scopes_supported
    if (authScopes !== undefined) {
      if (authScopes.length === 0) {
        debugLog('Authorization server advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = authScopes.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: authScopes,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default when metadata is unknown or omits scopes_supported
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    debugLog('Token request stack trace:', new Error().stack)

    const tokens = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)

    if (tokens) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      // Use the persisted absolute expiry timestamp to detect imminent expiry,
      // refreshing ~60s early to avoid sending a token that is about to 401.
      const isExpired = tokens.expires_at ? Date.now() >= tokens.expires_at - 60_000 : false

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresAt: tokens.expires_at ? new Date(tokens.expires_at).toISOString() : 'unknown',
        isExpired,
      })

      // Renew before the token is sent rather than after the server rejects it.
      // Waiting for a 401 assumes the server answers expiry with exactly 401 -
      // one that replies 400 or 403 instead never reaches the SDK's refresh path
      // and the connection just fails (see issue #273).
      if (isExpired && tokens.refresh_token) {
        const refreshed = await this.refreshTokens(tokens.refresh_token)
        if (refreshed) {
          return refreshed
        }
        // Refresh failed: hand back what we have and let the SDK's own 401
        // handling take it from here, exactly as it did before.
        log('Proactive token refresh failed, falling back to the stored token')
      }
    } else {
      debugLog('Token result: Not found')
    }

    return tokens
  }

  /**
   * Exchanges a refresh token for a new access token, reusing the same authorization
   * server, client credentials and RFC 8707 resource indicator the SDK would have
   * picked, so the refresh request agrees with the authorization that produced it.
   *
   * Concurrent callers share one attempt: `tokens()` runs on every outgoing request,
   * and with refresh token rotation a second, parallel use of the same token can
   * invalidate the whole chain rather than merely wasting a round trip.
   *
   * @param refreshToken The refresh token to redeem
   * @returns The refreshed tokens, or undefined if the refresh could not be completed
   */
  private async refreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.doRefreshTokens(refreshToken).finally(() => {
        this.refreshInFlight = null
      })
    }
    return this.refreshInFlight
  }

  private async doRefreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    try {
      const clientInformation = await this.clientInformation()
      if (!clientInformation) {
        debugLog('No client information available, cannot refresh proactively')
        return undefined
      }

      const metadata = await this.getAuthorizationServerMetadata()
      const authorizationServerUrl =
        (this.protectedResourceMetadata ? getAuthorizationServerUrl(this.protectedResourceMetadata) : undefined) ??
        new URL('/', this.options.serverUrl).toString()
      const resource = await selectResourceURL(new URL(this.options.serverUrl), this, this.protectedResourceMetadata)

      debugLog('Refreshing access token before it expires', { authorizationServerUrl, resource: resource?.toString() })

      // The SDK types metadata as the full OIDC discovery document, while ours is
      // the RFC 8414 subset. Only these two fields reach the token request
      // (executeTokenRequest), so narrow to them rather than cast the whole object.
      const tokenRequestMetadata = metadata
        ? ({
            token_endpoint: metadata.token_endpoint,
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
          } as Parameters<typeof refreshAuthorization>[1]['metadata'])
        : undefined

      const refreshed = await refreshAuthorization(authorizationServerUrl, {
        metadata: tokenRequestMetadata,
        clientInformation,
        refreshToken,
        resource,
      })

      // Goes through saveTokens so the new expiry is persisted the same way
      await this.saveTokens(refreshed)
      log('Refreshed the access token before it expired')

      return OAuthTokensWithExpiresAtSchema.parse({
        ...refreshed,
        expires_at: refreshed.expires_in ? Date.now() + refreshed.expires_in * 1000 : undefined,
      })
    } catch (error) {
      debugLog('Proactive token refresh failed', error)
      return undefined
    }
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const timeLeft = tokens.expires_in || 0

    // Alert if expires_in is invalid
    if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
      debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
        expiresIn: tokens.expires_in,
        tokenObject: JSON.stringify(tokens),
        stack: new Error('Invalid expires_in value').stack,
      })
    }

    debugLog('Saving tokens', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: `${timeLeft} seconds`,
      expiresInValue: tokens.expires_in,
    })

    // Persist an absolute expiry timestamp alongside the token so that future
    // reads can detect imminent expiry and refresh proactively (the spec only
    // provides the relative `expires_in`, which is meaningless once stored).
    const tokensToSave: OAuthTokensWithExpiresAt = {
      ...tokens,
      expires_at: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined,
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokensToSave)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    const effectiveScope = this.getEffectiveScope()
    if (effectiveScope) {
      authorizationUrl.searchParams.set('scope', effectiveScope)
      debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })
    } else {
      debugLog('Omitting scope parameter from authorization URL (no effective scope)')
    }

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   *
   * The filename is scoped to this flow's authorization state rather than to the process, so a
   * code can still be redeemed by an instance that took the callback port over from the one that
   * started the flow. See https://github.com/geelen/mcp-remote/issues/235.
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, this.codeVerifierFile(this._state), codeVerifier)
  }

  /**
   * Records the state a code came back with, so the flow that produced it decides which verifier
   * redeems it
   * @param state The state from the callback
   */
  useAuthorizationState(state: string): void {
    if (!ISSUED_STATE.test(state)) {
      log('Ignoring an authorization state this client could not have issued')
      debugLog('Rejected authorization state', { state })
      return
    }
    this.incomingState = state
  }

  /** The flow this instance is redeeming for: another instance's when a code names it. */
  private get flowState(): string {
    return this.incomingState ?? this._state
  }

  private codeVerifierFile(state: string): string {
    return `code_verifier_${state}.txt`
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, this.codeVerifierFile(this.flowState), 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState)),
        ])
        this._clientInfo = undefined
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState))
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
