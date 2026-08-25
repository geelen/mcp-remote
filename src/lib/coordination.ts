import { readJsonFile } from './mcp-auth-config'
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthTokensWithExpiresAtSchema } from './node-oauth-client-provider'
import { AuthCodeResult } from './types'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { log, debugLog, setupOAuthCallbackServerWithLongPoll, MCP_REMOTE_ID_PATH } from './utils'

/** How long a secondary instance waits for the primary to persist the tokens it just obtained. */
const TOKEN_HANDOFF_TIMEOUT_MS = 30_000
const TOKEN_HANDOFF_POLL_INTERVAL_MS = 200

export type AuthCoordinator = {
  initializeAuth: () => Promise<{
    server: Server
    waitForAuthCode: () => Promise<AuthCodeResult>
    skipBrowserAuth: boolean
    actualPort: number
  }>
}

/**
 * Creates a lazy auth coordinator that will only initiate auth when needed
 * @param serverUrlHash The hash of the server URL
 * @param callbackPath The path to serve the callback endpoint on
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @param strictPort If true, fail rather than fall back to a random port on EADDRINUSE
 * @returns An AuthCoordinator object with an initializeAuth method
 */
export function createLazyAuthCoordinator(
  serverUrlHash: string,
  callbackPath: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
  strictPort = false,
): AuthCoordinator {
  // The in-flight promise is what gets shared, not the resolved value. Guarding on the result
  // only rules out sequential re-entry: two 401s landing in the same tick would both find it
  // unset and both start a flow, and the loser of the resulting port race used to take the
  // process down with an unhandled EADDRINUSE (https://github.com/geelen/mcp-remote/issues/317).
  let authState: Promise<{
    server: Server
    waitForAuthCode: () => Promise<AuthCodeResult>
    skipBrowserAuth: boolean
    actualPort: number
  }> | null = null

  return {
    initializeAuth: async () => {
      if (authState) {
        debugLog('Auth already initializing or initialized, reusing it')
        return authState
      }

      log('Initializing auth coordination on-demand')
      debugLog('Initializing auth coordination on-demand', { serverUrlHash, callbackPort })

      authState = coordinateAuth(serverUrlHash, callbackPath, callbackPort, events, authTimeoutMs, strictPort)
      try {
        const resolved = await authState
        debugLog('Auth coordination completed', { skipBrowserAuth: resolved.skipBrowserAuth, actualPort: resolved.actualPort })
        return resolved
      } catch (error) {
        // A failed attempt must not be cached, or every later retry replays the same rejection
        authState = null
        throw error
      }
    },
  }
}

/**
 * Coordinates authentication between multiple instances of the client/proxy
 * @param serverUrlHash The hash of the server URL
 * @param callbackPath The path to serve the callback endpoint on
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @param strictPort If true, fail rather than fall back to a random port on EADDRINUSE
 * @returns An object with the server, actualPort, waitForAuthCode function, and a flag indicating if browser auth can be skipped
 */
/** How many ports after the deterministic one to try before giving up on strangers holding them. */
const PORT_CANDIDATES = 8

/** How often a follower checks whether the owner has finished, or has died and freed the port. */
const FOLLOWER_POLL_INTERVAL_MS = 250

/**
 * Asks whoever holds a port whether they are an mcp-remote serving this same server.
 *
 * A refused bind says the port is taken, not by what. Without this an unrelated process squatting
 * on the port would make every instance wait for a sign-in that is never coming.
 */
async function portHeldBySiblingFor(port: number, serverUrlHash: string): Promise<boolean> {
  try {
    const response = await fetch(`http://127.0.0.1:${port}${MCP_REMOTE_ID_PATH}`, {
      signal: AbortSignal.timeout(1000),
    })
    if (!response.ok) return false
    const body = (await response.json()) as { mcpRemote?: boolean; serverUrlHash?: string }
    return body?.mcpRemote === true && body.serverUrlHash === serverUrlHash
  } catch {
    // No answer, or not something that speaks our identity route
    return false
  }
}

/**
 * Whether the server answers an unauthenticated request with a challenge.
 *
 * Ownership has to be settled before the first connection attempt, because the SDK registers a
 * client from inside `transport.start()`. But that is only worth doing for a server that actually
 * wants OAuth: a public one, or one authenticated by `--header`, never writes tokens, so every
 * instance but the first would wait out the handoff timeout and exit.
 */
export async function serverIssuesAuthChallenge(serverUrl: string, headers: Record<string, string> = {}): Promise<boolean> {
  try {
    const response = await fetch(serverUrl, {
      method: 'GET',
      headers: { ...headers, accept: 'application/json, text/event-stream' },
      signal: AbortSignal.timeout(5000),
    })
    debugLog('Probed the server for an auth challenge', { status: response.status })
    return response.status === 401
  } catch (error) {
    // Unreachable or too slow to say. Leave it to the 401 handler, as before.
    debugLog('Could not probe the server for an auth challenge', error)
    return false
  }
}

/**
 * Whether the tokens on disk make a browser sign-in unnecessary.
 *
 * Not simply "a token exists": an expired one with a refresh token is renewed without the
 * browser, while an expired one without is exactly the case that needs a flow - and treating it
 * as usable is what let every instance skip coordination on re-authentication and open its own
 * tab, which is the storm of login windows people report after a token lapses.
 */
export async function hasUsableTokens(serverUrlHash: string): Promise<boolean> {
  const tokens = await readJsonFile<{ expires_at?: number; refresh_token?: string }>(
    serverUrlHash,
    'tokens.json',
    OAuthTokensWithExpiresAtSchema,
  )
  if (!tokens) return false
  if (tokens.expires_at && Date.now() >= tokens.expires_at - TOKEN_EXPIRY_MARGIN_MS) {
    return !!tokens.refresh_token
  }
  return true
}

/** Tokens another instance has already obtained, if they are on disk and usable. */
async function tokensOnDisk(serverUrlHash: string): Promise<boolean> {
  const tokens = await readJsonFile(serverUrlHash, 'tokens.json', OAuthTokensSchema)
  return !!tokens
}

/** Treat a token about to expire as expired, matching the provider's own refresh margin. */
const TOKEN_EXPIRY_MARGIN_MS = 60_000

/**
 * Takes ownership of a server's OAuth flow, or waits for whoever has it.
 *
 * Ownership *is* being bound to the callback port. That makes it atomic (the kernel admits one
 * listener), self-releasing (the port comes back when the process dies, however it dies), and
 * exactly the thing correctness depends on - an authorization code can only ever be delivered to
 * whoever holds the port named in its redirect_uri. A lockfile can only ever be a guess about
 * those facts, which is why the previous one needed liveness probes, staleness heuristics and a
 * carve-out disabling it on Windows.
 */
export async function coordinateAuth(
  serverUrlHash: string,
  callbackPath: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
  strictPort = false,
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean }> {
  debugLog('Coordinating authentication', { serverUrlHash, callbackPath, callbackPort })

  // Pinned by --port or by static client info: that exact port or nothing, since the redirect_uri
  // it implies is not ours to move.
  const candidates = strictPort ? [callbackPort] : Array.from({ length: PORT_CANDIDATES }, (_, i) => callbackPort + i)

  for (const port of candidates) {
    try {
      const { server, actualPort, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll({
        port,
        path: callbackPath,
        events,
        authTimeoutMs,
        serverUrlHash,
      })

      // Binding is only a mutex between instances contending for the *same* port. Instances that
      // were pushed past a port a stranger holds can race onto different candidates and each
      // conclude it won, so a later candidate has to yield to any sibling already established on
      // an earlier one. Lowest bound candidate wins, which every instance can agree on.
      const established = await firstSiblingBefore(candidates, port, serverUrlHash)
      if (established !== undefined) {
        debugLog('Yielding to a sibling established on an earlier candidate', { ours: actualPort, theirs: established })
        await new Promise<void>((resolve) => server.close(() => resolve()))
        return followUntilTokensOrPort(serverUrlHash, callbackPath, established, events, authTimeoutMs)
      }

      log(`This instance is running the sign-in for this server (callback port ${actualPort})`)
      return { server, actualPort, waitForAuthCode, skipBrowserAuth: false }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code
      if (code !== 'EADDRINUSE' && code !== 'EACCES') throw error

      if (code === 'EACCES') {
        // Reserved by the OS rather than held by anyone we can talk to
        debugLog(`Not permitted to bind port ${port}`, { serverUrlHash })
        if (strictPort) throw error
        continue
      }

      if (await portHeldBySiblingFor(port, serverUrlHash)) {
        log(`Another instance is running the sign-in for this server on port ${port}`)
        return followUntilTokensOrPort(serverUrlHash, callbackPath, port, events, authTimeoutMs)
      }

      // Somebody else's process. Ours is not there to be waited for, so keep looking.
      debugLog(`Port ${port} is held by an unrelated process`, { serverUrlHash })
      if (strictPort) throw error
    }
  }

  throw new Error(
    `Could not find a free callback port for this server (tried ${candidates[0]}-${candidates[candidates.length - 1]}). ` +
      `Close whatever is holding those ports, or pass --port to choose one.`,
  )
}

/** The earliest candidate before `port` that a sibling has taken, if any. */
async function firstSiblingBefore(candidates: number[], port: number, serverUrlHash: string): Promise<number | undefined> {
  for (const candidate of candidates) {
    if (candidate === port) return undefined
    if (await portHeldBySiblingFor(candidate, serverUrlHash)) return candidate
  }
  return undefined
}

/**
 * Waits for the instance that owns the flow, and takes over if it dies.
 *
 * The two exits need no timers or liveness checks of their own: tokens appearing means the owner
 * finished, and the port becoming bindable means the owner is gone and we are now the owner.
 */
async function followUntilTokensOrPort(
  serverUrlHash: string,
  callbackPath: string,
  port: number,
  events: EventEmitter,
  authTimeoutMs: number,
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean }> {
  // Bounded by how long a sign-in is allowed to take, not by a fixed handoff window: the person
  // at the browser may be going through SSO, MFA or a password manager.
  const deadline = Date.now() + Math.max(authTimeoutMs, TOKEN_HANDOFF_TIMEOUT_MS)

  while (Date.now() < deadline) {
    if (await tokensOnDisk(serverUrlHash)) {
      log('The sign-in was completed by another instance; using the tokens it wrote')
      // This instance never serves callbacks, so it reports the port it would have used rather
      // than a throwaway one - a port that looks changed makes callers re-register the client.
      const idleServer = express().listen(0, '127.0.0.1')
      return {
        server: idleServer,
        actualPort: port,
        waitForAuthCode: () =>
          Promise.reject(new Error('waitForAuthCode is not available in a follower; reconnect using the tokens on disk instead')),
        skipBrowserAuth: true,
      }
    }

    try {
      const { server, actualPort, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll({
        port,
        path: callbackPath,
        events,
        authTimeoutMs,
        serverUrlHash,
      })
      // The port came free, so the instance that had it is gone. Whatever tab it opened points
      // here, so its sign-in can still complete against this process.
      log(`The instance running the sign-in exited; taking it over on port ${actualPort}`)
      return { server, actualPort, waitForAuthCode, skipBrowserAuth: false }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw error
    }

    await new Promise((resolve) => setTimeout(resolve, FOLLOWER_POLL_INTERVAL_MS))
  }

  throw new Error(
    `Timed out waiting for another mcp-remote instance to finish signing in on port ${port}. ` + `Retry, or close the other instance.`,
  )
}
