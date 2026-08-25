import { readJsonFile } from './mcp-auth-config'
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { log, debugLog, setupOAuthCallbackServerWithLongPoll, MCP_REMOTE_ID_PATH } from './utils'

/** How long a secondary instance waits for the primary to persist the tokens it just obtained. */
const TOKEN_HANDOFF_TIMEOUT_MS = 30_000
const TOKEN_HANDOFF_POLL_INTERVAL_MS = 200

export type AuthCoordinator = {
  initializeAuth: () => Promise<{ server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean; actualPort: number }>
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
  let authState: { server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean; actualPort: number } | null = null

  return {
    initializeAuth: async () => {
      // If auth has already been initialized, return the existing state
      if (authState) {
        debugLog('Auth already initialized, reusing existing state')
        return authState
      }

      log('Initializing auth coordination on-demand')
      debugLog('Initializing auth coordination on-demand', { serverUrlHash, callbackPort })

      // Initialize auth using the existing coordinateAuth logic
      authState = await coordinateAuth(serverUrlHash, callbackPath, callbackPort, events, authTimeoutMs, strictPort)
      debugLog('Auth coordination completed', { skipBrowserAuth: authState.skipBrowserAuth, actualPort: authState.actualPort })
      return authState
    },
  }
}

/**
 * Waits for the primary instance to persist the tokens it obtained.
 *
 * The owner's callback server receives a code strictly before it has exchanged it for
 * authorization code, which is strictly earlier than the code being exchanged and the result
 * written to disk. Reconnecting in that window reads no tokens and 401s again, so poll for the
 * file rather than guessing at a fixed delay.
 *
 * @param serverUrlHash The hash of the server URL
 * @returns True if tokens showed up before the timeout
 */
export async function waitForTokensFromPrimary(serverUrlHash: string, timeoutMs = TOKEN_HANDOFF_TIMEOUT_MS): Promise<boolean> {
  const deadline = Date.now() + timeoutMs

  while (true) {
    const tokens = await readJsonFile(serverUrlHash, 'tokens.json', OAuthTokensSchema)
    if (tokens) {
      debugLog('Tokens from the primary instance are on disk')
      return true
    }

    if (Date.now() >= deadline) {
      log(`Timed out after ${Math.round(timeoutMs / 1000)}s waiting for the other instance to write its tokens`)
      return false
    }

    await new Promise((resolve) => setTimeout(resolve, TOKEN_HANDOFF_POLL_INTERVAL_MS))
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

/** Whether a usable access token is already on disk, so no sign-in is needed at all. */
export async function hasUsableTokens(serverUrlHash: string): Promise<boolean> {
  return tokensOnDisk(serverUrlHash)
}

/** Tokens another instance has already obtained, if they are on disk and usable. */
async function tokensOnDisk(serverUrlHash: string): Promise<boolean> {
  const tokens = await readJsonFile(serverUrlHash, 'tokens.json', OAuthTokensSchema)
  return !!tokens
}

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
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean }> {
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
      if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw error

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
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean }> {
  const deadline = Date.now() + TOKEN_HANDOFF_TIMEOUT_MS

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
