import { checkLockfile, createLockfile, deleteLockfile, getConfigFilePath, readJsonFile, LockfileData } from './mcp-auth-config'
import { OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { AuthCodeResult } from './types'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { AddressInfo } from 'net'
import { readFileSync, unlinkSync } from 'fs'
import { log, debugLog, setupOAuthCallbackServerWithLongPoll } from './utils'

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
 * Checks if a process with the given PID is running
 * @param pid The process ID to check
 * @returns True if the process is running, false otherwise
 */
export async function isPidRunning(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0) // Doesn't kill the process, just checks if it exists
    debugLog(`Process ${pid} is running`)
    return true
  } catch (err) {
    debugLog(`Process ${pid} is not running`, err)
    return false
  }
}

/**
 * Checks if a lockfile is valid (process running and endpoint accessible)
 * @param lockData The lockfile data
 * @returns True if the lockfile is valid, false otherwise
 */
export async function isLockValid(lockData: LockfileData): Promise<boolean> {
  debugLog('Checking if lockfile is valid', lockData)

  // Check if the lockfile is too old (over 30 minutes)
  const MAX_LOCK_AGE = 30 * 60 * 1000 // 30 minutes
  if (Date.now() - lockData.timestamp > MAX_LOCK_AGE) {
    log('Lockfile is too old')
    debugLog('Lockfile is too old', {
      age: Date.now() - lockData.timestamp,
      maxAge: MAX_LOCK_AGE,
    })
    return false
  }

  // Check if the process is still running
  if (!(await isPidRunning(lockData.pid))) {
    log('Process from lockfile is not running')
    debugLog('Process from lockfile is not running', { pid: lockData.pid })
    return false
  }

  // Check if the endpoint is accessible
  try {
    debugLog('Checking if endpoint is accessible', { port: lockData.port })

    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 1000)

    const response = await fetch(`http://127.0.0.1:${lockData.port}/wait-for-auth?poll=false`, {
      signal: controller.signal,
    })

    clearTimeout(timeout)

    const isValid = response.status === 200 || response.status === 202
    debugLog(`Endpoint check result: ${isValid ? 'valid' : 'invalid'}`, { status: response.status })
    return isValid
  } catch (error) {
    log(`Error connecting to auth server: ${(error as Error).message}`)
    debugLog('Error connecting to auth server', error)
    return false
  }
}

/** How long to keep polling a sibling that stops answering before taking over. */
const UNREACHABLE_SIBLING_TIMEOUT = 6000

function readLockfileSync(serverUrlHash: string): LockfileData | null {
  try {
    return JSON.parse(readFileSync(getConfigFilePath(serverUrlHash, 'lock.json'), 'utf-8')) as LockfileData
  } catch {
    return null
  }
}

/**
 * Deletes the lockfile, unless another instance owns it
 *
 * An exiting duplicate must not strip the lock from the instance driving the flow.
 * @param serverUrlHash The hash of the server URL
 */
export async function deleteOwnLockfile(serverUrlHash: string): Promise<void> {
  const lockData = readLockfileSync(serverUrlHash)
  if (lockData && lockData.pid !== process.pid) {
    debugLog('Leaving lockfile owned by another instance', { owner: lockData.pid, self: process.pid })
    return
  }
  await deleteLockfile(serverUrlHash)
}

/**
 * Synchronous counterpart of {@link deleteOwnLockfile}, for the 'exit' event
 * @param serverUrlHash The hash of the server URL
 */
export function deleteOwnLockfileSync(serverUrlHash: string): void {
  const lockData = readLockfileSync(serverUrlHash)
  if (lockData && lockData.pid !== process.pid) {
    debugLog('Leaving lockfile owned by another instance', { owner: lockData.pid, self: process.pid })
    return
  }
  const configPath = getConfigFilePath(serverUrlHash, 'lock.json')
  unlinkSync(configPath)
  debugLog(`Removed lockfile on exit: ${configPath}`)
}

/**
 * Waits for authentication from another server instance
 * @param port The port to connect to
 * @param lockData The lockfile entry describing the instance we are waiting on, when known
 * @returns True if authentication completed successfully, false otherwise
 */
export async function waitForAuthentication(port: number, lockData?: LockfileData): Promise<boolean> {
  log(`Waiting for authentication from the server on port ${port}...`)

  try {
    let attempts = 0
    let unreachableSince: number | null = null
    while (true) {
      attempts++
      const url = `http://127.0.0.1:${port}/wait-for-auth`
      log(`Querying: ${url}`)
      debugLog(`Poll attempt ${attempts}`)

      try {
        const response = await fetch(url)
        debugLog(`Poll response status: ${response.status}`)
        unreachableSince = null

        if (response.status === 200) {
          // Auth completed, but we don't return the code anymore
          log(`Authentication completed by other instance`)
          return true
        } else if (response.status === 202) {
          // Continue polling
          log(`Authentication still in progress`)
          debugLog(`Will retry in 1s`)
          await new Promise((resolve) => setTimeout(resolve, 1000))
        } else {
          log(`Unexpected response status: ${response.status}`)
          return false
        }
      } catch (fetchError) {
        debugLog(`Fetch error during poll`, fetchError)

        // The instance holding the lock may have been killed mid-flow
        if (lockData && !(await isPidRunning(lockData.pid))) {
          log(`Instance holding the lock (pid ${lockData.pid}) is gone`)
          return false
        }
        if (unreachableSince === null) {
          unreachableSince = Date.now()
        } else if (Date.now() - unreachableSince > UNREACHABLE_SIBLING_TIMEOUT) {
          log(`Authentication server on port ${port} stopped responding`)
          return false
        }

        // If we can't connect, we'll try again after a delay
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }
    }
  } catch (error) {
    log(`Error waiting for authentication: ${(error as Error).message}`)
    debugLog(`Error waiting for authentication`, error)
    return false
  }
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
  let authState: { server: Server; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean; actualPort: number } | null =
    null

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
 * `waitForAuthentication` resolves as soon as the primary's callback server has *received* the
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
export async function coordinateAuth(
  serverUrlHash: string,
  callbackPath: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
  strictPort = false,
): Promise<{ server: Server; actualPort: number; waitForAuthCode: () => Promise<AuthCodeResult>; skipBrowserAuth: boolean }> {
  debugLog('Coordinating authentication', { serverUrlHash, callbackPath, callbackPort })

  // Check for a lockfile (disabled on Windows for the time being)
  const lockData = process.platform === 'win32' ? null : await checkLockfile(serverUrlHash)

  if (process.platform === 'win32') {
    debugLog('Skipping lockfile check on Windows')
  } else {
    debugLog('Lockfile check result', { found: !!lockData, lockData })
  }

  // If there's a valid lockfile, try to use the existing auth process
  if (lockData && (await isLockValid(lockData))) {
    log(`Another instance is handling authentication on port ${lockData.port} (pid: ${lockData.pid})`)

    try {
      // Try to wait for the authentication to complete
      debugLog('Waiting for authentication from other instance')
      const authCompleted = await waitForAuthentication(lockData.port, lockData)

      // `waitForAuthentication` only reports that the primary's callback fired, which is strictly
      // earlier than its token exchange finishing, so wait for the tokens themselves. If they
      // never land, the primary failed somewhere we cannot observe - run the flow ourselves
      // rather than hand back credentials that do not exist.
      if (authCompleted && (await waitForTokensFromPrimary(serverUrlHash))) {
        log('Authentication completed by another instance. Using tokens from disk')

        // Setup a dummy server - the client will use tokens directly from disk
        const dummyServer = express().listen(0) // Listen on any available port
        const dummyPort = (dummyServer.address() as AddressInfo).port
        debugLog('Started dummy server', { port: dummyPort })

        // Never called: callers must branch on `skipBrowserAuth` and reconnect with the tokens
        // from disk instead of awaiting a code this instance will never receive. Kept only so the
        // returned shape matches the primary's, and it rejects rather than hangs so a caller that
        // regresses to awaiting it fails loudly instead of blocking until the host times out.
        const dummyWaitForAuthCode = () => {
          log('WARNING: waitForAuthCode called in secondary instance - this is unexpected')
          return Promise.reject(
            new Error('waitForAuthCode is not available in a secondary instance; reconnect using the tokens on disk instead'),
          )
        }

        return {
          server: dummyServer,
          // Report the caller's original callback port, not the dummy server's OS-assigned one.
          // This instance never serves callbacks, so its port did not "change" - returning
          // dummyPort here makes callers think the port moved and needlessly re-register the
          // OAuth client (deleting client_info.json) on every successful secondary startup.
          actualPort: callbackPort,
          waitForAuthCode: dummyWaitForAuthCode,
          skipBrowserAuth: true,
        }
      }

      log('Taking over authentication process...')
    } catch (error) {
      log(`Error waiting for authentication: ${error}`)
      debugLog('Error waiting for authentication', error)
    }

    // If we get here, the other process didn't complete auth successfully
    debugLog('Other instance did not complete auth successfully, deleting lockfile')
    await deleteLockfile(serverUrlHash)
  } else if (lockData) {
    // Invalid lockfile, delete it
    log('Found invalid lockfile, deleting it')
    await deleteLockfile(serverUrlHash)
  }

  // Create our own lockfile
  debugLog('Setting up OAuth callback server', { port: callbackPort })
  const { server, actualPort, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll({
    port: callbackPort,
    path: callbackPath,
    events,
    authTimeoutMs,
    strictPort,
  })

  debugLog('OAuth callback server running', { port: actualPort })

  log(`Creating lockfile for server ${serverUrlHash} with process ${process.pid} on port ${actualPort}`)
  await createLockfile(serverUrlHash, process.pid, actualPort)

  // Make sure lockfile is deleted on process exit
  const cleanupHandler = async () => {
    try {
      log(`Cleaning up lockfile for server ${serverUrlHash}`)
      await deleteOwnLockfile(serverUrlHash)
    } catch (error) {
      log(`Error cleaning up lockfile: ${error}`)
      debugLog('Error cleaning up lockfile', error)
    }
  }

  process.once('exit', () => {
    try {
      // Synchronous version for 'exit' event since we can't use async here
      deleteOwnLockfileSync(serverUrlHash)
    } catch (error) {
      debugLog(`Error removing lockfile on exit:`, error)
    }
  })

  // Also handle SIGINT separately
  process.once('SIGINT', async () => {
    debugLog('Received SIGINT signal, cleaning up')
    await cleanupHandler()
  })

  debugLog('Auth coordination complete, returning primary instance handlers')
  return {
    server,
    actualPort,
    waitForAuthCode,
    skipBrowserAuth: false,
  }
}
