import { checkLockfile, createLockfile, deleteLockfile, getConfigFilePath, LockfileData } from './mcp-auth-config'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { AddressInfo } from 'net'
import { unlinkSync } from 'fs'
import { log, debugLog, setupOAuthCallbackServerWithLongPoll } from './utils'
import type { AuthMode } from './types'

export interface AuthCoordinatorOptions {
  callbackPort: number
  authTimeoutMs: number
  authMode: AuthMode
  authBridgePollUrl?: string
  authBridgePollIntervalMs?: number
  authSessionId?: string
}

export type AuthCoordinatorState = {
  server?: Server
  waitForAuthCode: () => Promise<string>
  skipBrowserAuth: boolean
}

export type AuthCoordinator = {
  initializeAuth: () => Promise<AuthCoordinatorState>
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

/**
 * Waits for authentication from another server instance
 * @param port The port to connect to
 * @returns True if authentication completed successfully, false otherwise
 */
export async function waitForAuthentication(port: number): Promise<boolean> {
  log(`Waiting for authentication from the server on port ${port}...`)

  try {
    let attempts = 0
    while (true) {
      attempts++
      const url = `http://127.0.0.1:${port}/wait-for-auth`
      log(`Querying: ${url}`)
      debugLog(`Poll attempt ${attempts}`)

      try {
        const response = await fetch(url)
        debugLog(`Poll response status: ${response.status}`)

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
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @returns An AuthCoordinator object with an initializeAuth method
 */
export function createLazyAuthCoordinator(serverUrlHash: string, events: EventEmitter, options: AuthCoordinatorOptions): AuthCoordinator {
  let authState: AuthCoordinatorState | null = null

  return {
    initializeAuth: async () => {
      // If auth has already been initialized, return the existing state
      if (authState) {
        debugLog('Auth already initialized, reusing existing state')
        return authState
      }

      log('Initializing auth coordination on-demand')
      debugLog('Initializing auth coordination on-demand', { serverUrlHash, authMode: options.authMode })

      // Initialize auth using the existing coordinateAuth logic
      if (options.authMode === 'bridge') {
        authState = coordinateBridgeAuth(serverUrlHash, options)
      } else {
        authState = await coordinateAuth(serverUrlHash, options.callbackPort, events, options.authTimeoutMs)
      }

      debugLog('Auth coordination completed', { skipBrowserAuth: authState.skipBrowserAuth })
      return authState
    },
  }
}

function resolveBridgePollUrl(template: string, authSessionId: string, serverUrlHash: string): string {
  const withPlaceholders = template
    .replaceAll('{session_id}', encodeURIComponent(authSessionId))
    .replaceAll('{server_url_hash}', encodeURIComponent(serverUrlHash))

  const hasPlaceholder = withPlaceholders !== template
  if (hasPlaceholder) {
    return withPlaceholders
  }

  const url = new URL(withPlaceholders)
  url.searchParams.set('session_id', authSessionId)
  url.searchParams.set('server_url_hash', serverUrlHash)
  return url.toString()
}

function extractAuthCode(responseBody: string): string | undefined {
  const trimmed = responseBody.trim()
  if (!trimmed) {
    return undefined
  }

  try {
    const parsed = JSON.parse(trimmed) as { code?: string; authorization_code?: string }
    return parsed.code || parsed.authorization_code
  } catch {
    return trimmed
  }
}

async function waitForBridgeAuthCode(pollUrl: string, pollIntervalMs: number): Promise<string> {
  log(`Waiting for bridge auth code from: ${pollUrl}`)

  let attempts = 0
  while (true) {
    attempts++
    try {
      const response = await fetch(pollUrl, {
        headers: {
          Accept: 'application/json, text/plain',
        },
        signal: AbortSignal.timeout(10000),
      })

      if (response.status === 200) {
        const body = await response.text()
        const code = extractAuthCode(body)
        if (code) {
          debugLog('Received auth code from auth bridge', { attempts })
          return code
        }

        debugLog('Auth bridge returned 200 but no code yet', { attempts })
      } else if (response.status === 202 || response.status === 204 || response.status === 404) {
        debugLog('Auth bridge indicates auth is still pending', { attempts, status: response.status })
      } else if (response.status === 410) {
        throw new Error('Auth bridge session expired')
      } else {
        debugLog('Unexpected auth bridge response status', { attempts, status: response.status })
      }
    } catch (error) {
      debugLog('Error polling auth bridge for auth code', {
        attempts,
        error: error instanceof Error ? error.message : String(error),
      })
    }

    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs))
  }
}

function coordinateBridgeAuth(serverUrlHash: string, options: AuthCoordinatorOptions): AuthCoordinatorState {
  if (!options.authBridgePollUrl) {
    throw new Error('authBridgePollUrl is required for bridge auth mode')
  }

  const authSessionId = options.authSessionId || `${serverUrlHash}-${process.pid}`
  const pollUrl = resolveBridgePollUrl(options.authBridgePollUrl, authSessionId, serverUrlHash)
  const pollIntervalMs = options.authBridgePollIntervalMs || 2000

  debugLog('Using bridge auth coordinator', {
    authSessionId,
    pollUrl,
    pollIntervalMs,
  })

  return {
    waitForAuthCode: () => waitForBridgeAuthCode(pollUrl, pollIntervalMs),
    skipBrowserAuth: false,
  }
}

/**
 * Coordinates authentication between multiple instances of the client/proxy
 * @param serverUrlHash The hash of the server URL
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @returns An object with the server, waitForAuthCode function, and a flag indicating if browser auth can be skipped
 */
export async function coordinateAuth(
  serverUrlHash: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
): Promise<AuthCoordinatorState> {
  debugLog('Coordinating authentication', { serverUrlHash, callbackPort })

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
      const authCompleted = await waitForAuthentication(lockData.port)

      if (authCompleted) {
        log('Authentication completed by another instance. Using tokens from disk')

        // Setup a dummy server - the client will use tokens directly from disk
        const dummyServer = express().listen(0) // Listen on any available port
        const dummyPort = (dummyServer.address() as AddressInfo).port
        debugLog('Started dummy server', { port: dummyPort })

        // This shouldn't actually be called in normal operation, but provide it for API compatibility
        const dummyWaitForAuthCode = () => {
          log('WARNING: waitForAuthCode called in secondary instance - this is unexpected')
          // Return a promise that never resolves - the client should use the tokens from disk instead
          return new Promise<string>(() => {})
        }

        return {
          server: dummyServer,
          waitForAuthCode: dummyWaitForAuthCode,
          skipBrowserAuth: true,
        }
      } else {
        log('Taking over authentication process...')
      }
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
  const { server, waitForAuthCode, authCompletedPromise } = setupOAuthCallbackServerWithLongPoll({
    port: callbackPort,
    path: '/oauth/callback',
    events,
    authTimeoutMs,
  })

  // Get the actual port the server is running on
  let address = server.address() as AddressInfo | null
  if (!address) {
    await new Promise<void>((resolve) => server.once('listening', resolve))
    address = server.address() as AddressInfo | null
  }

  if (!address) {
    throw new Error('Failed to get server address after listening event')
  }

  const actualPort = address.port
  debugLog('OAuth callback server running', { port: actualPort })

  log(`Creating lockfile for server ${serverUrlHash} with process ${process.pid} on port ${actualPort}`)
  await createLockfile(serverUrlHash, process.pid, actualPort)

  // Make sure lockfile is deleted on process exit
  const cleanupHandler = async () => {
    try {
      log(`Cleaning up lockfile for server ${serverUrlHash}`)
      await deleteLockfile(serverUrlHash)
    } catch (error) {
      log(`Error cleaning up lockfile: ${error}`)
      debugLog('Error cleaning up lockfile', error)
    }
  }

  process.once('exit', () => {
    try {
      // Synchronous version for 'exit' event since we can't use async here
      const configPath = getConfigFilePath(serverUrlHash, 'lock.json')
      unlinkSync(configPath)
      debugLog(`Removed lockfile on exit: ${configPath}`)
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
    waitForAuthCode,
    skipBrowserAuth: false,
  }
}
