import { checkLockfile, createLockfile, deleteLockfile, getConfigFilePath, LockfileData } from './mcp-auth-config'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { AddressInfo } from 'net'
import { log, debugLog, DEBUG, setupOAuthCallbackServerWithLongPoll } from './utils'

export type AuthCoordinator = {
  initializeAuth: () => Promise<{ server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean }>
}

/**
 * Checks if a process with the given PID is running
 * @param pid The process ID to check
 * @returns True if the process is running, false otherwise
 */
export async function isPidRunning(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0) // Doesn't kill the process, just checks if it exists
    if (DEBUG) await debugLog(global.currentServerUrlHash!, `Process ${pid} is running`)
    return true
  } catch (err) {
    if (DEBUG) await debugLog(global.currentServerUrlHash!, `Process ${pid} is not running`, err)
    return false
  }
}

/**
 * Checks if a lockfile is valid (process running and endpoint accessible)
 * @param lockData The lockfile data
 * @returns True if the lockfile is valid, false otherwise
 */
export async function isLockValid(lockData: LockfileData): Promise<boolean> {
  if (DEBUG) await debugLog(global.currentServerUrlHash!, 'Checking if lockfile is valid', lockData)
  
  // Check if the lockfile is too old (over 30 minutes)
  const MAX_LOCK_AGE = 30 * 60 * 1000 // 30 minutes
  if (Date.now() - lockData.timestamp > MAX_LOCK_AGE) {
    log('Lockfile is too old')
    if (DEBUG) await debugLog(global.currentServerUrlHash!, 'Lockfile is too old', {
      age: Date.now() - lockData.timestamp,
      maxAge: MAX_LOCK_AGE
    })
    return false
  }

  // Check if the process is still running
  if (!(await isPidRunning(lockData.pid))) {
    log('Process from lockfile is not running')
    if (DEBUG) await debugLog(global.currentServerUrlHash!, 'Process from lockfile is not running', { pid: lockData.pid })
    return false
  }

  // Check if the endpoint is accessible
  try {
    if (DEBUG) await debugLog(global.currentServerUrlHash!, 'Checking if endpoint is accessible', { port: lockData.port })
    
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 1000)

    const response = await fetch(`http://127.0.0.1:${lockData.port}/wait-for-auth?poll=false`, {
      signal: controller.signal,
    })

    clearTimeout(timeout)
    
    const isValid = response.status === 200 || response.status === 202
    if (DEBUG) await debugLog(global.currentServerUrlHash!, `Endpoint check result: ${isValid ? 'valid' : 'invalid'}`, { status: response.status })
    return isValid
  } catch (error) {
    log(`Error connecting to auth server: ${(error as Error).message}`)
    if (DEBUG) await debugLog(global.currentServerUrlHash!, 'Error connecting to auth server', error)
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
  if (DEBUG) await debugLog(global.currentServerUrlHash!, `Waiting for authentication from server on port ${port}`)

  try {
    let attempts = 0;
    while (true) {
      attempts++;
      const url = `http://127.0.0.1:${port}/wait-for-auth`
      log(`Querying: ${url}`)
      if (DEBUG) await debugLog(global.currentServerUrlHash!, `Poll attempt ${attempts}: ${url}`)
      
      try {
        const response = await fetch(url)
        if (DEBUG) await debugLog(global.currentServerUrlHash!, `Poll response status: ${response.status}`)

        if (response.status === 200) {
          // Auth completed, but we don't return the code anymore
          log(`Authentication completed by other instance`)
          if (DEBUG) await debugLog(global.currentServerUrlHash!, `Authentication completed by other instance`)
          return true
        } else if (response.status === 202) {
          // Continue polling
          log(`Authentication still in progress`)
          if (DEBUG) await debugLog(global.currentServerUrlHash!, `Authentication still in progress, will retry in 1s`)
          await new Promise((resolve) => setTimeout(resolve, 1000))
        } else {
          log(`Unexpected response status: ${response.status}`)
          if (DEBUG) await debugLog(global.currentServerUrlHash!, `Unexpected response status`, { status: response.status })
          return false
        }
      } catch (fetchError) {
        if (DEBUG) await debugLog(global.currentServerUrlHash!, `Fetch error during poll`, fetchError)
        // If we can't connect, we'll try again after a delay
        await new Promise((resolve) => setTimeout(resolve, 2000))
      }
    }
  } catch (error) {
    log(`Error waiting for authentication: ${(error as Error).message}`)
    if (DEBUG) await debugLog(global.currentServerUrlHash!, `Error waiting for authentication`, error)
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
export function createLazyAuthCoordinator(
  serverUrlHash: string,
  callbackPort: number,
  events: EventEmitter
): AuthCoordinator {
  let authState: { server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean } | null = null

  return {
    initializeAuth: async () => {
      // If auth has already been initialized, return the existing state
      if (authState) {
        if (DEBUG) await debugLog(serverUrlHash, 'Auth already initialized, reusing existing state')
        return authState
      }

      log('Initializing auth coordination on-demand')
      if (DEBUG) await debugLog(serverUrlHash, 'Initializing auth coordination on-demand', { serverUrlHash, callbackPort })
      
      // Initialize auth using the existing coordinateAuth logic
      authState = await coordinateAuth(serverUrlHash, callbackPort, events)
      if (DEBUG) await debugLog(serverUrlHash, 'Auth coordination completed', { skipBrowserAuth: authState.skipBrowserAuth })
      return authState
    }
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
): Promise<{ server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean }> {
  if (DEBUG) await debugLog(serverUrlHash, 'Coordinating authentication', { serverUrlHash, callbackPort })
  
  // Check for a lockfile (disabled on Windows for the time being)
  const lockData = process.platform === 'win32' ? null : await checkLockfile(serverUrlHash)
  
  if (DEBUG) {
    if (process.platform === 'win32') {
      await debugLog(serverUrlHash, 'Skipping lockfile check on Windows')
    } else {
      await debugLog(serverUrlHash, 'Lockfile check result', { found: !!lockData, lockData })
    }
  }

  // If there's a valid lockfile, try to use the existing auth process
  if (lockData && (await isLockValid(lockData))) {
    log(`Another instance is handling authentication on port ${lockData.port}`)
    if (DEBUG) await debugLog(serverUrlHash, 'Another instance is handling authentication', { port: lockData.port, pid: lockData.pid })

    try {
      // Try to wait for the authentication to complete
      if (DEBUG) await debugLog(serverUrlHash, 'Waiting for authentication from other instance')
      const authCompleted = await waitForAuthentication(lockData.port)
      
      if (authCompleted) {
        log('Authentication completed by another instance')
        if (DEBUG) await debugLog(serverUrlHash, 'Authentication completed by another instance, will use tokens from disk')

        // Setup a dummy server - the client will use tokens directly from disk
        const dummyServer = express().listen(0) // Listen on any available port
        const dummyPort = (dummyServer.address() as AddressInfo).port
        if (DEBUG) await debugLog(serverUrlHash, 'Started dummy server', { port: dummyPort })

        // This shouldn't actually be called in normal operation, but provide it for API compatibility
        const dummyWaitForAuthCode = () => {
          log('WARNING: waitForAuthCode called in secondary instance - this is unexpected')
          if (DEBUG) debugLog(serverUrlHash, 'WARNING: waitForAuthCode called in secondary instance - this is unexpected').catch(() => {})
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
        if (DEBUG) await debugLog(serverUrlHash, 'Taking over authentication process')
      }
    } catch (error) {
      log(`Error waiting for authentication: ${error}`)
      if (DEBUG) await debugLog(serverUrlHash, 'Error waiting for authentication', error)
    }

    // If we get here, the other process didn't complete auth successfully
    if (DEBUG) await debugLog(serverUrlHash, 'Other instance did not complete auth successfully, deleting lockfile')
    await deleteLockfile(serverUrlHash)
  } else if (lockData) {
    // Invalid lockfile, delete it
    log('Found invalid lockfile, deleting it')
    if (DEBUG) await debugLog(serverUrlHash, 'Found invalid lockfile, deleting it')
    await deleteLockfile(serverUrlHash)
  }

  // Create our own lockfile
  if (DEBUG) await debugLog(serverUrlHash, 'Setting up OAuth callback server', { port: callbackPort })
  const { server, waitForAuthCode, authCompletedPromise } = setupOAuthCallbackServerWithLongPoll({
    port: callbackPort,
    path: '/oauth/callback',
    events,
  })

  // Get the actual port the server is running on
  const address = server.address() as AddressInfo
  const actualPort = address.port
  if (DEBUG) await debugLog(serverUrlHash, 'OAuth callback server running', { port: actualPort })

  log(`Creating lockfile for server ${serverUrlHash} with process ${process.pid} on port ${actualPort}`)
  if (DEBUG) await debugLog(serverUrlHash, 'Creating lockfile', { serverUrlHash, pid: process.pid, port: actualPort })
  await createLockfile(serverUrlHash, process.pid, actualPort)

  // Make sure lockfile is deleted on process exit
  const cleanupHandler = async () => {
    try {
      log(`Cleaning up lockfile for server ${serverUrlHash}`)
      if (DEBUG) await debugLog(serverUrlHash, 'Cleaning up lockfile')
      await deleteLockfile(serverUrlHash)
    } catch (error) {
      log(`Error cleaning up lockfile: ${error}`)
      if (DEBUG) await debugLog(serverUrlHash, 'Error cleaning up lockfile', error)
    }
  }

  process.once('exit', () => {
    try {
      // Synchronous version for 'exit' event since we can't use async here
      const configPath = getConfigFilePath(serverUrlHash, 'lock.json')
      require('fs').unlinkSync(configPath)
      if (DEBUG) console.error(`[DEBUG] Removed lockfile on exit: ${configPath}`)
    } catch (error) {
      if (DEBUG) console.error(`[DEBUG] Error removing lockfile on exit:`, error)
    }
  })

  // Also handle SIGINT separately
  process.once('SIGINT', async () => {
    if (DEBUG) await debugLog(serverUrlHash, 'Received SIGINT signal, cleaning up')
    await cleanupHandler()
  })

  if (DEBUG) await debugLog(serverUrlHash, 'Auth coordination complete, returning primary instance handlers')
  return {
    server,
    waitForAuthCode,
    skipBrowserAuth: false,
  }
}
