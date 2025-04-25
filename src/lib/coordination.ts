import { checkLockfile, createLockfile, deleteLockfile, getConfigFilePath, LockfileData } from './mcp-auth-config'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import { AddressInfo } from 'net'
import { log, setupOAuthCallbackServerWithLongPoll } from './utils'

/**
 * Checks if a process with the given PID is running
 * @param pid The process ID to check
 * @returns True if the process is running, false otherwise
 */
export async function isPidRunning(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0) // Doesn't kill the process, just checks if it exists
    return true
  } catch {
    return false
  }
}

/**
 * Checks if a lockfile is valid (process running and endpoint accessible)
 * @param lockData The lockfile data
 * @returns True if the lockfile is valid, false otherwise
 */
export async function isLockValid(lockData: LockfileData): Promise<boolean> {
  // Check if the process is still running
  if (!(await isPidRunning(lockData.pid))) {
    log('Process from lockfile is not running')
    return false
  }

  // Check if the endpoint is accessible
  try {
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 1000)

    const response = await fetch(`http://127.0.0.1:${lockData.port}/wait-for-auth?poll=false`, {
      signal: controller.signal,
    })

    clearTimeout(timeout)
    return response.status === 200 || response.status === 202
  } catch (error) {
    log(`Error connecting to auth server: ${(error as Error).message}`)
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
    while (true) {
      const url = `http://127.0.0.1:${port}/wait-for-auth`
      log(`Querying: ${url}`)
      const response = await fetch(url)

      if (response.status === 200) {
        // Auth completed, but we don't return the code anymore
        log(`Authentication completed by other instance`)
        return true
      } else if (response.status === 202) {
        // Continue polling
        log(`Authentication still in progress`)
        await new Promise((resolve) => setTimeout(resolve, 1000))
      } else {
        log(`Unexpected response status: ${response.status}`)
        return false
      }
    }
  } catch (error) {
    log(`Error waiting for authentication: ${(error as Error).message}`)
    return false
  }
}

/**
 * Coordinates authentication between multiple instances of the client/proxy
 * @param serverUrlHash The hash of the server URL
 * @param callbackPort The port to use for the callback server
 * @param events The event emitter to use for signaling
 * @param hasSavedTokens Whether the client has saved tokens
 * @returns An object with the server, waitForAuthCode function, and a flag indicating if browser auth can be skipped
 */
export async function coordinateAuth(
  serverUrlHash: string,
  callbackPort: number,
  events: EventEmitter,
  hasSavedTokens: boolean,
): Promise<{ server: Server; waitForAuthCode: () => Promise<string>; skipBrowserAuth: boolean }> {
  // Check for a lockfile (disabled on Windows for the time being)
  const lockData = process.platform === 'win32' ? null : await checkLockfile(serverUrlHash)

  // If there's a valid lockfile, try to use the existing auth process
  if (lockData && (await isLockValid(lockData))) {
    log(`Another instance is handling authentication on port ${lockData.port}`)

    try {
      // Try to wait for the authentication to complete
      const authCompleted = hasSavedTokens || (await waitForAuthentication(lockData.port))
      if (authCompleted) {
        log('Authentication completed by another instance')

        // Setup a dummy server - the client will use tokens directly from disk
        const dummyServer = express().listen(0) // Listen on any available port

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
    }

    // If we get here, the other process didn't complete auth successfully
    await deleteLockfile(serverUrlHash)
  } else if (lockData) {
    // Invalid lockfile, delete its
    log('Found invalid lockfile, deleting it')
    await deleteLockfile(serverUrlHash)
  }

  // Create our own lockfile
  const { server, waitForAuthCode, authCompletedPromise } = setupOAuthCallbackServerWithLongPoll({
    port: callbackPort,
    path: '/oauth/callback',
    events,
  })

  // Get the actual port the server is running on
  const address = server.address() as AddressInfo
  const actualPort = address.port

  log(`Creating lockfile for server ${serverUrlHash} with process ${process.pid} on port ${actualPort}`)
  await createLockfile(serverUrlHash, process.pid, actualPort)

  // Make sure lockfile is deleted on process exit
  const cleanupHandler = async () => {
    try {
      log(`Cleaning up lockfile for server ${serverUrlHash}`)
      await deleteLockfile(serverUrlHash)
    } catch (error) {
      log(`Error cleaning up lockfile: ${error}`)
    }
  }

  process.once('exit', () => {
    try {
      // Synchronous version for 'exit' event since we can't use async here
      const configPath = getConfigFilePath(serverUrlHash, 'lock.json')
      require('fs').unlinkSync(configPath)
    } catch {}
  })

  // Also handle SIGINT separately
  process.once('SIGINT', async () => {
    await cleanupHandler()
  })

  return {
    server,
    waitForAuthCode,
    skipBrowserAuth: false,
  }
}
