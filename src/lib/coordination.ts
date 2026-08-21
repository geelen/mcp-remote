import {
  checkAuthorizationCompletion,
  checkLockfile,
  createLockfile,
  deleteLockfile,
  LockfileData,
  writeAuthorizationCompletion,
} from './mcp-auth-config'
import { EventEmitter } from 'events'
import { Server } from 'http'
import express from 'express'
import net, { AddressInfo } from 'net'
import { log, debugLog, findAvailablePort, setupOAuthCallbackServerWithLongPoll } from './utils'
import type { OAuthCallback } from './types'

export type AuthCoordinator = {
  initializeAuth: () => Promise<{
    server: Server
    waitForAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
    waitForNextAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
    waitForSharedAuthorization: () => Promise<boolean>
    beginAuthorization: () => void
    markAuthCompleted: () => Promise<void>
    abortAuthorization: () => Promise<void>
    authTimeoutMs: number
    skipBrowserAuth: boolean
  }>
  /** Discards only a secondary-process view after the owner disappears. */
  resetSharedAuthorization: () => Promise<void>
  /** Releases the current local authorization round, regardless of ownership. */
  abortAuthorization: () => Promise<void>
}

type LazyAuthState = {
  server: Server
  waitForAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
  waitForNextAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
  waitForSharedAuthorization: () => Promise<boolean>
  beginAuthorization: () => void
  markAuthCompleted: () => Promise<void>
  abortAuthorization: () => Promise<void>
  authTimeoutMs: number
  skipBrowserAuth: boolean
  leaseId?: string
}

type CoordinatedAuth = {
  server: Server
  waitForAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
  waitForNextAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
  waitForSharedAuthorization: () => Promise<boolean>
  beginAuthorization: () => void
  markAuthCompleted: () => void
  authTimeoutMs: number
  skipBrowserAuth: boolean
  leaseId?: string
}

const LEASE_GUARD_PORT_BASE = 49_152
const LEASE_GUARD_PORT_COUNT = 16_384
const LEASE_GUARD_PORT_ATTEMPTS = 32
const LEASE_GUARD_RETRY_MS = 25
const LEASE_GUARD_PROBE_TIMEOUT_MS = 250

type LeaseGuardProbeResult = 'guard' | 'unrelated' | 'ambiguous'

function getLeaseGuardPort(serverUrlHash: string, attempt: number): number {
  const initial = Number.parseInt(serverUrlHash.slice(0, 8), 16)
  const seed = Number.isNaN(initial) ? Array.from(serverUrlHash).reduce((total, character) => total + character.charCodeAt(0), 0) : initial
  return LEASE_GUARD_PORT_BASE + ((seed + attempt * 6_425) % LEASE_GUARD_PORT_COUNT)
}

async function isLeaseGuard(port: number, signature: string): Promise<LeaseGuardProbeResult> {
  return await new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port })
    let response = ''
    let settled = false

    const finish = (result: LeaseGuardProbeResult) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      socket.destroy()
      resolve(result)
    }

    const timeout = setTimeout(() => {
      finish('ambiguous')
    }, LEASE_GUARD_PROBE_TIMEOUT_MS)

    socket.once('connect', () => socket.write(signature))
    socket.on('data', (chunk) => {
      response += chunk.toString()
      if (response === signature) {
        finish('guard')
      } else if (!signature.startsWith(response)) {
        finish('unrelated')
      }
    })
    socket.once('end', () => {
      finish(response === signature ? 'guard' : 'unrelated')
    })
    socket.once('error', () => {
      finish('ambiguous')
    })
  })
}

async function acquireLeaseMutationGuard(serverUrlHash: string, timeoutMs: number): Promise<() => Promise<void>> {
  const signature = `mcp-remote-oauth-lease:${serverUrlHash}`
  const deadline = Date.now() + timeoutMs

  while (Date.now() < deadline) {
    let waitForExistingGuard = false

    for (let attempt = 0; attempt < LEASE_GUARD_PORT_ATTEMPTS; attempt++) {
      const port = getLeaseGuardPort(serverUrlHash, attempt)
      const server = net.createServer((socket) => {
        let request = ''
        let completed = false
        const timeout = setTimeout(() => {
          socket.destroy()
        }, LEASE_GUARD_PROBE_TIMEOUT_MS)

        socket.on('data', (chunk) => {
          if (completed) return
          request += chunk.toString()
          if (request === signature) {
            completed = true
            clearTimeout(timeout)
            socket.end(signature)
            return
          }
          if (!signature.startsWith(request)) {
            completed = true
            clearTimeout(timeout)
            socket.destroy()
          }
        })
        socket.once('end', () => clearTimeout(timeout))
        socket.once('error', () => clearTimeout(timeout))
      })

      try {
        await new Promise<void>((resolve, reject) => {
          server.once('error', reject)
          server.listen(port, '127.0.0.1', () => {
            server.off('error', reject)
            resolve()
          })
        })

        return async () => {
          await new Promise<void>((resolve) => server.close(() => resolve()))
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EADDRINUSE') {
          throw error
        }

        // An occupied port that cannot conclusively prove it is unrelated is
        // treated as an existing guard. Falling back to another candidate on
        // a delayed or fragmented response would let two processes mutate the
        // OAuth lease at once.
        if ((await isLeaseGuard(port, signature)) !== 'unrelated') {
          waitForExistingGuard = true
          break
        }
      }
    }

    if (!waitForExistingGuard) {
      throw new Error('Unable to reserve a local OAuth lease-mutation guard port')
    }

    const remainingMs = deadline - Date.now()
    if (remainingMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(LEASE_GUARD_RETRY_MS, remainingMs)))
    }
  }

  throw new Error(`Timed out waiting for the OAuth lease-mutation guard after ${timeoutMs / 1000} seconds`)
}

async function withLeaseMutationGuard<T>(serverUrlHash: string, timeoutMs: number, action: () => Promise<T>): Promise<T> {
  const release = await acquireLeaseMutationGuard(serverUrlHash, timeoutMs)
  try {
    return await action()
  } finally {
    await release()
  }
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

  // Check if the process is still running
  if (!(await isPidRunning(lockData.pid))) {
    log('Process from lockfile is not running')
    debugLog('Process from lockfile is not running', { pid: lockData.pid })
    return false
  }

  // The owner writes the lease before binding the callback port. Give that
  // short startup window time to complete rather than allowing a second
  // process to delete and replace its lease.
  const LOCK_STARTUP_GRACE_MS = 5_000
  const leaseDeadlineMs = lockData.expiresAt ?? lockData.timestamp + 30_000

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
    if (Date.now() >= leaseDeadlineMs) {
      debugLog('OAuth callback endpoint is unavailable after its authorization deadline', { port: lockData.port, leaseDeadlineMs })
      return false
    }
    if (Date.now() - lockData.timestamp < LOCK_STARTUP_GRACE_MS) {
      debugLog('OAuth callback server is still starting; retaining its lease', { port: lockData.port })
      return true
    }
    debugLog('OAuth callback endpoint is unavailable but owner is still alive; retaining its lease', error)
    return true
  }
}

/**
 * Waits for authentication from another server instance
 * @param portOrServerUrlHash The port to connect to, or the lease key when
 * the callback port can be assigned after ownership is claimed.
 * @returns True if authentication completed successfully, false otherwise
 */
export async function waitForAuthentication(
  portOrServerUrlHash: number | string,
  authTimeoutMs: number = 30000,
  expectedLeaseId?: string,
): Promise<boolean> {
  const serverUrlHash = typeof portOrServerUrlHash === 'string' ? portOrServerUrlHash : undefined
  let port = typeof portOrServerUrlHash === 'number' ? portOrServerUrlHash : undefined
  log(`Waiting for authentication from the server on ${port ? `port ${port}` : 'the shared OAuth lease'}...`)

  try {
    let attempts = 0
    const deadline = Date.now() + authTimeoutMs
    while (Date.now() < deadline) {
      attempts++
      if (serverUrlHash) {
        const lockData = await checkLockfile(serverUrlHash)
        if (!lockData) {
          const completion = expectedLeaseId ? await checkAuthorizationCompletion(serverUrlHash) : null
          return completion?.leaseId === expectedLeaseId
        }
        if (expectedLeaseId && lockData.leaseId !== expectedLeaseId) {
          return false
        }
        if (!(await isPidRunning(lockData.pid))) {
          return false
        }
        port = lockData.port
      }

      if (!port) {
        const remainingAfterLeaseReadMs = deadline - Date.now()
        if (remainingAfterLeaseReadMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(50, remainingAfterLeaseReadMs)))
        }
        continue
      }

      const url = `http://127.0.0.1:${port}/wait-for-auth?poll=false`
      log(`Querying: ${url}`)
      debugLog(`Poll attempt ${attempts}`)

      const remainingMs = deadline - Date.now()
      if (remainingMs <= 0) {
        break
      }

      const controller = new AbortController()
      const timeout = setTimeout(() => controller.abort(), remainingMs)
      try {
        const response = await fetch(url, { signal: controller.signal })
        debugLog(`Poll response status: ${response.status}`)

        if (response.status === 200) {
          // Auth completed, but we don't return the code anymore
          log(`Authentication completed by other instance`)
          return true
        } else if (response.status === 202) {
          // Continue polling
          log(`Authentication still in progress`)
          debugLog(`Will retry in 1s`)
          const remainingAfterPollMs = deadline - Date.now()
          if (remainingAfterPollMs > 0) {
            await new Promise((resolve) => setTimeout(resolve, Math.min(1000, remainingAfterPollMs)))
          }
        } else {
          log(`Unexpected response status: ${response.status}`)
          return false
        }
      } catch (fetchError) {
        debugLog(`Fetch error during poll`, fetchError)
        // If we can't connect, we'll try again after a delay
        const remainingAfterErrorMs = deadline - Date.now()
        if (remainingAfterErrorMs > 0) {
          await new Promise((resolve) => setTimeout(resolve, Math.min(2000, remainingAfterErrorMs)))
        }
      } finally {
        clearTimeout(timeout)
      }
    }
    log('OAuth authorization deadline expired while waiting for another instance')
    return false
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
export function createLazyAuthCoordinator(
  serverUrlHash: string,
  callbackPort: number,
  events: EventEmitter,
  authTimeoutMs: number,
): AuthCoordinator {
  let authState: LazyAuthState | null = null
  let initialization: Promise<LazyAuthState> | null = null
  let cleanup: Promise<void> | null = null

  const closeCallbackServer = async (server: Server): Promise<void> => {
    if (!server.listening) {
      return
    }

    server.closeAllConnections?.()
    await new Promise<void>((resolve) => {
      server.close(() => resolve())
    })
  }

  const releaseAuthorization = async (state: LazyAuthState, completed: boolean): Promise<void> => {
    if (authState !== state) {
      await cleanup
      return
    }

    authState = null
    const currentCleanup = (async () => {
      if (!state.skipBrowserAuth) {
        await withLeaseMutationGuard(serverUrlHash, state.authTimeoutMs, async () => {
          if (completed && state.leaseId) {
            await writeAuthorizationCompletion(serverUrlHash, state.leaseId)
          }
          await deleteLockfile(serverUrlHash, state.leaseId)
          await closeCallbackServer(state.server)
        })
        return
      }
      await closeCallbackServer(state.server)
    })()
    cleanup = currentCleanup
    try {
      await currentCleanup
    } finally {
      if (cleanup === currentCleanup) {
        cleanup = null
      }
    }
  }

  return {
    initializeAuth: async () => {
      // If auth has already been initialized, return the existing state
      if (authState) {
        debugLog('Auth already initialized, reusing existing state')
        return authState
      }

      if (initialization) {
        debugLog('Auth coordination is already initializing, waiting for it')
        return await initialization
      }

      if (cleanup) {
        debugLog('Waiting for the previous OAuth round to release its lease')
        await cleanup
      }

      log('Initializing auth coordination on-demand')
      debugLog('Initializing auth coordination on-demand', { serverUrlHash, callbackPort })

      // Initialize auth using the existing coordinateAuth logic
      initialization = (async () => {
        const coordinated = await coordinateAuth(serverUrlHash, callbackPort, events, authTimeoutMs)
        const state: LazyAuthState = {
          ...coordinated,
          markAuthCompleted: async () => {
            coordinated.markAuthCompleted()
            await releaseAuthorization(state, true)
          },
          abortAuthorization: async () => {
            await releaseAuthorization(state, false)
          },
        }
        authState = state
        debugLog('Auth coordination completed', { skipBrowserAuth: state.skipBrowserAuth })
        return state
      })()

      try {
        return await initialization
      } finally {
        initialization = null
      }
    },
    resetSharedAuthorization: async () => {
      if (!authState?.skipBrowserAuth) {
        return
      }

      await authState.abortAuthorization()
    },
    abortAuthorization: async () => {
      if (authState) {
        await authState.abortAuthorization()
        return
      }

      await cleanup
    },
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
): Promise<CoordinatedAuth> {
  debugLog('Coordinating authentication', { serverUrlHash, callbackPort })

  while (true) {
    const coordinated = await withLeaseMutationGuard(serverUrlHash, authTimeoutMs, async (): Promise<CoordinatedAuth | null> => {
      // Check for a lockfile (disabled on Windows for the time being)
      const lockData = process.platform === 'win32' ? null : await checkLockfile(serverUrlHash)

      if (process.platform === 'win32') {
        debugLog('Skipping lockfile check on Windows')
      } else {
        debugLog('Lockfile check result', { found: !!lockData, lockData })
      }

      // If there's a valid lockfile, try to use the existing auth process.
      if (lockData && (await isLockValid(lockData))) {
        log(`Another instance is handling authentication on port ${lockData.port} (pid: ${lockData.pid})`)
        const dummyServer = express().listen(0)
        const dummyPort = (dummyServer.address() as AddressInfo).port
        debugLog('Started dummy server', { port: dummyPort })

        const dummyWaitForAuthCode = () => {
          log('WARNING: waitForAuthCode called in secondary instance - this is unexpected')
          return new Promise<OAuthCallback>(() => {})
        }

        return {
          server: dummyServer,
          waitForAuthCode: dummyWaitForAuthCode,
          waitForNextAuthCode: dummyWaitForAuthCode,
          waitForSharedAuthorization: () => waitForAuthentication(serverUrlHash, authTimeoutMs, lockData.leaseId),
          beginAuthorization: () => {},
          markAuthCompleted: () => {},
          authTimeoutMs,
          skipBrowserAuth: true,
          leaseId: lockData.leaseId,
        }
      }

      if (lockData) {
        log('Found invalid lockfile, deleting it')
        await deleteLockfile(serverUrlHash, lockData.leaseId)
      }

      // Claim ownership before opening the callback server. Holding the
      // mutation guard through listener startup makes stale reclamation and
      // replacement atomic across processes.
      const claimedCallbackPort = callbackPort || (await findAvailablePort())
      const claimedLease = await createLockfile(serverUrlHash, process.pid, claimedCallbackPort, authTimeoutMs)
      if (!claimedLease) {
        return null
      }

      debugLog('Setting up OAuth callback server', { port: claimedCallbackPort })
      let server: Server
      let waitForAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
      let waitForNextAuthCode: (timeoutMs?: number) => Promise<OAuthCallback>
      let beginAuthorization: () => void
      let markAuthCompleted: () => void
      try {
        ;({ server, waitForAuthCode, waitForNextAuthCode, beginAuthorization, markAuthCompleted } = setupOAuthCallbackServerWithLongPoll({
          port: claimedCallbackPort,
          path: '/oauth/callback',
          events,
          authTimeoutMs,
        }))
        if (!server.listening) {
          await new Promise<void>((resolve, reject) => {
            function onListening() {
              server.off('error', onError)
              resolve()
            }
            function onError(listenError: Error) {
              server.off('listening', onListening)
              reject(listenError)
            }
            server.once('listening', onListening)
            server.once('error', onError)
          })
        }
      } catch (error) {
        await deleteLockfile(serverUrlHash, claimedLease.leaseId)
        throw error
      }

      const address = server.address() as AddressInfo | null
      if (!address) {
        await deleteLockfile(serverUrlHash, claimedLease.leaseId)
        server.close()
        throw new Error('Failed to get server address after listening event')
      }

      const actualPort = address.port
      debugLog('OAuth callback server running', { port: actualPort })

      if (actualPort !== claimedCallbackPort) {
        await deleteLockfile(serverUrlHash, claimedLease.leaseId)
        server.close()
        throw new Error('OAuth callback server bound a port different from its claimed lease')
      }

      debugLog('Auth coordination complete, returning primary instance handlers')
      return {
        server,
        waitForAuthCode,
        waitForNextAuthCode,
        waitForSharedAuthorization: async () => true,
        beginAuthorization,
        markAuthCompleted,
        authTimeoutMs,
        skipBrowserAuth: false,
        leaseId: claimedLease.leaseId,
      }
    })

    if (coordinated) {
      return coordinated
    }
  }
}
