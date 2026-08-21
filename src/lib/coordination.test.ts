import { afterEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'events'
import { AddressInfo, createConnection, createServer } from 'net'
import * as mcpAuthConfig from './mcp-auth-config'
import { coordinateAuth, createLazyAuthCoordinator, isLockValid, waitForAuthentication } from './coordination'

vi.mock('./mcp-auth-config', () => ({
  checkLockfile: vi.fn(),
  checkAuthorizationCompletion: vi.fn(),
  createLockfile: vi.fn(),
  deleteLockfile: vi.fn(),
  writeAuthorizationCompletion: vi.fn(),
}))

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('waitForAuthentication', () => {
  it('keeps a long-lived lease when its owner and callback endpoint are healthy', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 202 }))

    await expect(
      isLockValid({
        pid: process.pid,
        port: 12345,
        timestamp: Date.now() - 31 * 60 * 1000,
      }),
    ).resolves.toBe(true)
  })

  it('rejects an expired lease whose live owner no longer serves the callback endpoint', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connection refused')))

    await expect(
      isLockValid({
        pid: process.pid,
        port: 12345,
        timestamp: Date.now() - 30_001,
      }),
    ).resolves.toBe(false)
  })

  it('follows the lease endpoint after its owner publishes an assigned callback port', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue({
      pid: process.pid,
      port: 23456,
      timestamp: Date.now(),
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 200 }))

    await expect(waitForAuthentication('server-hash', 20)).resolves.toBe(true)
    expect(fetch).toHaveBeenCalledWith(
      'http://127.0.0.1:23456/wait-for-auth?poll=false',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
  })

  it('accepts a completed matching lease after its owner releases the callback server', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile)
      .mockResolvedValueOnce({
        pid: process.pid,
        port: 23456,
        timestamp: Date.now(),
        leaseId: 'completed-lease',
      })
      .mockResolvedValueOnce(null)
    vi.mocked(mcpAuthConfig.checkAuthorizationCompletion).mockResolvedValue({
      leaseId: 'completed-lease',
      completedAt: Date.now(),
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 202 }))

    await expect(waitForAuthentication('server-hash', 1_100, 'completed-lease')).resolves.toBe(true)
  })

  it('stops polling when the authorization deadline expires', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 202 }))

    await expect(waitForAuthentication(12345, 20)).resolves.toBe(false)
  })

  it('aborts a hung callback status request at the authorization deadline', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_url: string, options: { signal: AbortSignal }) =>
          new Promise((_, reject) => {
            options.signal.addEventListener('abort', () => reject(new Error('aborted')))
          }),
      ),
    )

    await expect(waitForAuthentication(12345, 20)).resolves.toBe(false)
  })

  it('returns a shared-pending coordinator without waiting for the primary authorization', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue({
      pid: process.pid,
      port: 12345,
      timestamp: Date.now(),
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce({ status: 202 }).mockResolvedValueOnce({ status: 200 }))

    const authState = await coordinateAuth('server-hash', 0, new EventEmitter(), 30000)

    expect(authState.skipBrowserAuth).toBe(true)
    expect(fetch).toHaveBeenCalledTimes(1)
    await expect(authState.waitForSharedAuthorization()).resolves.toBe(true)
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('rechecks ownership after a shared authorization wait fails', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile)
      .mockResolvedValueOnce({
        pid: process.pid,
        port: 12345,
        timestamp: Date.now(),
      })
      .mockResolvedValueOnce(null)
    vi.mocked(mcpAuthConfig.createLockfile).mockResolvedValue({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'primary-lease',
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 202 }))

    const coordinator = createLazyAuthCoordinator('server-hash', 0, new EventEmitter(), 30000)
    const sharedAuth = await coordinator.initializeAuth()
    expect(sharedAuth.skipBrowserAuth).toBe(true)

    await coordinator.resetSharedAuthorization()
    const primaryAuth = await coordinator.initializeAuth()

    expect(primaryAuth.skipBrowserAuth).toBe(false)
    expect(mcpAuthConfig.checkLockfile).toHaveBeenCalledTimes(2)
    await new Promise<void>((resolve) => primaryAuth.server.close(() => resolve()))
  })

  it('reclaims a stale lease only with the identity it observed', async () => {
    const staleLease = {
      pid: process.pid,
      port: 12345,
      timestamp: Date.now() - 30_001,
      leaseId: 'stale-lease',
    }
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue(staleLease)
    vi.mocked(mcpAuthConfig.createLockfile).mockResolvedValue({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'newer-lease',
    })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connection refused')))

    const authState = await coordinateAuth('server-hash', 0, new EventEmitter(), 30000)

    expect(mcpAuthConfig.deleteLockfile).toHaveBeenCalledWith('server-hash', 'stale-lease')
    await new Promise<void>((resolve) => authState.server.close(() => resolve()))
  })

  it('serializes concurrent stale-lease reclamation before either process can claim ownership', async () => {
    const staleLease = {
      pid: process.pid,
      port: 12345,
      timestamp: Date.now() - 30_001,
      leaseId: 'stale-lease',
    }
    const replacementLease = {
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'replacement-lease',
    }
    let resolveFirstRead: (lease: typeof staleLease) => void = () => {}
    let firstRead = true
    let replacementClaimed = false
    vi.mocked(mcpAuthConfig.checkLockfile).mockImplementation(async () => {
      if (firstRead) {
        firstRead = false
        return await new Promise<typeof staleLease>((resolve) => {
          resolveFirstRead = resolve
        })
      }
      return replacementClaimed ? replacementLease : staleLease
    })
    vi.mocked(mcpAuthConfig.createLockfile).mockImplementation(async () => {
      replacementClaimed = true
      return replacementLease
    })
    vi.stubGlobal('fetch', vi.fn().mockRejectedValueOnce(new Error('connection refused')).mockResolvedValue({ status: 202 }))

    const first = coordinateAuth('server-hash', 0, new EventEmitter(), 30000)
    await vi.waitFor(() => expect(mcpAuthConfig.checkLockfile).toHaveBeenCalledOnce())
    const second = coordinateAuth('server-hash', 0, new EventEmitter(), 30000)

    await new Promise((resolve) => setTimeout(resolve, 50))
    expect(mcpAuthConfig.checkLockfile).toHaveBeenCalledOnce()
    resolveFirstRead(staleLease)

    const [firstAuth, secondAuth] = await Promise.all([first, second])
    expect(firstAuth.skipBrowserAuth).toBe(false)
    expect(secondAuth.skipBrowserAuth).toBe(true)
    expect(mcpAuthConfig.createLockfile).toHaveBeenCalledOnce()
    await new Promise<void>((resolve) => firstAuth.server.close(() => resolve()))
    await new Promise<void>((resolve) => secondAuth.server.close(() => resolve()))
  })

  it('does not bypass a guard whose reply is fragmented and delayed', async () => {
    const guardPort = await new Promise<number>((resolve, reject) => {
      const probe = createServer()
      probe.once('error', reject)
      probe.listen(0, '127.0.0.1', () => {
        const address = probe.address() as AddressInfo
        probe.close((error) => (error ? reject(error) : resolve(address.port)))
      })
    })
    const serverUrlHash = `${(guardPort - 49_152).toString(16).padStart(8, '0')}-delayed-guard`
    const signature = `mcp-remote-oauth-lease:${serverUrlHash}`
    const guard = createServer((socket) => {
      socket.once('data', () => {
        socket.write(signature.slice(0, 8))
        setTimeout(() => socket.end(signature.slice(8)), 150)
      })
    })
    await new Promise<void>((resolve, reject) => {
      guard.once('error', reject)
      guard.listen(guardPort, '127.0.0.1', () => resolve())
    })
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue(null)
    vi.mocked(mcpAuthConfig.createLockfile).mockResolvedValue({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'primary-lease',
    })

    const auth = coordinateAuth(serverUrlHash, 0, new EventEmitter(), 30_000)
    await new Promise((resolve) => setTimeout(resolve, 125))
    expect(mcpAuthConfig.createLockfile).not.toHaveBeenCalled()

    await new Promise<void>((resolve) => guard.close(() => resolve()))
    const authState = await auth
    await new Promise<void>((resolve) => authState.server.close(() => resolve()))
  })

  it('accepts a fragmented guard probe request before deciding whether to respond', async () => {
    const guardPort = await new Promise<number>((resolve, reject) => {
      const probe = createServer()
      probe.once('error', reject)
      probe.listen(0, '127.0.0.1', () => {
        const address = probe.address() as AddressInfo
        probe.close((error) => (error ? reject(error) : resolve(address.port)))
      })
    })
    const serverUrlHash = `${(guardPort - 49_152).toString(16).padStart(8, '0')}-fragmented-request`
    const signature = `mcp-remote-oauth-lease:${serverUrlHash}`
    let continueOwnershipCheck: (value: null) => void = () => {}
    vi.mocked(mcpAuthConfig.checkLockfile).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          continueOwnershipCheck = resolve
        }),
    )
    vi.mocked(mcpAuthConfig.createLockfile).mockResolvedValue({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'primary-lease',
    })

    const auth = coordinateAuth(serverUrlHash, 0, new EventEmitter(), 30_000)
    const response = new Promise<string>((resolve, reject) => {
      const socket = createConnection({ host: '127.0.0.1', port: guardPort })
      let received = ''
      const timeout = setTimeout(() => {
        socket.destroy()
        resolve(received)
      }, 100)
      socket.once('connect', () => {
        socket.write(signature.slice(0, 8))
        setTimeout(() => socket.write(signature.slice(8)), 10)
      })
      socket.on('data', (chunk) => {
        received += chunk.toString()
        if (received === signature) {
          clearTimeout(timeout)
          socket.destroy()
          resolve(received)
        }
      })
      socket.once('error', reject)
    })

    try {
      await expect(response).resolves.toBe(signature)
    } finally {
      continueOwnershipCheck(null)
      const authState = await auth
      await new Promise<void>((resolve) => authState.server.close(() => resolve()))
    }
  })

  it('releases a failed primary authorization round before a new owner is elected', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue(null)
    vi.mocked(mcpAuthConfig.createLockfile).mockResolvedValue({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: 'primary-lease',
    })

    const coordinator = createLazyAuthCoordinator('server-hash', 0, new EventEmitter(), 30000)
    const failedAuth = await coordinator.initializeAuth()

    await failedAuth.abortAuthorization()

    expect(mcpAuthConfig.deleteLockfile).toHaveBeenCalledWith('server-hash', 'primary-lease')
    expect(failedAuth.server.listening).toBe(false)

    const nextAuth = await coordinator.initializeAuth()
    expect(nextAuth.skipBrowserAuth).toBe(false)
    expect(mcpAuthConfig.createLockfile).toHaveBeenCalledTimes(2)
    await new Promise<void>((resolve) => nextAuth.server.close(() => resolve()))
  })

  it('releases the callback port before another process can claim the next lease', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue(null)
    let leaseNumber = 0
    vi.mocked(mcpAuthConfig.createLockfile).mockImplementation(async () => ({
      pid: process.pid,
      port: 0,
      timestamp: Date.now(),
      leaseId: `lease-${++leaseNumber}`,
    }))

    const coordinator = createLazyAuthCoordinator('server-hash', 0, new EventEmitter(), 30000)
    const primaryAuth = await coordinator.initializeAuth()
    const callbackPort = (primaryAuth.server.address() as AddressInfo).port
    const close = primaryAuth.server.close.bind(primaryAuth.server)
    primaryAuth.server.close = ((callback?: () => void) => {
      setTimeout(() => close(callback), 50)
      return primaryAuth.server
    }) as typeof primaryAuth.server.close

    const releasePrimary = primaryAuth.abortAuthorization()
    const successor = coordinateAuth('server-hash', callbackPort, new EventEmitter(), 30000)

    const [, successorAuth] = await Promise.all([releasePrimary, successor])
    expect(successorAuth.skipBrowserAuth).toBe(false)
    await new Promise<void>((resolve) => successorAuth.server.close(() => resolve()))
  })

  it('coalesces simultaneous local initialization into one lease owner', async () => {
    vi.mocked(mcpAuthConfig.checkLockfile).mockResolvedValue(null)
    let claimLease: (created: boolean) => void = () => {}
    vi.mocked(mcpAuthConfig.createLockfile).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          claimLease = (created) => resolve(created ? { pid: process.pid, port: 0, timestamp: Date.now(), leaseId: 'primary-lease' } : null)
        }),
    )

    const coordinator = createLazyAuthCoordinator('server-hash', 0, new EventEmitter(), 30000)
    const firstInitialization = coordinator.initializeAuth()
    const secondInitialization = coordinator.initializeAuth()

    await vi.waitFor(() => expect(mcpAuthConfig.createLockfile).toHaveBeenCalledOnce())
    claimLease(true)

    const [firstAuth, secondAuth] = await Promise.all([firstInitialization, secondInitialization])
    expect(firstAuth).toBe(secondAuth)
    expect(firstAuth.skipBrowserAuth).toBe(false)
    await firstAuth.abortAuthorization()
  })
})
