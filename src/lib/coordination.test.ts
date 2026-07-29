import { afterEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'events'
import * as mcpAuthConfig from './mcp-auth-config'
import { coordinateAuth, waitForAuthentication } from './coordination'

vi.mock('./mcp-auth-config', () => ({
  checkLockfile: vi.fn(),
  createLockfile: vi.fn(),
  deleteLockfile: vi.fn(),
  getConfigFilePath: vi.fn(),
}))

afterEach(() => {
  vi.unstubAllGlobals()
  vi.clearAllMocks()
})

describe('waitForAuthentication', () => {
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
})
