import { beforeEach, describe, expect, it, vi } from 'vitest'
import fs from 'fs/promises'
import { createLockfile, deleteLockfile, getConfigFilePath, writeJsonFile } from './mcp-auth-config'

vi.mock('fs/promises', () => ({
  default: {
    mkdir: vi.fn(),
    readFile: vi.fn(),
    writeFile: vi.fn(),
    rename: vi.fn(),
    link: vi.fn(),
    unlink: vi.fn(),
  },
}))

describe('writeJsonFile', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(fs.mkdir).mockResolvedValue(undefined)
    vi.mocked(fs.readFile).mockResolvedValue('{}')
    vi.mocked(fs.writeFile).mockResolvedValue(undefined)
    vi.mocked(fs.rename).mockResolvedValue(undefined)
    vi.mocked(fs.link).mockResolvedValue(undefined)
    vi.mocked(fs.unlink).mockResolvedValue(undefined)
  })

  it('publishes JSON through a same-directory temporary file', async () => {
    await writeJsonFile('server-hash', 'authorization.json', { state: 'state-one' })

    const [temporaryPath] = vi.mocked(fs.writeFile).mock.calls[0]
    expect(temporaryPath).toMatch(/server-hash_authorization\.json\..+\.tmp$/)
    expect(fs.rename).toHaveBeenCalledWith(temporaryPath, getConfigFilePath('server-hash', 'authorization.json'))
  })

  it('removes a temporary JSON file when publication fails', async () => {
    vi.mocked(fs.rename).mockRejectedValue(new Error('rename failed'))

    await expect(writeJsonFile('server-hash', 'authorization.json', { state: 'state-one' })).rejects.toThrow('rename failed')

    const [temporaryPath] = vi.mocked(fs.writeFile).mock.calls[0]
    expect(fs.unlink).toHaveBeenCalledWith(temporaryPath)
  })

  it('does not replace an existing lock owned by another process', async () => {
    const existsError = Object.assign(new Error('already exists'), { code: 'EEXIST' })
    vi.mocked(fs.link).mockRejectedValue(existsError)

    await expect(createLockfile('server-hash', 12345, 45678)).resolves.toBeNull()
    expect(fs.unlink).toHaveBeenCalledWith(expect.stringMatching(/server-hash_lock\.json\..+\.tmp$/))
  })

  it('stores the authorization deadline with a newly claimed lease', async () => {
    const now = vi.spyOn(Date, 'now').mockReturnValue(1_000)

    try {
      await expect(createLockfile('server-hash', 12345, 45678, 30_000)).resolves.toEqual(
        expect.objectContaining({ leaseId: expect.any(String) }),
      )

      const [, serializedLock] = vi.mocked(fs.writeFile).mock.calls[0]
      expect(JSON.parse(String(serializedLock))).toMatchObject({
        pid: 12345,
        port: 45678,
        timestamp: 1_000,
        expiresAt: 31_000,
      })
    } finally {
      now.mockRestore()
    }
  })

  it('does not remove a replacement lease when a prior owner releases its own lease', async () => {
    vi.mocked(fs.readFile).mockResolvedValue(
      JSON.stringify({
        pid: 54321,
        port: 45679,
        timestamp: 2_000,
        leaseId: 'newer-lease',
      }),
    )

    await expect(deleteLockfile('server-hash', 'older-lease')).resolves.toBe(false)
    expect(fs.unlink).not.toHaveBeenCalledWith(getConfigFilePath('server-hash', 'lock.json'))
  })
})
