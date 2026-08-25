import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, existsSync, writeFileSync } from 'fs'
import { spawn } from 'child_process'
import { tmpdir } from 'os'
import path from 'path'
import { writeJsonFile } from './mcp-auth-config'
import { MCP_REMOTE_VERSION } from './utils'

const SERVER_HASH = 'testserverhash'

let configDir: string

/** Returns the pid of a process that has already exited, so liveness checks fail for it. */
async function deadPid(): Promise<number> {
  const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' })
  const pid = child.pid!
  await new Promise((resolve) => child.once('exit', resolve))
  return pid
}

/** Files live in the version subdirectory the config helpers append to the base dir. */
function configFile(filename: string): string {
  return path.join(configDir, `mcp-remote-${MCP_REMOTE_VERSION}`, `${SERVER_HASH}_${filename}`)
}

function lockPath(): string {
  return configFile('lock.json')
}

beforeEach(() => {
  configDir = mkdtempSync(path.join(tmpdir(), 'mcp-remote-coordination-'))
  process.env.MCP_REMOTE_CONFIG_DIR = configDir
  mkdirSync(path.join(configDir, `mcp-remote-${MCP_REMOTE_VERSION}`), { recursive: true })
  // coordinateAuth logs to stderr; keep the test output readable
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.resetModules()
})

afterEach(() => {
  delete process.env.MCP_REMOTE_CONFIG_DIR
  rmSync(configDir, { recursive: true, force: true })
  vi.restoreAllMocks()
})

describe('Feature: Token handoff between concurrent instances', () => {
  it('Scenario: Resolves once the primary instance persists its tokens', async () => {
    const { waitForTokensFromPrimary } = await import('./coordination')
    // Given tokens that are not on disk yet - the primary's callback fired, but the code has
    // not been exchanged. This is the window a fixed sleep used to gamble on.
    const waiting = waitForTokensFromPrimary(SERVER_HASH, 5000)

    // When the primary finishes the exchange and writes them
    await new Promise((resolve) => setTimeout(resolve, 300))
    await writeJsonFile(SERVER_HASH, 'tokens.json', { access_token: 'from-primary', token_type: 'Bearer' })

    // Then the secondary stops waiting
    await expect(waiting).resolves.toBe(true)
  })

  it('Scenario: Gives up when the primary never writes them', async () => {
    const { waitForTokensFromPrimary } = await import('./coordination')
    // Given a primary that signalled completion but never persisted anything
    // Then the secondary reports failure instead of blocking forever
    await expect(waitForTokensFromPrimary(SERVER_HASH, 500)).resolves.toBe(false)
  })
})

describe('Feature: Lockfile ownership', () => {
  it('Scenario: an exiting instance keeps a lockfile another instance owns', async () => {
    const { deleteOwnLockfileSync } = await import('./coordination')
    // process.ppid is alive and is not us, standing in for a concurrent instance
    writeFileSync(lockPath(), JSON.stringify({ pid: process.ppid, port: 1234, timestamp: Date.now() }))

    deleteOwnLockfileSync(SERVER_HASH)

    expect(existsSync(lockPath())).toBe(true)
  })

  it('Scenario: an exiting instance removes its own lockfile', async () => {
    const { deleteOwnLockfileSync } = await import('./coordination')
    writeFileSync(lockPath(), JSON.stringify({ pid: process.pid, port: 1234, timestamp: Date.now() }))

    deleteOwnLockfileSync(SERVER_HASH)

    expect(existsSync(lockPath())).toBe(false)
  })

  it('Scenario: async cleanup keeps a lockfile another instance owns', async () => {
    const { deleteOwnLockfile } = await import('./coordination')
    writeFileSync(lockPath(), JSON.stringify({ pid: process.ppid, port: 1234, timestamp: Date.now() }))

    await deleteOwnLockfile(SERVER_HASH)

    expect(existsSync(lockPath())).toBe(true)
  })
})

describe('Feature: Waiting on another instance', () => {
  it('Scenario: waiting stops once the instance holding the lock is gone', async () => {
    const { waitForAuthentication } = await import('./coordination')
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'))

    const result = await waitForAuthentication(1234, { pid: await deadPid(), port: 1234, timestamp: Date.now() })

    expect(result).toBe(false)
  })

  it('Scenario: waiting stops after an unreachable instance stays silent', async () => {
    const { waitForAuthentication } = await import('./coordination')
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('ECONNREFUSED'))

    // Owner is alive, so only the silence timeout can end the wait
    const result = await waitForAuthentication(1234, { pid: process.ppid, port: 1234, timestamp: Date.now() })

    expect(result).toBe(false)
  }, 20000)

  it('Scenario: waiting succeeds when the other instance completes authentication', async () => {
    const { waitForAuthentication } = await import('./coordination')
    vi.spyOn(globalThis, 'fetch').mockResolvedValue({ status: 200 } as Response)

    const result = await waitForAuthentication(1234, { pid: process.ppid, port: 1234, timestamp: Date.now() })

    expect(result).toBe(true)
  })
})
