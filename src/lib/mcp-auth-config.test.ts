import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { writeJsonFile, readJsonFile, getConfigFilePath, claimConfigFile, deleteStaleConfigFiles } from './mcp-auth-config'

vi.mock('./utils', () => ({
  log: vi.fn(),
  debugLog: vi.fn(),
  MCP_REMOTE_VERSION: '1.0.0',
  getServerUrlHash: () => 'test-hash',
}))

describe('Feature: Config file writes', () => {
  const hash = 'write-test'
  const filename = 'tokens.json'
  const target = getConfigFilePath(hash, filename)

  afterEach(async () => {
    await fs.unlink(target).catch(() => {})
  })

  it('Scenario: A reader never observes a half-written file', async () => {
    // Given a payload large enough that a plain writeFile spans several syscalls.
    // Measured on this write path: 5 MB tears reliably, 1 MB does not tear at all,
    // so a smaller payload would make this test pass against the bug it guards.
    const big = { access_token: 'a'.repeat(5_000_000), refresh_token: 'r' }

    // When a reader polls the path while the write is in flight
    let torn = false
    const poll = setInterval(() => {
      try {
        JSON.parse(require('fs').readFileSync(target, 'utf-8'))
      } catch (error: any) {
        // ENOENT is fine - the file simply is not there yet. A parse error is not.
        if (error.code !== 'ENOENT') torn = true
      }
    }, 0)

    await writeJsonFile(hash, filename, big)
    clearInterval(poll)

    // Then every observation was either "absent" or "complete"
    expect(torn).toBe(false)
    const written = JSON.parse(await fs.readFile(target, 'utf-8'))
    expect(written.access_token).toHaveLength(5_000_000)
  })

  it('Scenario: No temp files are left behind', async () => {
    await writeJsonFile(hash, filename, { access_token: 'a' })

    const dir = path.dirname(target)
    const leftovers = (await fs.readdir(dir)).filter((f) => f.startsWith(`${filename}`) && f.endsWith('.tmp'))
    expect(leftovers).toEqual([])
  })

  it('Scenario: The file stays owner-only', async () => {
    await writeJsonFile(hash, filename, { access_token: 'a' })

    const stat = await fs.stat(target)
    // The temp file carries mode 0o600 through the rename
    expect(stat.mode & 0o777).toBe(0o600)
  })
})

describe('Feature: Claiming a file exactly once', () => {
  const hash = 'claim-test'
  const filename = 'pending_auth.json'

  afterEach(async () => {
    await fs.unlink(getConfigFilePath(hash, filename)).catch(() => {})
  })

  it('Scenario: Only one of several concurrent instances wins the claim', async () => {
    // Given three instances started together, as an MCP host does
    const claims = await Promise.all([1, 2, 3].map((n) => claimConfigFile(hash, filename, { state: `instance-${n}` })))

    // Then exactly one of them may act on it, and the file records that one
    expect(claims.filter(Boolean)).toHaveLength(1)
    const stored = await readJsonFile<{ state: string }>(hash, filename, { parseAsync: async (d: any) => d })
    expect(stored?.state).toBe(`instance-${claims.indexOf(true) + 1}`)
  })
})

describe('Feature: Sweeping files nothing will name again', () => {
  const hash = 'sweep-test'
  const prefix = 'code_verifier_'

  const write = async (name: string, ageMs: number) => {
    const target = getConfigFilePath(hash, name)
    await writeJsonFile(hash, name, 'verifier')
    const when = new Date(Date.now() - ageMs)
    await fs.utimes(target, when, when)
    return target
  }

  it('Scenario: Abandoned files go, files a live flow may still need stay', async () => {
    // Given one verifier from a flow long abandoned and one from a flow still in progress
    const abandoned = await write(`${prefix}old.txt`, 10 * 60 * 1000)
    const inFlight = await write(`${prefix}fresh.txt`, 0)
    const unrelated = await write('tokens.json', 10 * 60 * 1000)

    await deleteStaleConfigFiles(hash, prefix, 3 * 60 * 1000)

    await expect(fs.access(abandoned)).rejects.toThrow()
    await expect(fs.access(inFlight)).resolves.toBeUndefined()
    // The sweep is scoped to the prefix it was given
    await expect(fs.access(unrelated)).resolves.toBeUndefined()

    await fs.unlink(inFlight).catch(() => {})
    await fs.unlink(unrelated).catch(() => {})
  })
})
