import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { writeJsonFile } from './mcp-auth-config'
import { waitForTokensFromPrimary } from './coordination'

describe('Feature: Token handoff between concurrent instances', () => {
  const hash = 'handoff-test'
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-handoff-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
    // coordinateAuth logs to stderr; keep the test output readable
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
  })

  it('Scenario: Resolves once the primary instance persists its tokens', async () => {
    // Given tokens that are not on disk yet - the primary's callback fired, but the code has
    // not been exchanged. This is the window a fixed sleep used to gamble on.
    const waiting = waitForTokensFromPrimary(hash, 5000)

    // When the primary finishes the exchange and writes them
    await new Promise((resolve) => setTimeout(resolve, 300))
    await writeJsonFile(hash, 'tokens.json', { access_token: 'from-primary', token_type: 'Bearer' })

    // Then the secondary stops waiting
    await expect(waiting).resolves.toBe(true)
  })

  it('Scenario: Gives up when the primary never writes them', async () => {
    // Given a primary that signalled completion but never persisted anything
    // Then the secondary reports failure instead of blocking forever
    await expect(waitForTokensFromPrimary(hash, 500)).resolves.toBe(false)
  })
})
