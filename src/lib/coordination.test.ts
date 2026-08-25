import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { writeJsonFile } from './mcp-auth-config'
import { createLazyAuthCoordinator, hasUsableTokens } from './coordination'
import { EventEmitter } from 'events'
import net from 'net'
import http from 'http'

describe('Feature: Two 401s arriving in the same tick', () => {
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-lazy-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
    vi.restoreAllMocks()
  })

  it('Scenario: They share one flow instead of racing for the callback port', async () => {
    // Concurrent re-entry used to slip past a guard that tested the resolved value, so both calls
    // started a flow and the loser died on an unhandled EADDRINUSE - taking the winner's callback
    // server down with it (#317).
    const coordinator = createLazyAuthCoordinator('lazy-shared', '/oauth/callback', 0, new EventEmitter(), 5000)

    const [first, second] = await Promise.all([coordinator.initializeAuth(), coordinator.initializeAuth()])

    // One flow, so there is no second callback server to collide with the first
    expect(first).toBe(second)
    first.server.close()
  })

  it('Scenario: A failed attempt is not cached, so a retry can still succeed', async () => {
    // Given the port is taken by something that is not us, and pinned, so the attempt must fail
    const blocker = http.createServer((_req, res) => {
      res.writeHead(404).end()
    })
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })
    const coordinator = createLazyAuthCoordinator('lazy-retry', '/oauth/callback', blockedPort, new EventEmitter(), 5000, true)

    await expect(coordinator.initializeAuth()).rejects.toMatchObject({ code: 'EADDRINUSE' })

    // When the port frees up, a retry has to be able to take it - a cached rejection would
    // replay the original failure forever
    blocker.closeAllConnections()
    await new Promise<void>((resolve) => blocker.close(() => resolve()))
    const retried = await coordinator.initializeAuth()

    expect(retried.actualPort).toBe(blockedPort)
    retried.server.close()
  }, 15_000)
})

describe('Feature: Deciding whether a browser sign-in is needed', () => {
  let configDir: string

  beforeEach(async () => {
    configDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mcp-remote-usable-'))
    process.env.MCP_REMOTE_CONFIG_DIR = configDir
  })

  afterEach(async () => {
    delete process.env.MCP_REMOTE_CONFIG_DIR
    await fs.rm(configDir, { recursive: true, force: true })
  })

  const store = (tokens: Record<string, unknown>) => writeJsonFile('usable-test', 'tokens.json', tokens)

  it('Scenario: No tokens at all means a sign-in is needed', async () => {
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })

  it('Scenario: A live token needs nothing', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() + 3_600_000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(true)
  })

  it('Scenario: An expired token that can be refreshed needs no browser', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() - 1000, refresh_token: 'r' })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(true)
  })

  it('Scenario: An expired token with nothing to refresh from needs a sign-in', async () => {
    // Treating this as usable is what let every instance skip coordination on re-authentication
    // and open a tab of its own
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() - 1000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })

  it('Scenario: A token expiring within the refresh margin counts as expired', async () => {
    await store({ access_token: 'a', token_type: 'Bearer', expires_at: Date.now() + 5_000 })
    await expect(hasUsableTokens('usable-test')).resolves.toBe(false)
  })
})
