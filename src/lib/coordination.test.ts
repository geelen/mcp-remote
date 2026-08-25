import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import { writeJsonFile } from './mcp-auth-config'
import { waitForTokensFromPrimary, createLazyAuthCoordinator } from './coordination'
import { EventEmitter } from 'events'
import net from 'net'
import http from 'http'

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
