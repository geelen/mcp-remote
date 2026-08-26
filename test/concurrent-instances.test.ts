import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import net from 'net'
import { startOAuthSimulator, startPublicMcpServer, type OAuthSimulator } from './oauth-simulator/server'
import { runInstances, cleanupRun } from './oauth-simulator/instances'

/**
 * What several instances of mcp-remote do to one server between them.
 *
 * An MCP host starts two to five instances per server and stops them at will, so the behaviour
 * that matters is a property of the group rather than of any one process: how many clients get
 * registered, how many browser tabs the user is shown, how many instances end up working. None of
 * that is observable from inside a single process, which is why it is asserted here against a real
 * authorization server counting what it actually received.
 *
 * Reported in #235, #245, #251, #292, #298, #317, #322 and #323.
 */
describe('concurrent instances against one server', () => {
  let auth: OAuthSimulator

  // A fresh authorization server per scenario, so its counters describe that scenario alone
  beforeEach(async () => {
    auth = await startOAuthSimulator()
  })

  afterEach(async () => {
    await auth?.close()
  })

  it('signs in once and connects when a single instance runs alone', async () => {
    const run = await runInstances({ count: 1, serverUrl: `${auth.url}/mcp`, settleMs: 12_000 })

    expect(run.tabs).toHaveLength(1)
    expect(auth.counters.registrations).toBe(1)
    expect(auth.counters.initializations).toBe(1)
    expect(auth.counters.tokenFailures).toEqual([])

    cleanupRun(run)
  }, 60_000)

  for (const count of [3, 5]) {
    it(`shows one tab and connects every instance when ${count} start together`, async () => {
      const run = await runInstances({ count, serverUrl: `${auth.url}/mcp`, settleMs: 20_000 })

      try {
        // One tab, whichever instance won the callback port
        expect(run.tabs).toHaveLength(1)
        // One client, so a code is never presented to a registration it was not issued to
        expect(auth.counters.registrations).toBe(1)
        // One redirect_uri, because every instance derives the same callback port
        expect(auth.counters.redirectUris).toHaveLength(1)
        // The code is exchanged once; the rest read the tokens from disk
        expect(auth.counters.tokensIssued).toBe(1)
        expect(auth.counters.tokenFailures).toEqual([])
        // And every instance ends up actually working, not just the one that ran the flow
        expect(auth.counters.initializations).toBe(count)
      } finally {
        cleanupRun(run)
      }
    }, 90_000)
  }

  it('opens no tab at all when tokens are already on disk', async () => {
    const first = await runInstances({ count: 1, serverUrl: `${auth.url}/mcp`, settleMs: 12_000 })
    expect(first.tabs).toHaveLength(1)
    const tabsAfterSignIn = auth.tabs.length

    // Reusing the same config dir stands in for a restart after a successful sign-in
    const restarted = await runInstances({ count: 3, serverUrl: `${auth.url}/mcp`, settleMs: 12_000, configDir: first.configDir })

    try {
      // A warm start binds nothing and asks the user for nothing
      expect(auth.tabs.length).toBe(tabsAfterSignIn)
      expect(restarted.tabs).toHaveLength(0)
      expect(auth.counters.registrations).toBe(1)
      expect(auth.counters.initializations).toBeGreaterThanOrEqual(4)
    } finally {
      cleanupRun(first)
    }
  }, 90_000)

  it('takes the flow over when the instance running it is killed mid-sign-in', async () => {
    // The reported failure: the host stops the instance that opened the tab, seconds in. The tab
    // is still open and still points at the callback port, so somebody has to be listening there.
    const run = await runInstances({
      count: 3,
      serverUrl: `${auth.url}/mcp`,
      settleMs: 25_000,
      killTabOwnerAfterMs: 1500,
    })

    try {
      expect(run.killedPid).toBeDefined()
      // The survivors take over the port rather than each opening a tab of their own
      expect(run.tabs.length).toBeLessThanOrEqual(2)
      expect(auth.counters.initializations).toBeGreaterThanOrEqual(1)
    } finally {
      cleanupRun(run)
    }
  }, 120_000)

  it('completes the sign-in from the tab the killed instance opened', async () => {
    // The tab is followed only after the instance that opened it is gone, which is the ordering a
    // user produces: the host stops the instance seconds in, they approve a moment later.
    const run = await runInstances({
      count: 3,
      serverUrl: `${auth.url}/mcp`,
      settleMs: 25_000,
      killTabOwnerAfterMs: 1500,
      approveFirstTabAfterKillMs: 2000,
    })

    try {
      expect(run.killedPid).toBeDefined()
      expect(auth.counters.tokenFailures).toEqual([])
      expect(auth.counters.tokensIssued).toBe(1)
      expect(auth.counters.initializations).toBeGreaterThanOrEqual(1)
    } finally {
      cleanupRun(run)
    }
  }, 120_000)

  it('steps past a port held by an unrelated process', async () => {
    // The derived port is not reserved for us. Something else holding it must not make every
    // instance wait for a sign-in that is never coming.
    const run = await runInstances({ count: 2, serverUrl: `${auth.url}/mcp`, settleMs: 20_000, squatDerivedPort: true })

    try {
      expect(run.tabs).toHaveLength(1)
      expect(auth.counters.registrations).toBe(1)
      expect(auth.counters.initializations).toBe(2)
    } finally {
      cleanupRun(run)
    }
  }, 90_000)

  it('does not make instances wait for a sign-in a public server will never do', async () => {
    // Coordinating up front only makes sense for a server that wants OAuth. A public server, or
    // one authenticated by --header, never writes tokens - so anything waiting on them waits
    // forever, and every instance after the first used to exit non-zero.
    const publicServer = await startPublicMcpServer()

    try {
      const run = await runInstances({ count: 3, serverUrl: `${publicServer.url}/mcp`, settleMs: 15_000 })

      try {
        expect(run.tabs).toHaveLength(0)
        expect(publicServer.initializations).toBe(3)
      } finally {
        cleanupRun(run)
      }
    } finally {
      await publicServer.close()
    }
  }, 90_000)
})
