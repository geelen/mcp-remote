import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { startOAuthSimulator, type OAuthSimulator } from './oauth-simulator/server'
import { runInstances, cleanupRun } from './oauth-simulator/instances'

/**
 * What several instances of mcp-remote do to one server between them.
 *
 * An MCP host starts two to five instances per server and stops them at will, so the behaviour
 * that matters is a property of the group rather than of any one process: how many clients get
 * registered, how many browser tabs the user is shown, how many sign-ins complete. None of that
 * is observable from inside a single process, which is why it is asserted here against a real
 * authorization server instead of in a unit test.
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

  it('completes a sign-in when a single instance runs alone', async () => {
    const run = await runInstances({ count: 1, serverUrl: `${auth.url}/mcp`, settleMs: 12_000 })

    // The baseline the concurrent scenarios are measured against
    expect(run.tabs).toHaveLength(1)
    expect(auth.counters.registrations).toBe(1)
    expect(auth.counters.authorizations).toBe(1)
    expect(auth.counters.tokensIssued).toBeGreaterThanOrEqual(1)
    expect(auth.counters.tokenFailures).toEqual([])

    cleanupRun(run)
  }, 60_000)

  // Currently: 3 tabs, 3 registrations, 0 sign-ins, and two different callback ports among the
  // three instances. `it.fails` keeps CI honest about that - it will start failing, loudly, the
  // moment the behaviour is fixed, which is when this marker should be removed.
  it.fails(
    'shows one tab and signs in when three instances start together',
    async () => {
      const run = await runInstances({ count: 3, serverUrl: `${auth.url}/mcp`, settleMs: 20_000 })

      try {
        // One user-visible tab, whichever instance ends up owning the flow
        expect(run.tabs).toHaveLength(1)
        // One client, so a code is never presented to a registration it was not issued to
        expect(auth.counters.registrations).toBe(1)
        // Every instance ends up authenticated, whether it ran the flow or waited for it
        expect(auth.counters.tokensIssued).toBeGreaterThanOrEqual(1)
        expect(auth.counters.tokenFailures).toEqual([])
      } finally {
        cleanupRun(run)
      }
    },
    90_000,
  )
})
