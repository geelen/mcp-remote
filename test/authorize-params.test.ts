import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { startOAuthSimulator, type OAuthSimulator } from './oauth-simulator/server'
import { runInstances, cleanupRun } from './oauth-simulator/instances'

/**
 * What `--authorize-param` actually puts in front of the user.
 *
 * The unit tests cover the parser and the provider separately, but the value has to survive the
 * whole way from argv through `parseCommandLineArgs` and the entry point into the URL a browser is
 * pointed at. That path is only real end to end, which is why it is asserted here against an
 * authorization server that sees the request.
 */
describe('extra authorization parameters', () => {
  let auth: OAuthSimulator

  beforeEach(async () => {
    auth = await startOAuthSimulator()
  })

  afterEach(async () => {
    await auth?.close()
  })

  it('sends them on the authorize request without disturbing the flow', async () => {
    // Given the parameters Google requires before it will issue a refresh token
    const run = await runInstances({
      count: 1,
      serverUrl: `${auth.url}/mcp`,
      args: ['--authorize-param', 'access_type=offline', '--authorize-param', 'prompt=consent'],
      settleMs: 12_000,
    })

    try {
      // Then they are on the URL the user was sent to
      expect(run.tabs).toHaveLength(1)
      const authorizeUrl = new URL(run.tabs[0].url)
      expect(authorizeUrl.searchParams.get('access_type')).toBe('offline')
      expect(authorizeUrl.searchParams.get('prompt')).toBe('consent')

      // And the parameters the flow derives for itself are untouched, so it still completes
      expect(authorizeUrl.searchParams.get('code_challenge')).toBeTruthy()
      expect(authorizeUrl.searchParams.get('state')).toBeTruthy()
      expect(auth.counters.initializations).toBe(1)
      expect(auth.counters.tokenFailures).toEqual([])
    } finally {
      cleanupRun(run)
    }
  }, 60_000)
})
