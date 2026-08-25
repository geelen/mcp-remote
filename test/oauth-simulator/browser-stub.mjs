import { appendFileSync } from 'fs'

/**
 * Stands in for the `open` package inside an instance under test.
 *
 * Records the authorization URL - one line per tab a user would have been shown - and then follows
 * it the way a browser would, so the flow completes end to end. The follow is deliberately not
 * awaited: an instance can call this before its own callback server is listening, and a stub that
 * blocked would hide that ordering rather than exercise it.
 */
export default async function open(url) {
  appendFileSync(process.env.MCP_TEST_TAB_LOG, `${Date.now()} ${url}\n`)
  void followLikeABrowser(url)
  // `open` resolves with the helper's ChildProcess; callers may attach listeners or unref it
  return { on() {}, once() {}, unref() {}, stderr: null, kill() {} }
}

async function followLikeABrowser(authorizationUrl) {
  try {
    const response = await fetch(authorizationUrl, { redirect: 'manual' })
    const location = response.headers.get('location')
    if (!location) return
    // The callback server may still be binding; a real user's browser is slower than we are
    for (let attempt = 0; attempt < 40; attempt++) {
      try {
        await fetch(location)
        return
      } catch {
        await new Promise((r) => setTimeout(r, 50))
      }
    }
  } catch {
    // A tab that cannot be completed is itself a result; the counters record what was opened
  }
}
