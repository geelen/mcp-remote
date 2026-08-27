import { describe, it, expect, vi } from 'vitest'
import { createCookieJar } from './cookie-jar'

vi.mock('./utils', () => ({ debugLog: vi.fn() }))

/** A response carrying the Set-Cookie headers Node hands over separately. */
const setting = (...setCookie: string[]) => ({ headers: { getSetCookie: () => setCookie } })

describe('Feature: Cookie-based session stickiness', () => {
  it('Scenario: A cookie the server set comes back on the next request', () => {
    // Given a balancer pinning this client to one node
    const jar = createCookieJar()
    jar.capture('https://mcp.example.com/mcp', setting('AWSALB=node-1; Path=/'))

    // Then later requests carry it, which is the whole point of stickiness (issue #168)
    expect(jar.header('https://mcp.example.com/mcp')).toBe('AWSALB=node-1')
  })

  it('Scenario: Several cookies are sent together', () => {
    const jar = createCookieJar()
    jar.capture('https://mcp.example.com/mcp', setting('AWSALB=node-1; Path=/', 'AWSALBCORS=node-1; Path=/; SameSite=None'))

    expect(jar.header('https://mcp.example.com/mcp')).toBe('AWSALB=node-1; AWSALBCORS=node-1')
  })

  it('Scenario: A cookie is replaced when the server sets it again', () => {
    // Given a balancer moving this client to another node
    const jar = createCookieJar()
    jar.capture('https://mcp.example.com/mcp', setting('AWSALB=node-1; Path=/'))
    jar.capture('https://mcp.example.com/mcp', setting('AWSALB=node-2; Path=/'))

    expect(jar.header('https://mcp.example.com/mcp')).toBe('AWSALB=node-2')
  })

  it('Scenario: Nothing is sent to a server that set nothing', () => {
    const jar = createCookieJar()

    expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()

    jar.capture('https://mcp.example.com/mcp', setting())
    expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
  })

  it('Scenario: A cookie stays with the origin that set it', () => {
    // Given a cookie from one server
    const jar = createCookieJar()
    jar.capture('https://mcp.example.com/mcp', setting('session=secret; Path=/; Domain=.example.com'))

    // Then it goes nowhere else, however wide a Domain the server asked for. A balancer sets
    // its cookie on the host we are already talking to, so honouring Domain would only widen
    // where a credential can travel.
    expect(jar.header('https://other.example.com/mcp')).toBeUndefined()
    expect(jar.header('http://mcp.example.com/mcp')).toBeUndefined()
    expect(jar.header('https://mcp.example.com:8443/mcp')).toBeUndefined()
    expect(jar.header('https://mcp.example.com/mcp')).toBe('session=secret')
  })

  describe('paths', () => {
    it('Scenario: A cookie scoped to a path is sent below it, but not beside it', () => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/', setting('stick=1; Path=/mcp'))

      expect(jar.header('https://mcp.example.com/mcp')).toBe('stick=1')
      expect(jar.header('https://mcp.example.com/mcp/messages')).toBe('stick=1')
      expect(jar.header('https://mcp.example.com/mcp-admin')).toBeUndefined()
      expect(jar.header('https://mcp.example.com/other')).toBeUndefined()
    })

    it('Scenario: A cookie with no Path defaults to the directory it came from', () => {
      // RFC 6265 5.1.4: the last segment is dropped, so this scopes to /app, not /app/sse
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/app/sse', setting('stick=1'))

      expect(jar.header('https://mcp.example.com/app/messages')).toBe('stick=1')
      expect(jar.header('https://mcp.example.com/elsewhere')).toBeUndefined()
    })

    it('Scenario: A cookie from the root applies everywhere on that origin', () => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/sse', setting('stick=1'))

      expect(jar.header('https://mcp.example.com/messages')).toBe('stick=1')
    })
  })

  describe('expiry', () => {
    it('Scenario: A cookie re-sent already expired is a deletion', () => {
      // Given a server ending the session the way servers do
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/'))
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'))

      expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
    })

    it('Scenario: Max-Age=0 deletes too', () => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/'))
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; Max-Age=0'))

      expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
    })

    it('Scenario: Max-Age is preferred to Expires', () => {
      // RFC 6265 5.3, and worth honouring: a server sends both to cover old clients
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=3600'))

      expect(jar.header('https://mcp.example.com/mcp')).toBe('stick=1')
    })

    it('Scenario: A cookie is dropped once its lifetime runs out', async () => {
      vi.useFakeTimers()
      try {
        const jar = createCookieJar()
        jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; Max-Age=60'))
        expect(jar.header('https://mcp.example.com/mcp')).toBe('stick=1')

        vi.advanceTimersByTime(61_000)
        expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
      } finally {
        vi.useRealTimers()
      }
    })

    it('Scenario: A cookie with no expiry lasts as long as the process', () => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; HttpOnly; Secure; SameSite=Lax'))

      expect(jar.header('https://mcp.example.com/mcp')).toBe('stick=1')
    })
  })

  describe('malformed input', () => {
    it.each([
      ['no separator', 'AWSALB'],
      ['an empty name', '=node-1; Path=/'],
      ['nothing at all', ''],
    ])('Scenario: A Set-Cookie with %s is ignored', (_label, header) => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting(header))

      expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
    })

    it('Scenario: An unreadable expiry leaves the cookie alone rather than dropping it', () => {
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('stick=1; Path=/; Expires=not-a-date; Max-Age=nonsense'))

      expect(jar.header('https://mcp.example.com/mcp')).toBe('stick=1')
    })

    it('Scenario: A value containing an equals sign survives intact', () => {
      // Base64 padding is the common case, and splitting on the wrong = truncates the cookie
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', setting('AWSALB=aGVsbG8=; Path=/'))

      expect(jar.header('https://mcp.example.com/mcp')).toBe('AWSALB=aGVsbG8=')
    })

    it('Scenario: A response with no getSetCookie is not an error', () => {
      // Not every fetch flavour exposes it, and a missing one simply means no cookies
      const jar = createCookieJar()
      jar.capture('https://mcp.example.com/mcp', { headers: {} })

      expect(jar.header('https://mcp.example.com/mcp')).toBeUndefined()
    })
  })
})
