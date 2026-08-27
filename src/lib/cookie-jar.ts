import { debugLog } from './utils'

/**
 * A cookie jar just large enough to keep a load balancer routing us back to the same node.
 *
 * `fetch` keeps no cookies, so every request mcp-remote makes arrives at whichever backend the
 * balancer feels like. That is fine until the MCP session lives on one of them: AWS ALB, Azure
 * Load Balancer and friends offer stickiness, but they implement it with a cookie the client is
 * expected to hand back, and nothing here was handing it back (see issue #168).
 *
 * This is not a browser cookie store, and deliberately so:
 *
 * - Cookies are replayed to the exact origin that set them, and `Domain` is ignored. A balancer
 *   sets its cookie on the host we are already talking to, so honouring `Domain` would only widen
 *   where a credential can travel, for no gain here.
 * - `Secure` needs no handling for the same reason: a cookie set over HTTPS is only ever replayed
 *   to that same HTTPS origin.
 * - `HttpOnly` is meaningless outside a browser, where the point is hiding cookies from scripts.
 *
 * `Path` and expiry are honoured, because servers rely on both - re-sending a cookie with an
 * expiry in the past is how one is deleted.
 */

/** Just enough of a response for the jar to read; keeps this decoupled from any fetch flavour. */
type CookieSource = { headers: { getSetCookie?: () => string[] } }

interface StoredCookie {
  value: string
  path: string
  /** Absolute, in ms. Undefined for a session cookie, which lives as long as this process. */
  expiresAt?: number
}

export interface CookieJar {
  /** Records what a response set, so later requests to the same origin carry it. */
  capture(url: string | URL, response: CookieSource): void
  /** The `Cookie` header value for a request, or undefined when there is nothing to send. */
  header(url: string | URL): string | undefined
}

export function createCookieJar(): CookieJar {
  const byOrigin = new Map<string, Map<string, StoredCookie>>()

  return {
    capture(url, response) {
      // Node exposes each Set-Cookie separately here. Reading the joined `Set-Cookie` header
      // instead would be unparseable, since an Expires date contains a comma of its own.
      const setCookies = response.headers.getSetCookie?.() ?? []
      if (setCookies.length === 0) return

      const target = new URL(url)
      let jar = byOrigin.get(target.origin)
      if (!jar) {
        jar = new Map()
        byOrigin.set(target.origin, jar)
      }

      for (const header of setCookies) {
        const cookie = parseSetCookie(header, target)
        if (!cookie) continue

        // An expiry already in the past is a deletion, not a cookie
        if (cookie.expiresAt !== undefined && cookie.expiresAt <= Date.now()) {
          jar.delete(cookie.name)
          continue
        }

        jar.set(cookie.name, { value: cookie.value, path: cookie.path, expiresAt: cookie.expiresAt })
      }

      // Names only. A stickiness cookie is a routing hint, but a session cookie is a credential,
      // and this goes to stderr, which MCP clients capture into their own logs.
      debugLog('Stored cookies set by the remote server', { origin: target.origin, names: [...jar.keys()] })
    },

    header(url) {
      const target = new URL(url)
      const jar = byOrigin.get(target.origin)
      if (!jar) return undefined

      const now = Date.now()
      const pairs: string[] = []

      for (const [name, cookie] of jar) {
        if (cookie.expiresAt !== undefined && cookie.expiresAt <= now) {
          jar.delete(name)
          continue
        }
        if (!pathMatches(target.pathname, cookie.path)) continue
        pairs.push(`${name}=${cookie.value}`)
      }

      return pairs.length > 0 ? pairs.join('; ') : undefined
    },
  }
}

function parseSetCookie(header: string, target: URL) {
  const [pair, ...attributes] = header.split(';')
  const separator = pair.indexOf('=')
  // Position 0 would be an empty name, which RFC 6265 5.2 says to discard
  if (separator < 1) return undefined

  const name = pair.slice(0, separator).trim()
  const value = pair.slice(separator + 1).trim()
  if (!name) return undefined

  let path = defaultPath(target.pathname)
  let expires: number | undefined
  let maxAge: number | undefined

  for (const attribute of attributes) {
    const index = attribute.indexOf('=')
    const key = (index === -1 ? attribute : attribute.slice(0, index)).trim().toLowerCase()
    const attributeValue = index === -1 ? '' : attribute.slice(index + 1).trim()

    if (key === 'path' && attributeValue.startsWith('/')) {
      path = attributeValue
    } else if (key === 'expires') {
      const parsed = Date.parse(attributeValue)
      if (!Number.isNaN(parsed)) expires = parsed
    } else if (key === 'max-age') {
      const seconds = Number(attributeValue)
      if (attributeValue !== '' && Number.isFinite(seconds)) maxAge = seconds
    }
  }

  // RFC 6265 5.3: Max-Age wins over Expires wherever both are given
  return { name, value, path, expiresAt: maxAge !== undefined ? Date.now() + maxAge * 1000 : expires }
}

/** RFC 6265 5.1.4: a cookie with no Path defaults to the directory of the request. */
function defaultPath(pathname: string): string {
  if (!pathname.startsWith('/')) return '/'
  const lastSlash = pathname.lastIndexOf('/')
  return lastSlash === 0 ? '/' : pathname.slice(0, lastSlash)
}

/** RFC 6265 5.1.4: `/mcp` covers `/mcp` and `/mcp/messages`, but not `/mcp-admin`. */
function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true
  if (!requestPath.startsWith(cookiePath)) return false
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/'
}
