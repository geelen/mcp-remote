import { debugLog } from './utils'

/**
 * OAuth 2.0 Authorization Server Metadata as defined in RFC 8414
 * https://datatracker.ietf.org/doc/html/rfc8414#section-2
 */
export interface AuthorizationServerMetadata {
  /** The authorization server's issuer identifier */
  issuer: string
  /** URL of the authorization server's authorization endpoint */
  authorization_endpoint?: string
  /** URL of the authorization server's token endpoint */
  token_endpoint?: string
  /** JSON array containing a list of the OAuth 2.0 scope values that this server supports */
  scopes_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 response_type values that this server supports */
  response_types_supported?: string[]
  /** JSON array containing a list of the OAuth 2.0 grant type values that this server supports */
  grant_types_supported?: string[]
  /** JSON array containing a list of client authentication methods supported by this token endpoint */
  token_endpoint_auth_methods_supported?: string[]
  /** Additional metadata fields */
  [key: string]: unknown
}

/**
 * Constructs the well-known URL for OAuth authorization server metadata
 * @param serverUrl The base server URL
 * @returns The well-known metadata URL
 */
export function getMetadataUrl(serverUrl: string): string {
  return getMetadataUrls(serverUrl)[0]
}

/**
 * Builds the discovery URLs to try, most specific first.
 *
 * An issuer with a path has to be probed rather than guessed. RFC 8414 §3.1 inserts
 * the well-known segment *before* the path, OpenID Discovery 1.0 appends it after,
 * and plenty of deployments only answer at the root - so trying one shape and giving
 * up strands whichever servers use the others (see issues #128, #174, #207, #249).
 *
 * @param serverUrl The issuer or server URL
 * @returns Candidate metadata URLs in priority order
 */
export function getMetadataUrls(serverUrl: string): string[] {
  const url = new URL(serverUrl)
  const oauthPath = '/.well-known/oauth-authorization-server'
  const oidcPath = '/.well-known/openid-configuration'

  // A trailing slash would otherwise double up when the path is spliced in
  const pathname = url.pathname.replace(/\/+$/, '')

  if (pathname === '') {
    return [`${url.origin}${oauthPath}`, `${url.origin}${oidcPath}`]
  }

  return [
    // RFC 8414 §3.1: insert the well-known segment between host and path
    `${url.origin}${oauthPath}${pathname}`,
    // Servers that ignore the path and answer only at the root, which is what
    // this function used to assume and what #240 relies on
    `${url.origin}${oauthPath}`,
    // The same two shapes again for OIDC issuers, e.g. Keycloak realms
    `${url.origin}${oidcPath}${pathname}`,
    `${url.origin}${pathname}${oidcPath}`,
  ]
}

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoint
 * @param serverUrl The server URL to fetch metadata for
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadata(serverUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  const candidates = getMetadataUrls(serverUrl)

  debugLog('Fetching authorization server metadata', { serverUrl, candidates })

  for (const metadataUrl of candidates) {
    const metadata = await fetchMetadataFrom(metadataUrl)
    if (metadata) {
      return metadata
    }
  }

  debugLog('No authorization server metadata found at any candidate URL', { serverUrl, candidates })
  return undefined
}

/**
 * Fetches metadata from a single candidate URL
 * @param metadataUrl The candidate URL to try
 * @returns The metadata, or undefined if this candidate did not serve it
 */
async function fetchMetadataFrom(metadataUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: 'application/json',
        'Accept-Encoding': 'identity',
      },
      // Short timeout to avoid blocking
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      if (response.status === 404) {
        debugLog('Authorization server metadata endpoint not found (404)', { metadataUrl })
      } else {
        debugLog('Failed to fetch authorization server metadata', {
          status: response.status,
          statusText: response.statusText,
        })
      }
      return undefined
    }

    const metadata = (await response.json()) as AuthorizationServerMetadata

    debugLog('Successfully fetched authorization server metadata', {
      issuer: metadata.issuer,
      scopes_supported: metadata.scopes_supported,
      scopeCount: metadata.scopes_supported?.length || 0,
    })

    return metadata
  } catch (error) {
    debugLog('Error fetching authorization server metadata', {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl,
    })
    return undefined
  }
}
