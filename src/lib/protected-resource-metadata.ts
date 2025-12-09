import { debugLog } from './utils'

/**
 * Generic helper to fetch OAuth metadata from a well-known endpoint
 * @param metadataUrl The well-known metadata URL to fetch from
 * @param debugContext Additional context for debug logging
 * @returns The parsed metadata or undefined if fetch fails
 */
async function fetchOAuthMetadataJson<T>(
  metadataUrl: string,
  debugContext: Record<string, unknown>,
): Promise<T | undefined> {
  debugLog('Fetching OAuth metadata', { metadataUrl, ...debugContext })

  try {
    const response = await fetch(metadataUrl, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      if (response.status === 404) {
        debugLog('OAuth metadata endpoint not found (404)', { metadataUrl })
      } else {
        debugLog('Failed to fetch OAuth metadata', {
          status: response.status,
          statusText: response.statusText,
        })
      }
      return undefined
    }

    return (await response.json()) as T
  } catch (error) {
    debugLog('Error fetching OAuth metadata', {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl,
    })
    return undefined
  }
}

/**
 * OAuth 2.0 Protected Resource Metadata as defined in RFC 9728
 * https://datatracker.ietf.org/doc/html/rfc9728
 */
export interface ProtectedResourceMetadata {
  /** The protected resource's identifier URL (REQUIRED) */
  resource: string
  /** JSON array containing a list of OAuth authorization server issuer identifiers (OPTIONAL) */
  authorization_servers?: string[]
  /** JSON array containing a list of the OAuth 2.0 scope values that this resource supports (RECOMMENDED) */
  scopes_supported?: string[]
  /** JSON array containing methods for presenting bearer tokens (OPTIONAL) */
  bearer_methods_supported?: string[]
  /** URL of the protected resource's JWK Set document (OPTIONAL) */
  jwks_uri?: string
  /** JSON array of JWS signing algorithms supported for signed metadata (OPTIONAL) */
  resource_signing_alg_values_supported?: string[]
  /** Boolean indicating mTLS support for access tokens (OPTIONAL) */
  tls_client_certificate_bound_access_tokens?: boolean
  /** Boolean indicating DPoP requirement for access tokens (OPTIONAL) */
  dpop_bound_access_tokens_required?: boolean
  /** JWT-signed claims about the resource (OPTIONAL) */
  signed_metadata?: string
  /** Additional metadata fields */
  [key: string]: unknown
}

/**
 * Constructs the well-known URL for OAuth protected resource metadata
 * Per RFC 9728, the metadata is at /.well-known/oauth-protected-resource
 * relative to the resource identifier
 *
 * @param resourceUrl The resource server URL
 * @returns The well-known metadata URL
 */
export function getProtectedResourceMetadataUrl(resourceUrl: string): string {
  const url = new URL(resourceUrl)

  // Per RFC 9728, the metadata path is /.well-known/oauth-protected-resource
  // If the resource has a path component, it should be appended
  const resourcePath = url.pathname !== '/' ? url.pathname : ''
  const metadataPath = `/.well-known/oauth-protected-resource${resourcePath}`

  // Construct the full metadata URL
  return `${url.origin}${metadataPath}`
}

/**
 * SSRF Protection: Checks if a URL points to an internal/private IP address
 * Per RFC 9728 Section 7.7: Clients should take appropriate precautions against SSRF attacks
 *
 * @param url The URL to check
 * @returns true if the URL points to an internal IP, false otherwise
 */
function isInternalIP(url: URL): boolean {
  const hostname = url.hostname

  // Block localhost
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    return true
  }

  // Block private IPv4 ranges
  const ipv4Pattern = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/
  const match = hostname.match(ipv4Pattern)
  if (match) {
    const [, a, b] = match.map(Number)
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
      return true
    }
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) {
      return true
    }
  }

  return false
}

/**
 * Validates protected resource metadata response per RFC 9728 Section 3.3
 * The resource field MUST be identical to the protected resource's resource identifier
 *
 * @param metadata The metadata object to validate
 * @param expectedResource The expected resource URL
 * @returns true if validation passes, false otherwise
 */
function validateProtectedResourceMetadata(
  metadata: any,
  expectedResource: string,
): boolean {
  // Check that resource field exists and is a string
  if (!metadata.resource || typeof metadata.resource !== 'string') {
    debugLog('Protected resource metadata validation failed: missing or invalid resource field')
    return false
  }

  // RFC 9728 Section 3.3: Use exact Unicode code-point equality (no normalization)
  // We normalize both URLs to ensure consistent comparison
  try {
    const metadataResourceUrl = new URL(metadata.resource)
    const expectedResourceUrl = new URL(expectedResource)

    // Compare normalized URLs (origin + pathname)
    const metadataResourceNormalized = `${metadataResourceUrl.origin}${metadataResourceUrl.pathname}`
    const expectedResourceNormalized = `${expectedResourceUrl.origin}${expectedResourceUrl.pathname}`

    if (metadataResourceNormalized !== expectedResourceNormalized) {
      debugLog('Protected resource metadata validation failed: resource field mismatch', {
        expected: expectedResourceNormalized,
        actual: metadataResourceNormalized,
      })
      return false
    }
  } catch (error) {
    debugLog('Protected resource metadata validation failed: invalid URL', {
      error: error instanceof Error ? error.message : String(error),
    })
    return false
  }

  return true
}

/**
 * Fetches OAuth 2.0 Protected Resource Metadata from the well-known endpoint
 * Implements RFC 9728 discovery with security considerations
 *
 * @param resourceUrl The resource server URL to fetch metadata for
 * @returns The protected resource metadata, or undefined if fetch fails
 */
export async function fetchProtectedResourceMetadata(
  resourceUrl: string,
): Promise<ProtectedResourceMetadata | undefined> {
  const metadataUrl = getProtectedResourceMetadataUrl(resourceUrl)

  // RFC 9728 Section 7.7: SSRF protection
  const url = new URL(metadataUrl)
  if (isInternalIP(url)) {
    debugLog('Blocked request to internal IP (SSRF protection)', { url: metadataUrl })
    return undefined
  }

  // RFC 9728 Section 7.3: TLS certificate checking MUST be performed (automatic with fetch API)
  const metadata = await fetchOAuthMetadataJson<ProtectedResourceMetadata>(metadataUrl, { resourceUrl })

  // RFC 9728 Section 3.3: Validate metadata
  if (metadata && !validateProtectedResourceMetadata(metadata, resourceUrl)) {
    return undefined
  }

  if (metadata) {
    debugLog('Successfully fetched protected resource metadata', {
      resource: metadata.resource,
      authorization_servers: metadata.authorization_servers,
      scopes_supported: metadata.scopes_supported,
      authServerCount: metadata.authorization_servers?.length || 0,
      scopeCount: metadata.scopes_supported?.length || 0,
    })
  }

  return metadata
}
