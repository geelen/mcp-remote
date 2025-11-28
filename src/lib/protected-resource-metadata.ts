import { debugLog } from './utils'

/**
 * OAuth 2.0 Protected Resource Metadata as defined in RFC 9728
 * https://datatracker.ietf.org/doc/html/rfc9728
 */
export interface ProtectedResourceMetadata {
  /** The protected resource's resource identifier */
  resource: string
  /** JSON array containing a list of OAuth authorization server issuer identifiers */
  authorization_servers?: string[]
  /** JSON array containing a list of OAuth 2.0 scope values that are used in authorization requests */
  scopes_supported?: string[]
  /** JSON array containing a list of methods supported to present bearer tokens */
  bearer_methods_supported?: string[]
  /** JSON array containing JWS signing algorithms supported for resource request signing */
  resource_signing_alg_values_supported?: string[]
  /** URL of a page containing human-readable information about the protected resource */
  resource_documentation?: string
  /** Human-readable name of the protected resource */
  resource_name?: string
  /** Additional metadata fields */
  [key: string]: unknown
}

/**
 * Result of parsing a WWW-Authenticate header
 */
export interface WWWAuthenticateParams {
  /** The resource_metadata URL if present */
  resourceMetadataUrl?: string
  /** The scope parameter if present */
  scope?: string
  /** The error parameter if present */
  error?: string
  /** The error_description parameter if present */
  errorDescription?: string
}

/**
 * Parses a WWW-Authenticate header to extract resource_metadata URL and other parameters
 *
 * Example header:
 * Bearer error="invalid_request", error_description="No access token", resource_metadata="https://example.com/.well-known/oauth-protected-resource"
 *
 * @param header The WWW-Authenticate header value
 * @returns Parsed parameters including resource_metadata URL and scope
 */
export function parseWWWAuthenticateHeader(header: string): WWWAuthenticateParams {
  const result: WWWAuthenticateParams = {}

  if (!header) {
    return result
  }

  // Remove "Bearer " prefix if present (case-insensitive)
  const paramString = header.replace(/^Bearer\s+/i, '')

  // Parse key="value" pairs, handling quoted strings properly
  // This regex matches: key="value" or key=value
  const paramRegex = /(\w+)=(?:"([^"]*)"|([\w-]+))/g
  let match

  while ((match = paramRegex.exec(paramString)) !== null) {
    const key = match[1]
    const value = match[2] ?? match[3] // Use quoted value if present, otherwise unquoted

    switch (key) {
      case 'resource_metadata':
        result.resourceMetadataUrl = value
        break
      case 'scope':
        result.scope = value
        break
      case 'error':
        result.error = value
        break
      case 'error_description':
        result.errorDescription = value
        break
    }
  }

  debugLog('Parsed WWW-Authenticate header', {
    hasResourceMetadata: !!result.resourceMetadataUrl,
    hasScope: !!result.scope,
    error: result.error,
  })

  return result
}

/**
 * Builds the well-known URLs for Protected Resource Metadata discovery
 *
 * Per RFC 9728, clients should try:
 * 1. Path-specific: /.well-known/oauth-protected-resource/[path]
 * 2. Root-level: /.well-known/oauth-protected-resource
 *
 * @param resourceUrl The URL of the protected resource (MCP server)
 * @returns Array of URLs to try in order
 */
export function buildProtectedResourceMetadataUrls(resourceUrl: string): string[] {
  const url = new URL(resourceUrl)
  const urls: string[] = []

  // Get the path without trailing slash
  const path = url.pathname.replace(/\/$/, '')

  // 1. Path-specific well-known URL (if there's a path)
  if (path && path !== '/') {
    urls.push(`${url.origin}/.well-known/oauth-protected-resource${path}`)
  }

  // 2. Root-level well-known URL
  urls.push(`${url.origin}/.well-known/oauth-protected-resource`)

  debugLog('Built Protected Resource Metadata URLs', { resourceUrl, urls })

  return urls
}

/**
 * Fetches Protected Resource Metadata from a specific URL
 *
 * @param metadataUrl The URL to fetch metadata from
 * @returns The metadata if successful, undefined otherwise
 */
async function fetchProtectedResourceMetadataFromUrl(metadataUrl: string): Promise<ProtectedResourceMetadata | undefined> {
  debugLog('Fetching Protected Resource Metadata', { metadataUrl })

  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: 'application/json',
      },
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      if (response.status === 404) {
        debugLog('Protected Resource Metadata not found (404)', { metadataUrl })
      } else {
        debugLog('Failed to fetch Protected Resource Metadata', {
          status: response.status,
          statusText: response.statusText,
        })
      }
      return undefined
    }

    const metadata = (await response.json()) as ProtectedResourceMetadata

    debugLog('Successfully fetched Protected Resource Metadata', {
      resource: metadata.resource,
      authorizationServers: metadata.authorization_servers,
      scopesSupported: metadata.scopes_supported,
    })

    return metadata
  } catch (error) {
    debugLog('Error fetching Protected Resource Metadata', {
      error: error instanceof Error ? error.message : String(error),
      metadataUrl,
    })
    return undefined
  }
}

/**
 * Discovers Protected Resource Metadata for a given resource URL
 *
 * This implements the full discovery flow per RFC 9728 and MCP spec:
 * 1. If WWW-Authenticate header is provided with resource_metadata, use that URL directly
 * 2. Otherwise, try the path-specific well-known URL
 * 3. If that fails, try the root well-known URL
 *
 * @param resourceUrl The URL of the protected resource (MCP server)
 * @param wwwAuthenticateHeader Optional WWW-Authenticate header from a 401 response
 * @returns The metadata if found, undefined otherwise
 */
export async function discoverProtectedResourceMetadata(
  resourceUrl: string,
  wwwAuthenticateHeader?: string,
): Promise<ProtectedResourceMetadata | undefined> {
  debugLog('Starting Protected Resource Metadata discovery', {
    resourceUrl,
    hasWWWAuthenticateHeader: !!wwwAuthenticateHeader,
  })

  // Priority 1: Check WWW-Authenticate header for resource_metadata URL
  if (wwwAuthenticateHeader) {
    const params = parseWWWAuthenticateHeader(wwwAuthenticateHeader)
    if (params.resourceMetadataUrl) {
      debugLog('Using resource_metadata URL from WWW-Authenticate header', {
        url: params.resourceMetadataUrl,
      })
      const metadata = await fetchProtectedResourceMetadataFromUrl(params.resourceMetadataUrl)
      if (metadata) {
        return metadata
      }
      // If the URL from the header fails, fall through to well-known discovery
      debugLog('Failed to fetch from WWW-Authenticate URL, falling back to well-known discovery')
    }
  }

  // Priority 2 & 3: Try well-known URLs in order
  const wellKnownUrls = buildProtectedResourceMetadataUrls(resourceUrl)
  for (const url of wellKnownUrls) {
    const metadata = await fetchProtectedResourceMetadataFromUrl(url)
    if (metadata) {
      return metadata
    }
  }

  debugLog('Protected Resource Metadata discovery failed - no metadata found')
  return undefined
}

/**
 * Extracts the authorization server URL from Protected Resource Metadata
 *
 * @param metadata The Protected Resource Metadata
 * @returns The first authorization server URL, or undefined if none
 */
export function getAuthorizationServerUrl(metadata: ProtectedResourceMetadata): string | undefined {
  if (metadata.authorization_servers && metadata.authorization_servers.length > 0) {
    return metadata.authorization_servers[0]
  }
  return undefined
}
