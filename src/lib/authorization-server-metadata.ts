import { debugLog } from './utils'
import {
  fetchProtectedResourceMetadata,
  type ProtectedResourceMetadata,
} from './protected-resource-metadata'

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
 * Unified OAuth metadata containing both protected resource and authorization server metadata
 */
export interface OAuthMetadata {
  /** Protected resource metadata (RFC 9728) */
  protectedResourceMetadata?: ProtectedResourceMetadata
  /** Authorization server metadata (RFC 8414) */
  authorizationServerMetadata?: AuthorizationServerMetadata
  /** Combined effective scopes (priority: protected resource > authorization server) */
  effectiveScopes?: string[]
  /** Discovery source for debugging */
  discoverySource: 'protected-resource' | 'authorization-server' | 'none'
}

/**
 * Constructs the well-known URL for OAuth authorization server metadata
 * @param serverUrl The base server URL
 * @returns The well-known metadata URL
 */
export function getMetadataUrl(serverUrl: string): string {
  const url = new URL(serverUrl)
  // Per RFC 8414, the metadata is at /.well-known/oauth-authorization-server
  // relative to the issuer identifier
  const metadataPath = '/.well-known/oauth-authorization-server'

  // Construct the full metadata URL
  return `${url.origin}${metadataPath}`
}

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoint
 * @param serverUrl The server URL to fetch metadata for
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadata(serverUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  const metadataUrl = getMetadataUrl(serverUrl)

  debugLog('Fetching authorization server metadata', { serverUrl, metadataUrl })

  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: 'application/json',
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

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from an issuer URL
 * This is used when discovering the auth server from protected resource metadata
 *
 * @param issuerUrl The authorization server's issuer identifier URL
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadataFromIssuer(
  issuerUrl: string,
): Promise<AuthorizationServerMetadata | undefined> {
  // Construct the well-known metadata URL from the issuer
  const issuer = new URL(issuerUrl)
  const metadataUrl = `${issuer.origin}${issuer.pathname}/.well-known/oauth-authorization-server`

  debugLog('Fetching authorization server metadata from issuer', { issuerUrl, metadataUrl })

  try {
    const response = await fetch(metadataUrl, {
      headers: {
        Accept: 'application/json',
      },
      // Short timeout to avoid blocking
      signal: AbortSignal.timeout(5000),
    })

    if (!response.ok) {
      debugLog('Failed to fetch authorization server metadata from issuer', {
        issuerUrl,
        status: response.status,
        statusText: response.statusText,
      })
      return undefined
    }

    const metadata = (await response.json()) as AuthorizationServerMetadata

    debugLog('Successfully fetched authorization server metadata from issuer', {
      issuer: metadata.issuer,
      scopes_supported: metadata.scopes_supported,
      scopeCount: metadata.scopes_supported?.length || 0,
    })

    return metadata
  } catch (error) {
    debugLog('Error fetching authorization server metadata from issuer', {
      error: error instanceof Error ? error.message : String(error),
      issuerUrl,
      metadataUrl,
    })
    return undefined
  }
}

/**
 * Discovers OAuth metadata using a multi-stage approach:
 * 1. Try RFC 9728 Protected Resource Metadata discovery
 * 2. If successful and has authorization_servers, try each issuer
 * 3. Fall back to RFC 8414 Authorization Server Metadata on resource server
 *
 * This implements the full RFC 9728 discovery flow with backward compatibility
 *
 * @param resourceUrl The resource server URL
 * @returns Unified OAuth metadata with discovery source
 */
export async function discoverOAuthMetadata(resourceUrl: string): Promise<OAuthMetadata> {
  debugLog('Starting OAuth metadata discovery', { resourceUrl })

  // Stage 1: Try protected resource metadata (RFC 9728)
  const protectedResourceMetadata = await fetchProtectedResourceMetadata(resourceUrl)

  if (protectedResourceMetadata) {
    debugLog('Protected resource metadata found', {
      hasAuthServers: !!protectedResourceMetadata.authorization_servers?.length,
      authServerCount: protectedResourceMetadata.authorization_servers?.length || 0,
    })

    // If we have authorization servers, try each one
    if (protectedResourceMetadata.authorization_servers?.length) {
      debugLog('Trying authorization servers from protected resource metadata', {
        servers: protectedResourceMetadata.authorization_servers,
      })

      for (const issuerUrl of protectedResourceMetadata.authorization_servers) {
        debugLog('Attempting to fetch metadata from issuer', { issuerUrl })

        const authServerMetadata = await fetchAuthorizationServerMetadataFromIssuer(issuerUrl)

        if (authServerMetadata) {
          // Success! We have both protected resource and auth server metadata
          const effectiveScopes =
            protectedResourceMetadata.scopes_supported ||
            authServerMetadata.scopes_supported

          debugLog('OAuth metadata discovery successful via protected resource', {
            discoverySource: 'protected-resource',
            effectiveScopes,
          })

          return {
            protectedResourceMetadata,
            authorizationServerMetadata: authServerMetadata,
            effectiveScopes,
            discoverySource: 'protected-resource',
          }
        }
      }

      debugLog('All authorization servers from protected resource metadata failed')
      // Fall through to fallback
    } else {
      debugLog('Protected resource metadata has no authorization_servers, falling back')
      // Fall through to fallback
    }
  }

  // Stage 2: Fallback to authorization server metadata on resource server (RFC 8414)
  debugLog('Falling back to authorization server metadata on resource server')
  const authServerMetadata = await fetchAuthorizationServerMetadata(resourceUrl)

  if (authServerMetadata) {
    debugLog('OAuth metadata discovery successful via authorization server fallback', {
      discoverySource: 'authorization-server',
      effectiveScopes: authServerMetadata.scopes_supported,
    })

    return {
      authorizationServerMetadata: authServerMetadata,
      effectiveScopes: authServerMetadata.scopes_supported,
      discoverySource: 'authorization-server',
    }
  }

  // Stage 3: Complete failure
  debugLog('OAuth metadata discovery failed - no metadata available')

  return {
    discoverySource: 'none',
  }
}
