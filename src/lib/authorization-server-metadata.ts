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
 * @returns The well-known metadata URL candidates
 */
export function getMetadataUrls(serverUrl: string): string[] {
  const url = new URL(serverUrl)
  return [
    `${url.origin}/.well-known/oauth-authorization-server`, // Per RFC 8414, the metadata is at /.well-known/oauth-authorization-server relative to the issuer identifier
    `${url.href.replace(/\/$/, '')}/.well-known/openid-configuration` // Per RFC 8414, the OIDC metadata might be used for compatibility
  ]
}

/**
 * Fetches OAuth 2.0 Authorization Server Metadata from the well-known endpoint
 * @param serverUrl The server URL to fetch metadata for
 * @returns The authorization server metadata, or undefined if fetch fails
 */
export async function fetchAuthorizationServerMetadata(serverUrl: string): Promise<AuthorizationServerMetadata | undefined> {
  const metadataUrlCandidates = getMetadataUrls(serverUrl)

  try {
    let response: Response
    for (const metadataUrl of metadataUrlCandidates) {
      debugLog('Fetching authorization server metadata', { metadataUrl })
      response = await fetch(metadataUrl, {
        headers: {
          Accept: 'application/json',
        },
        // Short timeout to avoid blocking
        signal: AbortSignal.timeout(5000),
      })

      if (!response.ok) {
        if (response.status === 404) {
          debugLog('Authorization server metadata endpoint not found (404)', { metadataUrl })
          continue;
        } else {
          debugLog('Failed to fetch authorization server metadata', {
            status: response.status,
            statusText: response.statusText,
          })
        }
        return undefined
      } else {
        const metadata = (await response.json()) as AuthorizationServerMetadata

        debugLog('Successfully fetched authorization server metadata', {
          issuer: metadata.issuer,
          scopes_supported: metadata.scopes_supported,
          scopeCount: metadata.scopes_supported?.length || 0,
        })

        return metadata
      }
    }

  } catch (error) {
    debugLog('Error fetching authorization server metadata', {
      error: error instanceof Error ? error.message : String(error),
      metadataUrlCandidates,
    })
    return undefined
  }
}
