import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'

vi.mock('./mcp-auth-config')
vi.mock('./authorization-server-metadata', () => ({
  fetchAuthorizationServerMetadata: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))

describe('NodeOAuthClientProvider - OAuth Scope Handling', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockDeleteConfigFile.mockResolvedValue(undefined)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('scope priority', () => {
    it('should prioritize custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should use scope from registration response', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile read:user',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile read:user')
    })

    it('should fallback to default scopes when none provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('authorization URL', () => {
    it('should include scope parameter in authorization URL', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'github read:user',
        } as any,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('github read:user')
    })

    it('should include default scope in authorization URL when none specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should preserve existing custom scope behavior', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'user:email repo',
        client_name: 'My Custom Client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        software_id: '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d',
        software_version: '1.0.0',
      })
    })
  })

  describe('credential invalidation', () => {
    it('should reset to default scopes after client invalidation', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      mockReadJsonFile.mockResolvedValueOnce(clientInfo)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted custom scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
    })

    it('should not delete client info when invalidating only tokens', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'client_info.json')
    })
  })

  describe('scopes_supported parsing', () => {
    it('should use custom scopes without filtering', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'openid email profile custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use all requested scopes without filtering
      expect(clientMetadata.scope).toBe('openid email profile custom:read custom:write')
    })

    it('should use requested scopes regardless of scopes_supported', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['some', 'other', 'scopes'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use requested scopes even if not in scopes_supported
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when scopes_supported is missing', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        // No scopes_supported
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write special:scope',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write special:scope')
    })

    it('should use scopes when scopes_supported is empty', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes when no metadata is provided', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:read custom:write',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      expect(clientMetadata.scope).toBe('custom:read custom:write')
    })

    it('should use scopes from client registration response', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'openid email profile custom:read',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const clientMetadata = provider.clientMetadata
      // Should use all scopes from registration response
      expect(clientMetadata.scope).toBe('openid email profile custom:read')
    })

    it('should use scopes_supported when no user or client scopes provided', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['openid', 'email'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const clientMetadata = provider.clientMetadata
      // Should use scopes_supported when nothing else is provided
      expect(clientMetadata.scope).toBe('openid email')
    })

    it('should treat empty scope string as no scope and use default', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: '',
        } as any,
      })

      const clientMetadata = provider.clientMetadata
      // Empty scope should fallback to default
      expect(clientMetadata.scope).toBe('openid email profile')
    })
  })

  describe('OAuthMetadata Integration', () => {
    it('should accept oauthMetadata field in constructor', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['api:read', 'api:write'],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['openid', 'email'],
        },
        effectiveScopes: ['api:read', 'api:write'],
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('api:read api:write')
    })

    it('should maintain backward compatibility with deprecated authorizationServerMetadata field', () => {
      const authServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['legacy:scope1', 'legacy:scope2'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: authServerMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('legacy:scope1 legacy:scope2')
    })

    it('should prioritize oauthMetadata over deprecated authorizationServerMetadata', () => {
      const oauthMetadata = {
        authorizationServerMetadata: {
          issuer: 'https://example.com',
          scopes_supported: ['new:scope'],
        },
        discoverySource: 'authorization-server' as const,
      }

      const deprecatedMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['old:scope'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
        authorizationServerMetadata: deprecatedMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('new:scope')
    })

    it('should correctly preserve discoverySource', async () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['api:read'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      // Access the metadata through getAuthorizationServerMetadata
      const authMetadata = await provider.getAuthorizationServerMetadata()
      expect(authMetadata).toBeUndefined()
    })

    it('should handle oauthMetadata with only protected resource metadata', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:read', 'protected:write'],
        },
        effectiveScopes: ['protected:read', 'protected:write'],
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('protected:read protected:write')
    })

    it('should handle oauthMetadata with only auth server metadata', () => {
      const oauthMetadata = {
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:read', 'auth:write'],
        },
        effectiveScopes: ['auth:read', 'auth:write'],
        discoverySource: 'authorization-server' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('auth:read auth:write')
    })

    it('should handle oauthMetadata with discoverySource none', () => {
      const oauthMetadata = {
        discoverySource: 'none' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should handle missing oauthMetadata field', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })
  })

  describe('Scope Priority with RFC 9728', () => {
    it('Priority 1: should use staticOAuthClientMetadata.scope when provided', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:scope'],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:scope'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom:priority1',
        } as any,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom:priority1')
    })

    it('Priority 2: should use _clientInfo.scope when no static scope provided', async () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:scope'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'registered:priority2',
      }

      await provider.saveClientInformation(clientInfo)
      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('registered:priority2')
    })

    it('Priority 3: should use protectedResourceMetadata.scopes_supported (NEW)', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:priority3', 'protected:new'],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:scope'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('protected:priority3 protected:new')
    })

    it('Priority 4: should use authorizationServerMetadata.scopes_supported when no protected resource scopes', () => {
      const oauthMetadata = {
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:priority4', 'auth:fallback'],
        },
        effectiveScopes: ['auth:priority4', 'auth:fallback'],
        discoverySource: 'authorization-server' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('auth:priority4 auth:fallback')
    })

    it('Priority 5: should fallback to openid email profile when no scopes available', () => {
      const oauthMetadata = {
        discoverySource: 'none' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should use protected resource scopes when both metadata types present', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:1', 'protected:2'],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:1', 'auth:2'],
        },
        effectiveScopes: ['protected:1', 'protected:2'],
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('protected:1 protected:2')
      expect(metadata.scope).not.toContain('auth:')
    })

    it('should use auth server scopes when protected resource has no scopes', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          // No scopes_supported
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:read', 'auth:write'],
        },
        effectiveScopes: ['auth:read', 'auth:write'],
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('auth:read auth:write')
    })

    it('should handle empty protected resource scopes array', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: [],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:fallback'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      // Empty array should fall back to auth server scopes
      expect(metadata.scope).toBe('auth:fallback')
    })

    it('should handle empty auth server scopes array', () => {
      const oauthMetadata = {
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: [],
        },
        effectiveScopes: [],
        discoverySource: 'authorization-server' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      // Empty array should fall back to default
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should handle all metadata types present with correct priority', async () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          scopes_supported: ['protected:scope'],
        },
        authorizationServerMetadata: {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:scope'],
        },
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'static:scope',
        } as any,
        oauthMetadata,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'registered:scope',
      }

      await provider.saveClientInformation(clientInfo)

      // Before clientInformation is loaded, should use static scope
      expect(provider.clientMetadata.scope).toBe('static:scope')

      // After clientInformation is loaded, still uses static scope (highest priority)
      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('static:scope')
    })

    it('should handle partial metadata correctly', () => {
      const oauthMetadata = {
        protectedResourceMetadata: {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          // No scopes_supported in protected resource
        },
        // No auth server metadata
        discoverySource: 'protected-resource' as const,
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        oauthMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should maintain backward compatibility with existing scope logic', () => {
      // Test that old code using authorizationServerMetadata still works
      const authServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: ['backward:compatible'],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: authServerMetadata,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('backward:compatible')
    })
  })
})
