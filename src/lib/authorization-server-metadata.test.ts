import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  fetchAuthorizationServerMetadata,
  fetchAuthorizationServerMetadataFromIssuer,
  discoverOAuthMetadata,
  getMetadataUrl,
} from './authorization-server-metadata'
import * as protectedResourceMetadata from './protected-resource-metadata'

describe('authorization-server-metadata', () => {
  describe('getMetadataUrl', () => {
    it('should construct correct well-known URL', () => {
      const url = getMetadataUrl('https://example.com/mcp')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with different paths', () => {
      const url = getMetadataUrl('https://api.example.com/v1/mcp/server')
      expect(url).toBe('https://api.example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with ports', () => {
      const url = getMetadataUrl('https://localhost:8080/mcp')
      expect(url).toBe('https://localhost:8080/.well-known/oauth-authorization-server')
    })
  })

  describe('fetchAuthorizationServerMetadata', () => {
    let originalFetch: typeof global.fetch

    beforeEach(() => {
      originalFetch = global.fetch
    })

    afterEach(() => {
      global.fetch = originalFetch
    })

    it('should fetch and parse metadata successfully', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        scopes_supported: ['openid', 'email', 'profile', 'custom:read'],
        response_types_supported: ['code'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith(
        'https://example.com/.well-known/oauth-authorization-server',
        expect.objectContaining({
          headers: {
            Accept: 'application/json',
          },
        }),
      )
    })

    it('should return undefined on 404', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should return undefined on other HTTP errors', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should return undefined on network errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should handle timeout errors', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Timeout'))

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should handle metadata without scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        authorization_endpoint: 'https://example.com/oauth/authorize',
        token_endpoint: 'https://example.com/oauth/token',
        // No scopes_supported
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toBeUndefined()
    })

    it('should handle metadata with empty scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toEqual([])
    })
  })

  describe('fetchAuthorizationServerMetadataFromIssuer', () => {
    let originalFetch: typeof global.fetch

    beforeEach(() => {
      originalFetch = global.fetch
    })

    afterEach(() => {
      global.fetch = originalFetch
    })

    it('should fetch metadata successfully from issuer URL', async () => {
      const mockMetadata = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        token_endpoint: 'https://auth.example.com/token',
        scopes_supported: ['openid', 'email', 'profile'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith(
        'https://auth.example.com/.well-known/oauth-authorization-server',
        expect.objectContaining({
          headers: {
            Accept: 'application/json',
          },
        }),
      )
    })

    it('should handle issuer URL with path component', async () => {
      const mockMetadata = {
        issuer: 'https://auth.example.com/oauth',
        scopes_supported: ['openid'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com/oauth')
      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith('https://auth.example.com/oauth/.well-known/oauth-authorization-server', expect.anything())
    })

    it('should construct well-known URL correctly from issuer', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ issuer: 'https://auth.example.com/v1' }),
      })

      await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com/v1')
      expect(global.fetch).toHaveBeenCalledWith('https://auth.example.com/v1/.well-known/oauth-authorization-server', expect.anything())
    })

    it('should return undefined on 404', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toBeUndefined()
    })

    it('should return undefined on 500 error', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toBeUndefined()
    })

    it('should return undefined on network error', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toBeUndefined()
    })

    it('should return undefined on timeout', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Timeout'))

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toBeUndefined()
    })

    it('should handle metadata without scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://auth.example.com',
        authorization_endpoint: 'https://auth.example.com/authorize',
        // No scopes_supported
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toBeUndefined()
    })

    it('should handle metadata with empty scopes_supported', async () => {
      const mockMetadata = {
        issuer: 'https://auth.example.com',
        scopes_supported: [],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await fetchAuthorizationServerMetadataFromIssuer('https://auth.example.com')
      expect(metadata).toEqual(mockMetadata)
      expect(metadata?.scopes_supported).toEqual([])
    })
  })

  describe('discoverOAuthMetadata', () => {
    let originalFetch: typeof global.fetch
    let mockFetchProtectedResourceMetadata: any

    beforeEach(() => {
      originalFetch = global.fetch
      mockFetchProtectedResourceMetadata = vi.spyOn(protectedResourceMetadata, 'fetchProtectedResourceMetadata')
    })

    afterEach(() => {
      global.fetch = originalFetch
      vi.restoreAllMocks()
    })

    describe('Stage 1: Protected Resource Discovery', () => {
      it('should discover via protected resource with authorization_servers', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['api:read', 'api:write'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          authorization_endpoint: 'https://auth.example.com/authorize',
          token_endpoint: 'https://auth.example.com/token',
          scopes_supported: ['openid', 'email'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('protected-resource')
        expect(result.protectedResourceMetadata).toEqual(protectedMetadata)
        expect(result.authorizationServerMetadata).toEqual(authServerMetadata)
        expect(result.effectiveScopes).toEqual(['api:read', 'api:write'])
      })

      it('should prioritize protected resource scopes over auth server scopes', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['custom:read', 'custom:write'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['openid', 'email'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['custom:read', 'custom:write'])
        expect(result.effectiveScopes).not.toEqual(['openid', 'email'])
      })

      it('should try multiple authorization servers in order', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com'],
        }

        const authServerMetadata = {
          issuer: 'https://auth1.example.com',
          scopes_supported: ['openid'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('protected-resource')
        expect(global.fetch).toHaveBeenCalledWith(
          expect.stringContaining('auth1.example.com'),
          expect.objectContaining({
            headers: expect.objectContaining({
              Accept: 'application/json',
            }),
          }),
        )
      })

      it('should use second auth server when first fails', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com'],
        }

        const authServerMetadata2 = {
          issuer: 'https://auth2.example.com',
          scopes_supported: ['openid', 'email'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)

        // First call fails (auth1), second succeeds (auth2)
        global.fetch = vi
          .fn()
          .mockResolvedValueOnce({
            ok: false,
            status: 404,
          })
          .mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => authServerMetadata2,
          })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('protected-resource')
        expect(result.authorizationServerMetadata).toEqual(authServerMetadata2)
        expect(global.fetch).toHaveBeenCalledTimes(2)
      })

      it('should fallback to RFC 8414 when all auth servers fail', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com'],
        }

        const fallbackMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['fallback:scope'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)

        // First two calls fail (auth servers), third succeeds (fallback to resource server)
        global.fetch = vi
          .fn()
          .mockResolvedValueOnce({ ok: false, status: 404 })
          .mockResolvedValueOnce({ ok: false, status: 404 })
          .mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => fallbackMetadata,
          })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
        expect(result.authorizationServerMetadata).toEqual(fallbackMetadata)
        expect(result.protectedResourceMetadata).toBeUndefined()
      })

      it('should fallback when protected resource has no authorization_servers', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          scopes_supported: ['api:read'],
          // No authorization_servers
        }

        const fallbackMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['openid'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => fallbackMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
      })

      it('should fallback when protected resource has empty authorization_servers', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: [],
        }

        const fallbackMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['openid'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => fallbackMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
      })

      it('should fallback when protected resource not found (404)', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const fallbackMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['openid'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => fallbackMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
      })

      it('should use auth server scopes when protected resource has no scopes', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          // No scopes_supported
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['openid', 'email', 'profile'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['openid', 'email', 'profile'])
      })
    })

    describe('Stage 2: Authorization Server Fallback', () => {
      it('should succeed with fallback after protected resource fails', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          authorization_endpoint: 'https://example.com/authorize',
          token_endpoint: 'https://example.com/token',
          scopes_supported: ['openid', 'email'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
        expect(result.authorizationServerMetadata).toEqual(authServerMetadata)
        expect(result.protectedResourceMetadata).toBeUndefined()
      })

      it('should return correct discovery source for fallback', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['openid'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
      })

      it('should use fallback scopes_supported', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['custom:read', 'custom:write', 'custom:admin'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['custom:read', 'custom:write', 'custom:admin'])
      })

      it('should handle fallback without scopes_supported', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          // No scopes_supported
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
        expect(result.effectiveScopes).toBeUndefined()
      })

      it('should handle fallback with empty scopes_supported', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          scopes_supported: [],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('authorization-server')
        expect(result.effectiveScopes).toBeUndefined()
      })

      it('should call resource server metadata endpoint for fallback', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['openid'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        await discoverOAuthMetadata('https://example.com/api')

        expect(global.fetch).toHaveBeenCalledWith('https://example.com/.well-known/oauth-authorization-server', expect.anything())
      })
    })

    describe('Stage 3: Complete Failure', () => {
      it('should return discoverySource none when both methods fail', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 404,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('none')
      })

      it('should have no effectiveScopes on complete failure', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 500,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toBeUndefined()
      })

      it('should have no metadata on complete failure', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.protectedResourceMetadata).toBeUndefined()
        expect(result.authorizationServerMetadata).toBeUndefined()
        expect(result.discoverySource).toBe('none')
      })
    })

    describe('Scope Priority', () => {
      it('should prioritize protected resource scopes over auth server scopes', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['priority:1', 'priority:2'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['priority:3', 'priority:4'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['priority:1', 'priority:2'])
      })

      it('should use auth server scopes when protected resource has none', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['openid', 'email'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['openid', 'email'])
      })

      it('should handle empty protected resource scopes array', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: [],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['openid'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        // Empty arrays are treated as undefined, so falls back to auth server scopes
        expect(result.effectiveScopes).toEqual(['openid'])
      })

      it('should handle empty auth server scopes array', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: [],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        // Empty arrays are treated as undefined, so no scopes available
        expect(result.effectiveScopes).toBeUndefined()
      })

      it('should populate effectiveScopes correctly for protected resource discovery', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['scope1', 'scope2', 'scope3'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toBeDefined()
        expect(result.effectiveScopes).toHaveLength(3)
      })

      it('should populate effectiveScopes correctly for auth server fallback', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)

        const authServerMetadata = {
          issuer: 'https://example.com',
          scopes_supported: ['fallback1', 'fallback2'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.effectiveScopes).toEqual(['fallback1', 'fallback2'])
      })

      it('should handle both metadata present with protected resource priority', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['protected:scope1', 'protected:scope2'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          scopes_supported: ['auth:scope1', 'auth:scope2'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.protectedResourceMetadata).toBeDefined()
        expect(result.authorizationServerMetadata).toBeDefined()
        expect(result.effectiveScopes).toEqual(['protected:scope1', 'protected:scope2'])
      })
    })

    describe('Integration Tests', () => {
      it('should complete full successful discovery path', async () => {
        const protectedMetadata = {
          resource: 'https://api.example.com/v1',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['api:read', 'api:write', 'api:admin'],
          bearer_methods_supported: ['header'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          authorization_endpoint: 'https://auth.example.com/authorize',
          token_endpoint: 'https://auth.example.com/token',
          scopes_supported: ['openid', 'email', 'profile'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://api.example.com/v1')

        expect(result.discoverySource).toBe('protected-resource')
        expect(result.protectedResourceMetadata).toEqual(protectedMetadata)
        expect(result.authorizationServerMetadata).toEqual(authServerMetadata)
        expect(result.effectiveScopes).toEqual(['api:read', 'api:write', 'api:admin'])
      })

      it('should populate all metadata fields correctly', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['scope1'],
        }

        const authServerMetadata = {
          issuer: 'https://auth.example.com',
          authorization_endpoint: 'https://auth.example.com/authorize',
          token_endpoint: 'https://auth.example.com/token',
          scopes_supported: ['scope2'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => authServerMetadata,
        })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result).toHaveProperty('protectedResourceMetadata')
        expect(result).toHaveProperty('authorizationServerMetadata')
        expect(result).toHaveProperty('effectiveScopes')
        expect(result).toHaveProperty('discoverySource')
      })

      it('should verify discoverySource accuracy across all paths', async () => {
        // Test protected resource path
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ issuer: 'https://auth.example.com' }),
        })

        let result = await discoverOAuthMetadata('https://example.com/api')
        expect(result.discoverySource).toBe('protected-resource')

        // Test fallback path
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ issuer: 'https://example.com' }),
        })

        result = await discoverOAuthMetadata('https://example.com/api')
        expect(result.discoverySource).toBe('authorization-server')

        // Test failure path
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockResolvedValue({ ok: false, status: 404 })

        result = await discoverOAuthMetadata('https://example.com/api')
        expect(result.discoverySource).toBe('none')
      })

      it('should handle complex multi-stage scenario with retries', async () => {
        const protectedMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com', 'https://auth3.example.com'],
          scopes_supported: ['api:read'],
        }

        const authServerMetadata3 = {
          issuer: 'https://auth3.example.com',
          scopes_supported: ['openid'],
        }

        mockFetchProtectedResourceMetadata.mockResolvedValue(protectedMetadata)

        // First two fail, third succeeds
        global.fetch = vi
          .fn()
          .mockResolvedValueOnce({ ok: false, status: 404 })
          .mockResolvedValueOnce({ ok: false, status: 500 })
          .mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => authServerMetadata3,
          })

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('protected-resource')
        expect(result.authorizationServerMetadata).toEqual(authServerMetadata3)
        expect(global.fetch).toHaveBeenCalledTimes(3)
      })

      it('should handle network failures gracefully throughout discovery', async () => {
        mockFetchProtectedResourceMetadata.mockResolvedValue(undefined)
        global.fetch = vi.fn().mockRejectedValue(new Error('Network failure'))

        const result = await discoverOAuthMetadata('https://example.com/api')

        expect(result.discoverySource).toBe('none')
        expect(result.protectedResourceMetadata).toBeUndefined()
        expect(result.authorizationServerMetadata).toBeUndefined()
        expect(result.effectiveScopes).toBeUndefined()
      })
    })
  })
})
