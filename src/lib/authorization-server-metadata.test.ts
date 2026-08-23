import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchAuthorizationServerMetadata, getMetadataUrl, getMetadataUrls } from './authorization-server-metadata'

describe('authorization-server-metadata', () => {
  describe('getMetadataUrl', () => {
    it('should construct correct well-known URL', () => {
      const url = getMetadataUrl('https://example.com')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with a trailing slash', () => {
      const url = getMetadataUrl('https://example.com/')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server')
    })

    it('should handle URLs with trailing slashes', () => {
      const url = getMetadataUrl('https://example.com///')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server')
    })

    it('should construct well-known URL using path insertion when URL has path components', () => {
      const url = getMetadataUrl('https://example.com/mcp')
      expect(url).toBe('https://example.com/.well-known/oauth-authorization-server/mcp')
    })

    it('should handle URLs with different paths', () => {
      const url = getMetadataUrl('https://api.example.com/v1/mcp/server')
      expect(url).toBe('https://api.example.com/.well-known/oauth-authorization-server/v1/mcp/server')
    })

    it('should handle URLs with ports', () => {
      const url = getMetadataUrl('https://localhost:8080/mcp')
      expect(url).toBe('https://localhost:8080/.well-known/oauth-authorization-server/mcp')
    })
  })

  describe('getMetadataUrls', () => {
    it('should try RFC 8414 insertion, then the root, then the OIDC shapes', () => {
      // A path-bearing issuer can be served in any of these shapes, so probe rather
      // than guess. The root entry is what servers fixed by #240 answer on.
      expect(getMetadataUrls('https://example.com/auth/realms/myRealm')).toEqual([
        'https://example.com/.well-known/oauth-authorization-server/auth/realms/myRealm',
        'https://example.com/.well-known/oauth-authorization-server',
        'https://example.com/.well-known/openid-configuration/auth/realms/myRealm',
        'https://example.com/auth/realms/myRealm/.well-known/openid-configuration',
      ])
    })

    it('should only try the root shapes when the issuer has no path', () => {
      expect(getMetadataUrls('https://example.com')).toEqual([
        'https://example.com/.well-known/oauth-authorization-server',
        'https://example.com/.well-known/openid-configuration',
      ])
    })

    it('should not double up separators on a trailing slash', () => {
      expect(getMetadataUrls('https://example.com/mcp///')[0]).toBe('https://example.com/.well-known/oauth-authorization-server/mcp')
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
        'https://example.com/.well-known/oauth-authorization-server/mcp',
        expect.objectContaining({
          headers: {
            Accept: 'application/json',
            'Accept-Encoding': 'identity',
          },
        }),
      )
    })

    it('should fall back to the root URL when path insertion 404s', async () => {
      // Servers that ignore the path and serve metadata at the root would otherwise
      // be stranded by a path-only implementation
      const mockMetadata = { issuer: 'https://example.com', token_endpoint: 'https://example.com/oauth/token' }
      global.fetch = vi.fn(async (url: any) =>
        url === 'https://example.com/.well-known/oauth-authorization-server'
          ? { ok: true, status: 200, json: async () => mockMetadata }
          : { ok: false, status: 404, statusText: 'Not Found' },
      ) as any

      const metadata = await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledTimes(2)
    })

    it('should reach an OIDC issuer that appends the well-known segment', async () => {
      // Keycloak realms, the case reported in #128
      const issuer = 'https://example.com/auth/realms/myRealm'
      const mockMetadata = { issuer, token_endpoint: `${issuer}/protocol/openid-connect/token` }
      global.fetch = vi.fn(async (url: any) =>
        url === `${issuer}/.well-known/openid-configuration`
          ? { ok: true, status: 200, json: async () => mockMetadata }
          : { ok: false, status: 404, statusText: 'Not Found' },
      ) as any

      const metadata = await fetchAuthorizationServerMetadata(issuer)

      expect(metadata).toEqual(mockMetadata)
    })

    it('should stop at the first candidate that answers', async () => {
      const mockMetadata = { issuer: 'https://example.com/mcp' }
      global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: async () => mockMetadata })

      await fetchAuthorizationServerMetadata('https://example.com/mcp')

      expect(global.fetch).toHaveBeenCalledTimes(1)
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
})
