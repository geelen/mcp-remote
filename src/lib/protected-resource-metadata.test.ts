import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchProtectedResourceMetadata, getProtectedResourceMetadataUrl } from './protected-resource-metadata'

describe('protected-resource-metadata', () => {
  describe('getProtectedResourceMetadataUrl', () => {
    it('should construct correct well-known URL for basic resource', () => {
      const url = getProtectedResourceMetadataUrl('https://example.com')
      expect(url).toBe('https://example.com/.well-known/oauth-protected-resource')
    })

    it('should append resource path component to metadata path', () => {
      const url = getProtectedResourceMetadataUrl('https://example.com/api/resource')
      expect(url).toBe('https://example.com/.well-known/oauth-protected-resource/api/resource')
    })

    it('should handle URLs with ports', () => {
      const url = getProtectedResourceMetadataUrl('https://localhost:8080/mcp')
      expect(url).toBe('https://localhost:8080/.well-known/oauth-protected-resource/mcp')
    })
  })

  describe('fetchProtectedResourceMetadata', () => {
    let originalFetch: typeof global.fetch

    beforeEach(() => {
      originalFetch = global.fetch
    })

    afterEach(() => {
      global.fetch = originalFetch
    })

    describe('SSRF Protection', () => {
      it('should block localhost (127.0.0.1)', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://127.0.0.1/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block localhost (::1)', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://[::1]/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block localhost (hostname)', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://localhost/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block private IPv4 10.x.x.x range', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://10.0.0.1/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block private IPv4 172.16-31.x.x range (start of range)', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://172.16.0.1/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block private IPv4 172.16-31.x.x range (end of range)', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://172.31.255.255/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block private IPv4 192.168.x.x range', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://192.168.1.1/resource')
        expect(metadata).toBeUndefined()
      })

      it('should block link-local 169.254.x.x range', async () => {
        const metadata = await fetchProtectedResourceMetadata('http://169.254.169.254/resource')
        expect(metadata).toBeUndefined()
      })

      it('should allow public IPs', async () => {
        const mockMetadata = {
          resource: 'https://8.8.8.8/resource',
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://8.8.8.8/resource')
        expect(metadata).toEqual(mockMetadata)
      })
    })

    describe('Metadata Validation', () => {
      it('should accept valid metadata with matching resource field', async () => {
        const mockMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth.example.com'],
          scopes_supported: ['read', 'write'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toEqual(mockMetadata)
      })

      it('should reject metadata with missing resource field', async () => {
        const mockMetadata = {
          // Missing resource field
          authorization_servers: ['https://auth.example.com'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should reject metadata with resource field mismatch', async () => {
        const mockMetadata = {
          resource: 'https://different.com/api',
          authorization_servers: ['https://auth.example.com'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should reject metadata with invalid URL in resource field', async () => {
        const mockMetadata = {
          resource: 'not-a-valid-url',
          authorization_servers: ['https://auth.example.com'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should use normalized URL comparison (ignoring query params)', async () => {
        const mockMetadata = {
          resource: 'https://example.com/api',
          scopes_supported: ['read'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        // Request URL has query params, but metadata URL doesn't
        const metadata = await fetchProtectedResourceMetadata('https://example.com/api?param=value')
        expect(metadata).toEqual(mockMetadata)
      })
    })

    describe('Success Scenarios', () => {
      it('should fetch complete metadata with all optional fields', async () => {
        const mockMetadata = {
          resource: 'https://example.com/api',
          authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com'],
          scopes_supported: ['read', 'write', 'admin'],
          bearer_methods_supported: ['header', 'body', 'query'],
          jwks_uri: 'https://example.com/.well-known/jwks.json',
          resource_signing_alg_values_supported: ['RS256', 'ES256'],
          tls_client_certificate_bound_access_tokens: true,
          dpop_bound_access_tokens_required: false,
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toEqual(mockMetadata)
        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com/.well-known/oauth-protected-resource/api',
          expect.objectContaining({
            headers: {
              Accept: 'application/json',
            },
          }),
        )
      })

      it('should fetch minimal valid metadata (only resource field)', async () => {
        const mockMetadata = {
          resource: 'https://example.com/mcp',
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/mcp')
        expect(metadata).toEqual(mockMetadata)
      })

      it('should fetch metadata with authorization_servers and scopes_supported', async () => {
        const mockMetadata = {
          resource: 'https://api.example.com/v1',
          authorization_servers: ['https://oauth.example.com'],
          scopes_supported: ['openid', 'email', 'profile', 'api:read', 'api:write'],
        }

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

        const metadata = await fetchProtectedResourceMetadata('https://api.example.com/v1')
        expect(metadata).toEqual(mockMetadata)
        expect(metadata?.authorization_servers).toHaveLength(1)
        expect(metadata?.scopes_supported).toHaveLength(5)
      })
    })

    describe('Error Handling', () => {
      it('should return undefined on 404', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should return undefined on 500 error', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 500,
          statusText: 'Internal Server Error',
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should return undefined on network error', async () => {
        global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should return undefined on timeout', async () => {
        global.fetch = vi.fn().mockRejectedValue(new Error('Timeout'))

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })

      it('should return undefined on invalid JSON', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => {
            throw new Error('Invalid JSON')
          },
        })

        const metadata = await fetchProtectedResourceMetadata('https://example.com/api')
        expect(metadata).toBeUndefined()
      })
    })
  })
})
