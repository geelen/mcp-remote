import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  parseWWWAuthenticateHeader,
  buildProtectedResourceMetadataUrls,
  discoverProtectedResourceMetadata,
  getAuthorizationServerUrl,
  type ProtectedResourceMetadata,
} from './protected-resource-metadata'

describe('protected-resource-metadata', () => {
  describe('parseWWWAuthenticateHeader', () => {
    it('should parse resource_metadata URL from header', () => {
      const header = 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.resourceMetadataUrl).toBe('https://mcp.example.com/.well-known/oauth-protected-resource')
    })

    it('should parse scope from header', () => {
      const header = 'Bearer scope="files:read files:write"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.scope).toBe('files:read files:write')
    })

    it('should parse both resource_metadata and scope', () => {
      const header = 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", scope="read write"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.resourceMetadataUrl).toBe('https://mcp.example.com/.well-known/oauth-protected-resource')
      expect(result.scope).toBe('read write')
    })

    it('should parse error and error_description', () => {
      const header = 'Bearer error="invalid_request", error_description="No access token was provided"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.error).toBe('invalid_request')
      expect(result.errorDescription).toBe('No access token was provided')
    })

    it('should parse Supabase-style WWW-Authenticate header', () => {
      const header =
        'Bearer error="invalid_request", error_description="No access token was provided in this request", resource_metadata="https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.error).toBe('invalid_request')
      expect(result.errorDescription).toBe('No access token was provided in this request')
      expect(result.resourceMetadataUrl).toBe('https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp')
    })

    it('should handle empty header', () => {
      const result = parseWWWAuthenticateHeader('')

      expect(result.resourceMetadataUrl).toBeUndefined()
      expect(result.scope).toBeUndefined()
    })

    it('should handle header without Bearer prefix', () => {
      const header = 'resource_metadata="https://example.com/prm"'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.resourceMetadataUrl).toBe('https://example.com/prm')
    })

    it('should handle unquoted values', () => {
      const header = 'Bearer error=invalid_token'
      const result = parseWWWAuthenticateHeader(header)

      expect(result.error).toBe('invalid_token')
    })
  })

  describe('buildProtectedResourceMetadataUrls', () => {
    it('should build path-specific and root URLs for URL with path', () => {
      const urls = buildProtectedResourceMetadataUrls('https://mcp.example.com/mcp')

      expect(urls).toEqual([
        'https://mcp.example.com/.well-known/oauth-protected-resource/mcp',
        'https://mcp.example.com/.well-known/oauth-protected-resource',
      ])
    })

    it('should build only root URL for URL without path', () => {
      const urls = buildProtectedResourceMetadataUrls('https://mcp.example.com')

      expect(urls).toEqual(['https://mcp.example.com/.well-known/oauth-protected-resource'])
    })

    it('should build only root URL for URL with just slash', () => {
      const urls = buildProtectedResourceMetadataUrls('https://mcp.example.com/')

      expect(urls).toEqual(['https://mcp.example.com/.well-known/oauth-protected-resource'])
    })

    it('should handle deep paths', () => {
      const urls = buildProtectedResourceMetadataUrls('https://api.example.com/v1/mcp/server')

      expect(urls).toEqual([
        'https://api.example.com/.well-known/oauth-protected-resource/v1/mcp/server',
        'https://api.example.com/.well-known/oauth-protected-resource',
      ])
    })

    it('should handle URLs with ports', () => {
      const urls = buildProtectedResourceMetadataUrls('https://localhost:8080/mcp')

      expect(urls).toEqual([
        'https://localhost:8080/.well-known/oauth-protected-resource/mcp',
        'https://localhost:8080/.well-known/oauth-protected-resource',
      ])
    })

    it('should strip trailing slash from path', () => {
      const urls = buildProtectedResourceMetadataUrls('https://example.com/mcp/')

      expect(urls).toEqual([
        'https://example.com/.well-known/oauth-protected-resource/mcp',
        'https://example.com/.well-known/oauth-protected-resource',
      ])
    })
  })

  describe('discoverProtectedResourceMetadata', () => {
    let originalFetch: typeof global.fetch

    beforeEach(() => {
      originalFetch = global.fetch
    })

    afterEach(() => {
      global.fetch = originalFetch
    })

    it('should use resource_metadata URL from WWW-Authenticate header', async () => {
      const mockMetadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com/mcp',
        authorization_servers: ['https://auth.example.com'],
        scopes_supported: ['read', 'write'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const header = 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp', header)

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith(
        'https://mcp.example.com/.well-known/oauth-protected-resource/mcp',
        expect.objectContaining({
          headers: { Accept: 'application/json' },
        }),
      )
    })

    it('should fall back to well-known URLs if header URL fails', async () => {
      const mockMetadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com/mcp',
        authorization_servers: ['https://auth.example.com'],
      }

      // First call (header URL) fails, second call (path-specific well-known) succeeds
      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

      const header = 'Bearer resource_metadata="https://mcp.example.com/invalid-url"'
      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp', header)

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledTimes(2)
    })

    it('should try path-specific URL first when no header provided', async () => {
      const mockMetadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com/mcp',
        authorization_servers: ['https://auth.example.com'],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockMetadata,
      })

      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledWith('https://mcp.example.com/.well-known/oauth-protected-resource/mcp', expect.any(Object))
    })

    it('should fall back to root well-known URL if path-specific fails', async () => {
      const mockMetadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com',
        authorization_servers: ['https://auth.example.com'],
      }

      global.fetch = vi
        .fn()
        .mockResolvedValueOnce({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => mockMetadata,
        })

      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp')

      expect(metadata).toEqual(mockMetadata)
      expect(global.fetch).toHaveBeenCalledTimes(2)
      expect(global.fetch).toHaveBeenNthCalledWith(2, 'https://mcp.example.com/.well-known/oauth-protected-resource', expect.any(Object))
    })

    it('should return undefined if all discovery methods fail', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      })

      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should handle network errors gracefully', async () => {
      global.fetch = vi.fn().mockRejectedValue(new Error('Network error'))

      const metadata = await discoverProtectedResourceMetadata('https://mcp.example.com/mcp')

      expect(metadata).toBeUndefined()
    })

    it('should parse Supabase Protected Resource Metadata correctly', async () => {
      const supabaseMetadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.supabase.com/mcp',
        bearer_methods_supported: ['Bearer'],
        authorization_servers: ['https://api.supabase.com'],
        resource_documentation: 'https://api.supabase.com/api/mcp',
        resource_name: 'Supabase MCP (Beta)',
        scopes_supported: [
          'organizations:read',
          'projects:read',
          'projects:write',
          'database:write',
          'database:read',
          'analytics:read',
          'secrets:read',
          'edge_functions:read',
          'edge_functions:write',
          'environment:read',
          'environment:write',
          'storage:read',
        ],
      }

      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => supabaseMetadata,
      })

      const header =
        'Bearer error="invalid_request", error_description="No access token was provided in this request", resource_metadata="https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp"'
      const metadata = await discoverProtectedResourceMetadata('https://mcp.supabase.com/mcp', header)

      expect(metadata).toEqual(supabaseMetadata)
      expect(metadata?.authorization_servers).toEqual(['https://api.supabase.com'])
      expect(metadata?.scopes_supported).toContain('organizations:read')
      expect(metadata?.scopes_supported).toContain('database:write')
    })
  })

  describe('getAuthorizationServerUrl', () => {
    it('should return first authorization server from metadata', () => {
      const metadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com',
        authorization_servers: ['https://auth1.example.com', 'https://auth2.example.com'],
      }

      const url = getAuthorizationServerUrl(metadata)

      expect(url).toBe('https://auth1.example.com')
    })

    it('should return undefined if authorization_servers is empty', () => {
      const metadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com',
        authorization_servers: [],
      }

      const url = getAuthorizationServerUrl(metadata)

      expect(url).toBeUndefined()
    })

    it('should return undefined if authorization_servers is missing', () => {
      const metadata: ProtectedResourceMetadata = {
        resource: 'https://mcp.example.com',
      }

      const url = getAuthorizationServerUrl(metadata)

      expect(url).toBeUndefined()
    })
  })
})
