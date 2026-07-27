import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import open from 'open'
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
  let mockFetch: ReturnType<typeof vi.fn>

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
    vi.unstubAllGlobals()
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

    it('should replace an existing authorization URL scope with the default scope when none is specified', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const authUrl = new URL('https://auth.example.com/authorize?scope=existing')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('openid email profile')
    })

    it('invalidates a cached dynamic client when authorization reports it is no longer registered', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'stale-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      await provider.clientInformation()
      mockFetch = vi.fn().mockResolvedValue({
        status: 400,
        json: async () => ({
          registration_endpoint: 'https://auth.example.com/register',
          error: 'invalid_request',
          error_description: "Client ID 'stale-client' is not registered with this server",
        }),
      })
      vi.stubGlobal('fetch', mockFetch)

      await expect(
        provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=stale-client')),
      ).rejects.toMatchObject({
        name: 'StaleClientRegistrationError',
        message: 'Cached OAuth client registration is no longer valid',
      })

      expect(mockFetch).toHaveBeenCalledWith(
        'https://auth.example.com/authorize?client_id=stale-client&scope=openid+email+profile',
        expect.objectContaining({
          redirect: 'manual',
          headers: { Accept: 'application/json' },
          signal: expect.any(AbortSignal),
        }),
      )
      expect(mockDeleteConfigFile).toHaveBeenCalledTimes(3)
      expect(mockDeleteConfigFile.mock.calls.map(([, fileName]: [string, string]) => fileName)).toEqual(
        expect.arrayContaining(['client_info.json', 'tokens.json', 'code_verifier.txt']),
      )
      expect(open).not.toHaveBeenCalled()
    })

    it('retains cached credentials and opens the browser when authorization redirects', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'active-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      await provider.clientInformation()
      mockFetch = vi.fn().mockResolvedValue({ status: 302 })
      vi.stubGlobal('fetch', mockFetch)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=active-client'))

      expect(mockFetch).toHaveBeenCalledWith(
        'https://auth.example.com/authorize?client_id=active-client&scope=openid+email+profile',
        expect.objectContaining({
          redirect: 'manual',
          headers: { Accept: 'application/json' },
          signal: expect.any(AbortSignal),
        }),
      )
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      expect(open).toHaveBeenCalledOnce()
    })

    it('does not invalidate a cached client when its redirect URI is described as not registered', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValueOnce({
        client_id: 'active-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      await provider.clientInformation()
      mockFetch = vi.fn().mockResolvedValue({
        status: 400,
        json: async () => ({
          registration_endpoint: 'https://auth.example.com/register',
          error: 'invalid_request',
          error_description: 'The client redirect URI is not registered',
        }),
      })
      vi.stubGlobal('fetch', mockFetch)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=active-client'))

      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
      expect(open).toHaveBeenCalledOnce()
    })

    it('does not preflight a freshly dynamically registered client', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.saveClientInformation({
        client_id: 'fresh-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      mockFetch = vi.fn()
      vi.stubGlobal('fetch', mockFetch)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=fresh-client'))

      expect(mockFetch).not.toHaveBeenCalled()
      expect(open).toHaveBeenCalledOnce()
    })

    it('does not preflight a static client registration', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientInfo: {
          client_id: 'static-client',
          redirect_uris: ['http://localhost:8080/oauth/callback'],
        },
      })
      mockFetch = vi.fn()
      vi.stubGlobal('fetch', mockFetch)

      await provider.clientInformation()
      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=static-client'))

      expect(mockFetch).not.toHaveBeenCalled()
      expect(open).toHaveBeenCalledOnce()
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
})
