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
  let mockReadTextFile: any
  let mockWriteTextFile: any
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
    mockReadTextFile = vi.mocked(mcpAuthConfig.readTextFile)
    mockWriteTextFile = vi.mocked(mcpAuthConfig.writeTextFile)
    mockDeleteConfigFile = vi.mocked(mcpAuthConfig.deleteConfigFile)

    mockReadJsonFile.mockResolvedValue(undefined)
    mockWriteJsonFile.mockResolvedValue(undefined)
    mockReadTextFile.mockResolvedValue('legacy-verifier')
    mockWriteTextFile.mockResolvedValue(undefined)
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

    it('opens only one browser while an authorization is already pending', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?attempt=one'))

      await expect(provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?attempt=two'))).rejects.toThrow(
        'OAuth authorization is already pending',
      )

      expect(open).toHaveBeenCalledOnce()
    })

    it('does not reopen the browser after exchanging a token until the remote server accepts it', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))
      await provider.saveTokens({
        access_token: 'access-token',
        token_type: 'Bearer',
      })

      await expect(provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))).rejects.toThrow(
        'OAuth token is awaiting remote verification',
      )

      expect(open).toHaveBeenCalledOnce()
    })

    it('does not open a browser when another local process has completed the authorization', async () => {
      const prepareAuthorization = vi.fn().mockResolvedValue({ skipBrowserAuth: true })
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        prepareAuthorization,
      })

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))

      expect(prepareAuthorization).toHaveBeenCalledOnce()
      expect(open).not.toHaveBeenCalled()
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
      expect(mockDeleteConfigFile).toHaveBeenCalledTimes(4)
      expect(mockDeleteConfigFile.mock.calls.map(([, fileName]: [string, string]) => fileName)).toEqual(
        expect.arrayContaining(['client_info.json', 'tokens.json', 'authorization.json', 'code_verifier.txt']),
      )
      expect(open).not.toHaveBeenCalled()
    })

    it('invalidates a fresh dynamic client when authorization reports it is not registered', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.saveClientInformation({
        client_id: 'fresh-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      mockFetch = vi.fn().mockResolvedValue({
        status: 400,
        json: async () => ({
          registration_endpoint: 'https://auth.example.com/register',
          error: 'invalid_request',
          error_description: "Client ID 'fresh-client' is not registered with this server",
        }),
      })
      vi.stubGlobal('fetch', mockFetch)

      await expect(
        provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=fresh-client')),
      ).rejects.toMatchObject({
        name: 'StaleClientRegistrationError',
        message: 'Cached OAuth client registration is no longer valid',
      })

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'client_info.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'code_verifier.txt')
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

    it('preflights a freshly dynamically registered client and opens the browser on redirect', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.saveClientInformation({
        client_id: 'fresh-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      })
      mockFetch = vi.fn().mockResolvedValue({ status: 302 })
      vi.stubGlobal('fetch', mockFetch)

      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize?client_id=fresh-client'))

      expect(mockFetch).toHaveBeenCalledWith(
        'https://auth.example.com/authorize?client_id=fresh-client&scope=openid+email+profile',
        expect.objectContaining({
          redirect: 'manual',
          headers: { Accept: 'application/json' },
          signal: expect.any(AbortSignal),
        }),
      )
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

  describe('PKCE authorization transactions', () => {
    it('creates one state-bound transaction and rejects a concurrent verifier write', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const state = provider.state()

      await provider.saveCodeVerifier('verifier-one')

      expect(mockWriteJsonFile).toHaveBeenCalledWith(
        'test-hash',
        'authorization.json',
        expect.objectContaining({
          version: 1,
          state,
          codeVerifier: 'verifier-one',
          createdAt: expect.any(Number),
        }),
      )
      await expect(provider.saveCodeVerifier('verifier-two')).rejects.toMatchObject({
        name: 'OAuthAuthorizationPendingError',
      })
      expect(mockWriteJsonFile).toHaveBeenCalledTimes(1)
    })

    it('accepts a callback only when its state matches the persisted PKCE transaction', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const state = provider.state()
      mockReadJsonFile.mockResolvedValue({
        version: 1,
        state,
        codeVerifier: 'verifier-one',
        createdAt: Date.now(),
      })

      await expect(provider.acceptAuthorizationCallback('old-state')).rejects.toMatchObject({
        name: 'OAuthCallbackStateError',
      })
      expect(mockReadTextFile).not.toHaveBeenCalled()

      await provider.acceptAuthorizationCallback(state)
      await expect(provider.codeVerifier()).resolves.toBe('verifier-one')
      expect(mockReadTextFile).not.toHaveBeenCalled()
    })

    it('uses a legacy verifier only when no state-bound transaction exists', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      mockReadJsonFile.mockResolvedValue(undefined)

      await expect(provider.codeVerifier()).resolves.toBe('legacy-verifier')
      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', 'code_verifier.txt', 'No code verifier saved for session')
    })

    it('retires an expired transaction when its delayed callback arrives', async () => {
      provider = new NodeOAuthClientProvider({ ...defaultOptions, authTimeoutMs: 20 })
      const state = provider.state()
      mockReadJsonFile.mockResolvedValue({
        version: 1,
        state,
        codeVerifier: 'expired-verifier',
        createdAt: Date.now() - 21,
      })

      await expect(provider.acceptAuthorizationCallback(state)).rejects.toMatchObject({
        name: 'OAuthCallbackStateError',
      })

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'authorization.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'code_verifier.txt')
    })

    it('does not retire a transaction owned by another process when reusing an existing token', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.markRemoteAuthorizationVerified()

      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('resets a failed secondary authorization without deleting the owner credentials', async () => {
      const prepareAuthorization = vi.fn().mockResolvedValue({ skipBrowserAuth: true })
      provider = new NodeOAuthClientProvider({ ...defaultOptions, prepareAuthorization })
      await provider.saveCodeVerifier('secondary-verifier')

      await provider.handleAuthorizationFailure(new Error('Shared OAuth authorization did not complete'))
      await provider.saveCodeVerifier('fresh-verifier')

      expect(prepareAuthorization).toHaveBeenCalledTimes(2)
      expect(mockDeleteConfigFile).not.toHaveBeenCalled()
    })

    it('ignores late tokens from a timed-out authorization exchange', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      const state = provider.state()
      mockReadJsonFile.mockResolvedValue({ version: 1, state, codeVerifier: 'verifier-one', createdAt: Date.now() })
      await provider.acceptAuthorizationCallback(state)

      const lateExchange = provider.runAuthorizationExchange(state, async () => {
        await new Promise((resolve) => setTimeout(resolve, 0))
        await provider.saveTokens({ access_token: 'late-token', token_type: 'Bearer' })
      })
      await provider.invalidateCredentials('tokens')
      await lateExchange

      expect(mockWriteJsonFile).not.toHaveBeenCalledWith('test-hash', 'tokens.json', expect.anything())
    })

    it('retires the authorization transaction when an OAuth token is invalidated', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'tokens.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'authorization.json')
      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'code_verifier.txt')
    })
  })
})
