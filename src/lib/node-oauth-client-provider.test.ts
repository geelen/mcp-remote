import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import { refreshAuthorization } from '@modelcontextprotocol/sdk/client/auth.js'
import { openBrowser } from './open-browser'

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
  // Must mirror the real implementation: the redirect URI registered with the authorization
  // server and the one checked against a cached registration have to match exactly.
  buildRedirectUrl: (host: string, port: number, callbackPath = '/oauth/callback') => `http://${host}:${port}${callbackPath}`,
}))
vi.mock('open', () => ({ default: vi.fn() }))
vi.mock('@modelcontextprotocol/sdk/client/auth.js', async (importOriginal) => ({
  ...(await importOriginal<Record<string, unknown>>()),
  refreshAuthorization: vi.fn(),
}))
vi.mock('./open-browser', () => ({ openBrowser: vi.fn().mockResolvedValue(true) }))

const openBrowserMock = vi.mocked(openBrowser)

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

  // Regression tests for https://github.com/geelen/mcp-remote/issues/235:
  // concurrent mcp-remote processes for the same server used to share a single
  // code_verifier.txt file, so a second process starting mid-flow would silently
  // overwrite the first process's verifier and break its PKCE token exchange.
  describe('PKCE code verifier isolation across processes', () => {
    let mockReadTextFile: any
    let mockWriteTextFile: any

    beforeEach(() => {
      mockReadTextFile = vi.mocked(mcpAuthConfig.readTextFile)
      mockWriteTextFile = vi.mocked(mcpAuthConfig.writeTextFile)
      mockWriteTextFile.mockResolvedValue(undefined)
      mockReadTextFile.mockResolvedValue('test-verifier')
      // No competing instance unless a scenario says so
      vi.mocked(mcpAuthConfig.claimConfigFile).mockResolvedValue(true)
    })

    it('should save the code verifier to a filename scoped to the authorization state', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.saveCodeVerifier('test-verifier')

      expect(mockWriteTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`, 'test-verifier')
      // Two processes for the same server must never target the same filename
      expect(mockWriteTextFile).not.toHaveBeenCalledWith('test-hash', 'code_verifier.txt', 'test-verifier')
    })

    it('should not open a second tab while another instance has one pending', async () => {
      vi.mocked(mcpAuthConfig.claimConfigFile).mockResolvedValue(false)
      vi.mocked(mcpAuthConfig.readJsonFile).mockResolvedValue({ state: 'other-instance-state', timestamp: Date.now() } as any)
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))

      await provider.openPendingAuthorization()

      expect(openBrowserMock).not.toHaveBeenCalled()
    })

    it('should open a tab when the pending one is too old to still be useful', async () => {
      vi.mocked(mcpAuthConfig.claimConfigFile).mockResolvedValue(false)
      const fourMinutesAgo = Date.now() - 4 * 60 * 1000
      vi.mocked(mcpAuthConfig.readJsonFile).mockResolvedValue({ state: 'other-instance-state', timestamp: fourMinutesAgo } as any)
      provider = new NodeOAuthClientProvider(defaultOptions)
      await provider.redirectToAuthorization(new URL('https://auth.example.com/authorize'))

      await provider.openPendingAuthorization()

      expect(openBrowserMock).toHaveBeenCalled()
    })

    it('should read the verifier of the flow the code came from, not its own', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)
      // A tab opened by an instance the host has since killed
      provider.useAuthorizationState('state-from-another-instance')

      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', 'code_verifier_state-from-another-instance.txt', expect.any(String))
      expect(mockReadTextFile).not.toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`, expect.any(String))
    })

    it('should read the code verifier back from the same flow-scoped filename', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`, expect.any(String))
    })

    it('should open exactly one tab when two instances start together', async () => {
      // Both instances find no marker; only the one whose exclusive create wins may open a tab
      vi.mocked(mcpAuthConfig.claimConfigFile).mockResolvedValueOnce(true).mockResolvedValueOnce(false)
      vi.mocked(mcpAuthConfig.readJsonFile).mockResolvedValue({ state: 'winner-state', timestamp: Date.now() } as any)

      for (const _ of [0, 1]) {
        const instance = new NodeOAuthClientProvider(defaultOptions)
        await instance.redirectToAuthorization(new URL('https://auth.example.com/authorize'))
        await instance.openPendingAuthorization()
      }

      expect(openBrowserMock).toHaveBeenCalledTimes(1)
    })

    it('should redeem a code with the client the flow was started with', async () => {
      // The instance that opened the tab listens on 38923; a sibling that could not have that port
      // re-registered and overwrote the shared client_info.json before the code came back
      const openTabFlow = {
        clientInformation: { client_id: 'client-of-the-open-tab', redirect_uris: ['http://localhost:38923/oauth/callback'] },
        redirectUri: 'http://localhost:38923/oauth/callback',
      }
      vi.mocked(mcpAuthConfig.readJsonFile).mockImplementation(async (_hash: any, filename: string) =>
        filename.startsWith('flow_client_') ? openTabFlow : ({ client_id: 'client-a-sibling-registered' } as any),
      )
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.useAuthorizationState('11111111-2222-3333-4444-555555555555')

      // Both halves of the exchange must describe the flow the code belongs to
      await expect(provider.clientInformation()).resolves.toMatchObject({ client_id: 'client-of-the-open-tab' })
      expect(provider.redirectUrl).toBe('http://localhost:38923/oauth/callback')
    })

    it('should fall back to its own client and callback when the code is from its own flow', async () => {
      vi.mocked(mcpAuthConfig.readJsonFile).mockResolvedValue({ client_id: 'client-from-shared-file' } as any)
      provider = new NodeOAuthClientProvider(defaultOptions)

      await expect(provider.clientInformation()).resolves.toMatchObject({ client_id: 'client-from-shared-file' })
      expect(provider.redirectUrl).toBe('http://localhost:8080/oauth/callback')
    })

    it('should ignore an authorization state it could not have issued', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      // A crafted state would otherwise be interpolated straight into a config file path
      provider.useAuthorizationState('../../../../etc/passwd')
      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`, expect.any(String))
      expect(mockReadTextFile).not.toHaveBeenCalledWith('test-hash', expect.stringContaining('..'), expect.any(String))
    })

    it('should sweep verifiers abandoned by instances that lost the flow', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.saveTokens({ access_token: 'token', token_type: 'Bearer' } as any)

      expect(vi.mocked(mcpAuthConfig.deleteStaleConfigFiles)).toHaveBeenCalledWith('test-hash', 'code_verifier_', expect.any(Number))
    })

    it('should delete the flow-scoped verifier file when invalidating the verifier scope', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('verifier')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`)
    })

    it('should delete the flow-scoped verifier file when invalidating all credentials', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${provider.state()}.txt`)
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

    it('should omit scope when authorization server advertises scopes_supported: []', () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      expect(provider.clientMetadata.scope).toBeUndefined()
    })

    it('should omit scope when protected resource advertises scopes_supported: []', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: {
          resource: 'https://example.com',
          scopes_supported: [],
        } as any,
      })

      expect(provider.clientMetadata.scope).toBeUndefined()
    })

    it('should still fall back to defaults when protected resource omits scopes_supported', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        protectedResourceMetadata: {
          resource: 'https://example.com',
        } as any,
      })

      expect(provider.clientMetadata.scope).toBe('openid email profile')
    })

    it('should omit scope query param when scopes_supported is []', async () => {
      const metadata: AuthorizationServerMetadata = {
        issuer: 'https://example.com',
        scopes_supported: [],
      }

      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        authorizationServerMetadata: metadata,
      })

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.has('scope')).toBe(false)
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

// The SDK feeds a single `resource` value into the authorization, token and refresh
// requests via selectResourceURL(). These tests pin that value, because RFC 8707 §2.2
// requires the token request to carry the same resource that was authorized.
describe('NodeOAuthClientProvider - RFC 8707 resource indicator', () => {
  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://mcp.example.com/mcp',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }
  const prm: any = { resource: 'https://mcp.example.com' }
  const defaultResource = new URL('https://mcp.example.com/mcp')

  it('defers to the SDK default when no resource options are given', () => {
    const provider = new NodeOAuthClientProvider(defaultOptions)
    // Left undefined so selectResourceURL applies its Protected Resource Metadata logic
    expect(provider.validateResourceURL).toBeUndefined()
  })

  it('sends the user-supplied --resource to token requests too, not just authorize', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, authorizeResource: 'https://tenant1.example.com/' })
    const resolved = await provider.validateResourceURL!(defaultResource, prm.resource)
    // Previously this resolved to the PRM resource, so the authorize request said tenant1
    // while the token request said mcp.example.com and the server could reject the exchange.
    expect(String(resolved)).toBe('https://tenant1.example.com/')
  })

  it('omits the resource entirely when disabled', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, skipResourceParameter: true })
    expect(await provider.validateResourceURL!(defaultResource, prm.resource)).toBeUndefined()
  })

  it('lets the disable flag win over an explicit resource', async () => {
    const provider = new NodeOAuthClientProvider({
      ...defaultOptions,
      authorizeResource: 'https://tenant1.example.com/',
      skipResourceParameter: true,
    })
    expect(await provider.validateResourceURL!(defaultResource, prm.resource)).toBeUndefined()
  })

  it('no longer rewrites the resource on the authorization URL after the fact', async () => {
    const provider = new NodeOAuthClientProvider({ ...defaultOptions, authorizeResource: 'https://tenant1.example.com/' })
    const authUrl = new URL('https://auth.example.com/authorize')
    await provider.redirectToAuthorization(authUrl)
    // The SDK sets `resource` from validateResourceURL before we ever see the URL, so the
    // provider must not touch it - that post-hoc rewrite was the source of the mismatch.
    expect(authUrl.searchParams.has('resource')).toBe(false)
  })
})

describe('NodeOAuthClientProvider - proactive token refresh', () => {
  const options: OAuthProviderOptions = {
    serverUrl: 'https://example.com/mcp',
    callbackPort: 8080,
    host: 'localhost',
    serverUrlHash: 'test-hash',
  }

  const storedTokens = (overrides: Record<string, unknown> = {}) => ({
    access_token: 'stale-token',
    refresh_token: 'r1',
    token_type: 'Bearer',
    expires_in: 3600,
    ...overrides,
  })

  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockRefresh: any

  beforeEach(() => {
    mockReadJsonFile = vi.mocked(mcpAuthConfig.readJsonFile)
    mockWriteJsonFile = vi.mocked(mcpAuthConfig.writeJsonFile)
    mockRefresh = vi.mocked(refreshAuthorization)
    mockWriteJsonFile.mockResolvedValue(undefined)
    vi.mocked(mcpAuthConfig.deleteConfigFile).mockResolvedValue(undefined)

    // Any client_info read hands back a registered client; tokens.json is per-test
    mockReadJsonFile.mockImplementation(async (_hash: string, file: string) =>
      file === 'client_info.json' ? { client_id: 'c1', client_secret: 's1', redirect_uris: [] } : undefined,
    )
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  const withStoredTokens = (tokens: Record<string, unknown>) =>
    mockReadJsonFile.mockImplementation(async (_hash: string, file: string) =>
      file === 'client_info.json' ? { client_id: 'c1', client_secret: 's1', redirect_uris: [] } : tokens,
    )

  it('Scenario: an absolute expiry is persisted alongside the token', async () => {
    const provider = new NodeOAuthClientProvider(options)
    const before = Date.now()

    await provider.saveTokens({ access_token: 'a', refresh_token: 'r', token_type: 'Bearer', expires_in: 3600 } as any)

    const [, file, written] = mockWriteJsonFile.mock.calls[0]
    expect(file).toBe('tokens.json')
    // expires_in alone is meaningless once on disk; the absolute time is what a
    // later process can actually compare against
    expect(written.expires_at).toBeGreaterThanOrEqual(before + 3600 * 1000)
  })

  it('Scenario: a token that is still valid is returned untouched', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() + 10 * 60 * 1000 }))
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    expect(result?.access_token).toBe('stale-token')
    expect(mockRefresh).not.toHaveBeenCalled()
  })

  it('Scenario: an expired token is refreshed before it is ever sent', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockResolvedValue({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 })
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    // Renewed up front, rather than after the server rejects the stale token -
    // a server that answers expiry with 400 or 403 never reaches the SDK's 401 path
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(mockRefresh.mock.calls[0][1].refreshToken).toBe('r1')
    expect(result?.access_token).toBe('fresh-token')
  })

  it('Scenario: concurrent requests share a single refresh', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockImplementation(
      async () =>
        new Promise((resolve) =>
          setTimeout(() => resolve({ access_token: 'fresh-token', refresh_token: 'r2', token_type: 'Bearer', expires_in: 3600 }), 10),
        ),
    )
    const provider = new NodeOAuthClientProvider(options)

    const results = await Promise.all([provider.tokens(), provider.tokens(), provider.tokens()])

    // tokens() runs on every outgoing request. With refresh token rotation a
    // second parallel use of the same token can invalidate the whole chain.
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(results.map((r) => r?.access_token)).toEqual(['fresh-token', 'fresh-token', 'fresh-token'])
  })

  it('Scenario: a failed refresh falls back to the stored token', async () => {
    withStoredTokens(storedTokens({ expires_at: Date.now() - 1000 }))
    mockRefresh.mockRejectedValue(new Error('authorization server unreachable'))
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    // The SDK's own 401 handling is still there to catch this; never hand back
    // a blank access token, which some servers reject as a malformed request
    expect(result?.access_token).toBe('stale-token')
  })

  it('Scenario: an expired token with no refresh token is left alone', async () => {
    withStoredTokens({ access_token: 'stale-token', token_type: 'Bearer', expires_in: 3600, expires_at: Date.now() - 1000 })
    const provider = new NodeOAuthClientProvider(options)

    const result = await provider.tokens()

    expect(mockRefresh).not.toHaveBeenCalled()
    expect(result?.access_token).toBe('stale-token')
  })
})
