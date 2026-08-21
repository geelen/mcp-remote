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
  // Must mirror the real implementation: the redirect URI registered with the authorization
  // server and the one checked against a cached registration have to match exactly.
  buildRedirectUrl: (host: string, port: number, callbackPath = '/oauth/callback') => `http://${host}:${port}${callbackPath}`,
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
    })

    it('should save the code verifier to a filename scoped to the current process ID', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.saveCodeVerifier('test-verifier')

      expect(mockWriteTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${process.pid}.txt`, 'test-verifier')
      // Two processes for the same server must never target the same filename
      expect(mockWriteTextFile).not.toHaveBeenCalledWith('test-hash', 'code_verifier.txt', 'test-verifier')
    })

    it('should read the code verifier back from the same process-scoped filename', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.codeVerifier()

      expect(mockReadTextFile).toHaveBeenCalledWith('test-hash', `code_verifier_${process.pid}.txt`, expect.any(String))
    })

    it('should delete the process-scoped verifier file when invalidating the verifier scope', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('verifier')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${process.pid}.txt`)
    })

    it('should delete the process-scoped verifier file when invalidating all credentials', async () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', `code_verifier_${process.pid}.txt`)
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
