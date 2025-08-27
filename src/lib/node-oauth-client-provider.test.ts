import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import * as mcpAuthConfig from './mcp-auth-config'
import type { OAuthProviderOptions } from './types'

vi.mock('./mcp-auth-config')
vi.mock('./utils', () => ({
  getServerUrlHash: () => 'test-hash',
  log: vi.fn(),
  debugLog: vi.fn(),
  DEBUG: false,
  MCP_REMOTE_VERSION: '1.0.0',
}))
vi.mock('open', () => ({ default: vi.fn() }))

describe('NodeOAuthClientProvider', () => {
  let provider: NodeOAuthClientProvider
  let mockReadJsonFile: any
  let mockWriteJsonFile: any
  let mockDeleteConfigFile: any

  const defaultOptions: OAuthProviderOptions = {
    serverUrl: 'https://example.com',
    callbackPort: 8080,
    host: 'localhost',
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

  describe('custom scopes preservation', () => {
    it('should use custom scope from staticOAuthClientMetadata', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom read write',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom read write')
    })

    it('should prioritize custom scope over default scopes', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'user:email repo',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('user:email repo')
    })

    it('should use default scopes when no custom scope provided', () => {
      provider = new NodeOAuthClientProvider(defaultOptions)

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('openid email profile')
    })

    it('should include scope in authorization URL with custom scope', async () => {
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
  })

  describe('extracted scopes from registration', () => {
    beforeEach(() => {
      provider = new NodeOAuthClientProvider(defaultOptions)
    })

    it('should extract scope from registration response', async () => {
      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'extracted custom scopes',
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'scopes.json', {
        scopes: 'extracted custom scopes',
      })
    })

    it('should extract default_scope from registration response', async () => {
      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        default_scope: 'default extracted scopes',
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'scopes.json', {
        scopes: 'default extracted scopes',
      })
    })

    it('should extract scopes array from registration response', async () => {
      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scopes: ['scope1', 'scope2', 'scope3'],
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'scopes.json', {
        scopes: 'scope1 scope2 scope3',
      })
    })

    it('should extract default_scopes array from registration response', async () => {
      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        default_scopes: ['default1', 'default2'],
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'scopes.json', {
        scopes: 'default1 default2',
      })
    })

    it('should fallback to default when no scopes in registration', async () => {
      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).toHaveBeenCalledWith('test-hash', 'scopes.json', {
        scopes: 'openid email profile',
      })
    })

    it('should load extracted scopes and use in clientMetadata', async () => {
      mockReadJsonFile.mockResolvedValueOnce({ client_id: 'test-client' }).mockResolvedValueOnce({ scopes: 'loaded extracted scopes' })

      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('loaded extracted scopes')
    })

    it('should include extracted scopes in authorization URL', async () => {
      mockReadJsonFile.mockResolvedValueOnce({ client_id: 'test-client' }).mockResolvedValueOnce({ scopes: 'loaded scopes for auth' })

      await provider.clientInformation()

      const authUrl = new URL('https://auth.example.com/authorize')
      await provider.redirectToAuthorization(authUrl)

      expect(authUrl.searchParams.get('scope')).toBe('loaded scopes for auth')
    })
  })

  describe('scope priority and behavior', () => {
    it('should NOT extract scopes when custom scope is provided', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom priority scope',
        } as any,
      })

      const clientInfo = {
        client_id: 'test-client',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
        scope: 'registration scope should be ignored',
      }

      await provider.saveClientInformation(clientInfo)

      expect(mockWriteJsonFile).not.toHaveBeenCalledWith('test-hash', 'scopes.json', expect.anything())
    })

    it('should NOT load stored scopes when custom scope is provided', async () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom override scope',
        } as any,
      })

      mockReadJsonFile.mockResolvedValueOnce({ client_id: 'test-client' })

      await provider.clientInformation()

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom override scope')
    })

    it('should respect staticOAuthClientMetadata spreading with custom scope', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'custom scope',
          client_name: 'Custom Client Name',
          some_other_field: 'custom value',
        } as any,
      })

      const metadata = provider.clientMetadata
      expect(metadata.scope).toBe('custom scope')
      expect(metadata.client_name).toBe('Custom Client Name')
      expect((metadata as any).some_other_field).toBe('custom value')
    })
  })

  describe('credential invalidation', () => {
    beforeEach(() => {
      provider = new NodeOAuthClientProvider(defaultOptions)
    })

    it('should clean up scopes file when invalidating all credentials', async () => {
      await provider.invalidateCredentials('all')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'scopes.json')
    })

    it('should clean up scopes file when invalidating client credentials', async () => {
      await provider.invalidateCredentials('client')

      expect(mockDeleteConfigFile).toHaveBeenCalledWith('test-hash', 'scopes.json')
    })

    it('should not clean up scopes file when invalidating only tokens', async () => {
      await provider.invalidateCredentials('tokens')

      expect(mockDeleteConfigFile).not.toHaveBeenCalledWith('test-hash', 'scopes.json')
    })

    it('should reset to default scopes after client invalidation', async () => {
      mockReadJsonFile.mockResolvedValueOnce({ client_id: 'test-client' }).mockResolvedValueOnce({ scopes: 'extracted scopes' })

      await provider.clientInformation()
      expect(provider.clientMetadata.scope).toBe('extracted scopes')

      await provider.invalidateCredentials('client')

      expect(provider.clientMetadata.scope).toBe('openid email profile')
    })
  })

  describe('backward compatibility', () => {
    it('should work exactly like before when using staticOAuthClientMetadata.scope', () => {
      provider = new NodeOAuthClientProvider({
        ...defaultOptions,
        staticOAuthClientMetadata: {
          scope: 'existing custom scope',
          client_name: 'My Custom Client',
        } as any,
      })

      const metadata = provider.clientMetadata

      expect(metadata).toMatchObject({
        scope: 'existing custom scope',
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
})
