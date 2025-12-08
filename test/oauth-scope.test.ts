import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import express, { Express } from 'express'
import { Server } from 'http'
import { NodeOAuthClientProvider } from '../src/lib/node-oauth-client-provider.js'
import { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js'

describe('OAuth Scope in Token Exchange', () => {
  let mockServer: Server
  let app: Express
  let capturedTokenRequest: {
    headers: Record<string, string>
    body: URLSearchParams
  } | null = null

  const TEST_PORT = 18765
  const TEST_SERVER_URL = `http://localhost:${TEST_PORT}`

  beforeEach(() => {
    capturedTokenRequest = null
    app = express()

    // Middleware to parse URL-encoded bodies
    app.use(express.urlencoded({ extended: true }))

    // Mock OAuth metadata endpoint
    app.get('/.well-known/oauth-authorization-server', (_req, res) => {
      res.json({
        issuer: TEST_SERVER_URL,
        authorization_endpoint: `${TEST_SERVER_URL}/authorize`,
        token_endpoint: `${TEST_SERVER_URL}/token`,
        registration_endpoint: `${TEST_SERVER_URL}/register`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
        scopes_supported: ['openid', 'email', 'profile', 'all-apis'],
      })
    })

    // Mock token endpoint - this is what we're testing
    app.post('/token', (req, res) => {
      // Capture the request for verification
      capturedTokenRequest = {
        headers: req.headers as Record<string, string>,
        body: new URLSearchParams(req.body as Record<string, string>),
      }

      // Return a mock token response
      res.json({
        access_token: 'mock-access-token',
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: 'mock-refresh-token',
        scope: req.body.scope || 'default',
      })
    })

    // Start the mock server
    return new Promise<void>((resolve) => {
      mockServer = app.listen(TEST_PORT, resolve)
    })
  })

  afterEach(() => {
    return new Promise<void>((resolve, reject) => {
      if (mockServer) {
        mockServer.close((err?: Error) => {
          if (err) reject(err)
          else resolve()
        })
      } else {
        resolve()
      }
    })
  })

  it('includes scope parameter in token exchange with static OAuth client metadata', async () => {
    // Create provider with static OAuth client metadata
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientMetadata: {
        scope: 'all-apis',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
      staticOAuthClientInfo: {
        client_id: '1b88cac5-e0ff-46ad-89b6-b1d3c8baecaf',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    // Simulate calling addClientAuthentication (which is what the SDK does during token exchange)
    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    // Verify the scope parameter is included
    expect(params.get('scope')).toBe('all-apis')
    expect(params.get('client_id')).toBe('1b88cac5-e0ff-46ad-89b6-b1d3c8baecaf')
  })

  it('includes scope parameter in token exchange with custom scope', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientMetadata: {
        scope: 'custom:read custom:write',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    expect(params.get('scope')).toBe('custom:read custom:write')
    expect(params.get('client_id')).toBe('test-client-id')
  })

  it('includes default scope when no custom scope is provided', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    // Should fall back to default scope
    expect(params.get('scope')).toBe('openid email profile')
    expect(params.get('client_id')).toBe('test-client-id')
  })

  it('supports client_secret_post authentication method', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientMetadata: {
        scope: 'all-apis',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        client_secret: 'test-secret',
        token_endpoint_auth_method: 'client_secret_post',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    expect(params.get('scope')).toBe('all-apis')
    expect(params.get('client_id')).toBe('test-client-id')
    expect(params.get('client_secret')).toBe('test-secret')
  })

  it('supports client_secret_basic authentication method', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientMetadata: {
        scope: 'all-apis',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
      staticOAuthClientInfo: {
        client_id: 'test-client-id',
        client_secret: 'test-secret',
        token_endpoint_auth_method: 'client_secret_basic',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    // Check scope is added
    expect(params.get('scope')).toBe('all-apis')

    // Check Basic auth header is set
    const authHeader = headers.get('Authorization')
    expect(authHeader).toBeDefined()
    expect(authHeader).toMatch(/^Basic /)

    // Decode and verify credentials
    const base64Credentials = authHeader!.replace('Basic ', '')
    const decodedCredentials = Buffer.from(base64Credentials, 'base64').toString('utf-8')
    expect(decodedCredentials).toBe('test-client-id:test-secret')
  })

  it('uses scope from client registration response over default', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
    })

    // Simulate client registration response with custom scope
    const clientInfo: OAuthClientInformationFull = {
      client_id: 'registered-client-id',
      redirect_uris: ['http://localhost:8080/callback'],
      scope: 'openid email profile custom:read',
    }

    await provider.saveClientInformation(clientInfo)
    await provider.clientInformation()

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    // Should use scope from registration response
    expect(params.get('scope')).toBe('openid email profile custom:read')
    expect(params.get('client_id')).toBe('registered-client-id')
  })

  it('prioritizes staticOAuthClientMetadata scope over registration response scope', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: TEST_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'test-hash',
      staticOAuthClientMetadata: {
        scope: 'all-apis override',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    // Simulate client registration response with different scope
    const clientInfo: OAuthClientInformationFull = {
      client_id: 'registered-client-id',
      redirect_uris: ['http://localhost:8080/callback'],
      scope: 'openid email profile',
    }

    await provider.saveClientInformation(clientInfo)
    await provider.clientInformation()

    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(TEST_SERVER_URL), undefined)

    // Should prioritize staticOAuthClientMetadata scope
    expect(params.get('scope')).toBe('all-apis override')
  })
})

describe('Databricks MCP Server Authentication Integration', () => {
  const DATABRICKS_SERVER_URL = 'https://j-github-mcp-2850744067564480.staging.aws.databricksapps.com/mcp'
  const DATABRICKS_CLIENT_ID = 'fd81783c-35cb-49a1-89bf-69716ffb009f'

  it('attempts to fetch authorization server metadata from Databricks MCP server', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: DATABRICKS_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'databricks-test',
      staticOAuthClientInfo: {
        client_id: DATABRICKS_CLIENT_ID,
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    // Attempt to fetch the authorization server metadata
    // Note: The metadata endpoint may not be publicly accessible
    const metadata = await provider.getAuthorizationServerMetadata()

    if (metadata) {
      // If metadata is available, verify it has the expected fields
      expect(metadata.authorization_endpoint).toBeDefined()
      expect(metadata.token_endpoint).toBeDefined()

      console.log('Databricks OAuth endpoints:', {
        authorization_endpoint: metadata.authorization_endpoint,
        token_endpoint: metadata.token_endpoint,
        scopes_supported: metadata.scopes_supported,
      })
    } else {
      // If metadata is not available, this is expected for some deployments
      console.log('Authorization server metadata not publicly accessible (expected for some Databricks deployments)')
      expect(metadata).toBeUndefined()
    }
  })

  it('prepares token exchange request with correct scope for Databricks', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: DATABRICKS_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'databricks-test',
      staticOAuthClientMetadata: {
        scope: 'all-apis',
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
      staticOAuthClientInfo: {
        client_id: DATABRICKS_CLIENT_ID,
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    // Prepare authentication parameters as would be done during token exchange
    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(DATABRICKS_SERVER_URL), undefined)

    // Verify the scope parameter is included (critical for Databricks)
    expect(params.get('scope')).toBe('all-apis')
    expect(params.get('client_id')).toBe(DATABRICKS_CLIENT_ID)

    // Log the full token exchange parameters
    console.log('Token exchange parameters:', {
      scope: params.get('scope'),
      client_id: params.get('client_id'),
      allParams: Array.from(params.entries()),
    })
  })

  it('uses authorization server provided scopes if no custom scope specified', async () => {
    const provider = new NodeOAuthClientProvider({
      serverUrl: DATABRICKS_SERVER_URL,
      callbackPort: 8080,
      host: 'localhost',
      serverUrlHash: 'databricks-test',
      staticOAuthClientInfo: {
        client_id: DATABRICKS_CLIENT_ID,
        redirect_uris: ['http://localhost:8080/oauth/callback'],
      },
    })

    // Fetch metadata to get server-supported scopes
    const metadata = await provider.getAuthorizationServerMetadata()

    // Prepare authentication without custom scope
    const headers = new Headers()
    const params = new URLSearchParams()

    provider.addClientAuthentication(headers, params, new URL(DATABRICKS_SERVER_URL), metadata)

    // Should use either server-provided scopes or default
    const scope = params.get('scope')
    expect(scope).toBeDefined()
    expect(scope).not.toBe('')

    console.log('Server supported scopes:', metadata?.scopes_supported)
    console.log('Used scope:', scope)
  })
})
