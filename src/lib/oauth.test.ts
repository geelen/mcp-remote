import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { connectToRemoteServer, REASON_AUTH_NEEDED } from './utils'
import { NodeOAuthClientProvider } from './node-oauth-client-provider'
import type { OAuthProviderOptions } from './types'
import express from 'express'
import { Server } from 'http'

describe('OAuth Authorization', () => {
  let mcpServer: MockServer
  let idpServer: MockServer

  beforeEach(async () => {
    mcpServer = new MockServer()
    await mcpServer.start()

    idpServer = new MockServer()
    await idpServer.start()
  })

  afterEach(async () => {
    await mcpServer.stop()
    await idpServer.stop()
  })

  it('uses the protected resource metadata URL from the WWW-Authenticate response header to find authorization server', async () => {
    // Setup mocked mcp server
    const mcpServerUrl = mcpServer.url('/test/mcp')
    mcpServer.addRoute('POST', '/test/mcp', (req, res) => {
      res.status(401)// Since we are testing only the login flow, we ignore the post-auth stuff.
        .header('WWW-Authenticate', `Bearer realm="mcp", resource_metadata="${mcpServer.url('/test/mcp/.well-known/oauth-protected-resource')}"`)
        .json({ error: 'Unauthorized' })
    })
    mcpServer.addRoute('GET', '/test/mcp/.well-known/oauth-protected-resource', (req, res) => {
      res.json({
        resource: mcpServer.url('/test/mcp'),
        authorization_servers: [idpServer.url('/test/auth')]
      })
    });

    // Setup mocked idp server
    idpServer.addRoute('GET', '/test/auth/.well-known/openid-configuration', (req, res) => {
      res.json({
        issuer: idpServer.url('/test/auth'),
        authorization_endpoint: idpServer.url('/test/auth/authorize'),
        token_endpoint: idpServer.url('/test/auth/token'),
        jwks_uri: idpServer.url('/test/auth/jwks'),
        response_types_supported: ['code', 'token', 'id_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['plain', 'S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'none'],
        scopes_supported: ['openid', 'profile', 'email'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email'],
      })
    });
    idpServer.addRoute('POST', '/test/auth/token', (req, res) => {
      res.json({
        "access_token": "abc123def456ghi789",
        "token_type": "Bearer"
      })
    });

    // Setup OAuth client
    const authProvider = new NodeOAuthClientProvider(<OAuthProviderOptions>{
      serverUrl: mcpServerUrl,
      callbackPort: 0,
      host: 'localhost',
      callbackPath: '/oauth/callback',
      staticOAuthClientInfo: {
        client_id: 'mock-client-id',
        client_name: 'Mock Client',
        redirect_uris: ['http://localhost/callback'],
        token_endpoint_auth_method: 'none',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code']
      }
    })

    // Mock auth code acquisition
    vi.spyOn(authProvider, 'redirectToAuthorization').mockImplementation(() => Promise.resolve())
    const mockAuthInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: vi.fn().mockResolvedValue('mocked-auth-code'),
      skipBrowserAuth: false,
    })

    // Initiate login flow
    try {
      const transport = await connectToRemoteServer(
        null,
        mcpServerUrl,
        authProvider,
        {},
        mockAuthInitializer,
        'http-first', 
        new Set([REASON_AUTH_NEEDED])/*dont do the recursion thing, because we want to stop after the first auth attempt*/
      )
    } catch (e: Error | any) {
      // Since we only do one run and skip the recursion, we expect it to give up early.
      expect(e).toBeInstanceOf(Error);
      expect(e.message).contains("Giving up.");
    }
    
    // Verify we successfully acquired the accesstoken
    const tokens = await authProvider.tokens();
    expect(tokens?.access_token).toBe('abc123def456ghi789')
  })
})

// Test utility for controlling fetch responses.
class MockServer {
  private app: express.Application
  private server: Server | null = null
  private port: number = 0
  public baseUrl: string = ''

  constructor() {
    this.app = express()
    this.app.use(express.json())
  }

  addRoute(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, handler: express.RequestHandler) {
    this.app[method.toLowerCase() as 'get' | 'post' | 'put' | 'delete'](path, handler)
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = this.app.listen(0, 'localhost', () => {
        if (this.server) {
          const address = this.server.address()
          if (address && typeof address === 'object') {
            this.port = address.port
            this.baseUrl = `http://localhost:${this.port}`
            resolve()
          } else {
            reject(new Error('Failed to get server address'))
          }
        } else {
          reject(new Error('Server failed to start'))
        }
      })
      
      this.server.on('error', reject)
    })
  }

  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) {
            reject(err)
          } else {
            this.server = null
            resolve()
          }
        })
      } else {
        resolve()
      }
    })
  }

  url(path: string): string {
    return `${this.baseUrl}${path}`
  }
}

describe('Test Infrastructure: Mock Server', () => {
  let mockServer: MockServer

  beforeEach(async () => {
    mockServer = new MockServer()
    await mockServer.start()
  })

  afterEach(async () => {
    await mockServer.stop()
  })

  it('responds with custom data', async () => {
    // Given a mock server with a custom route
    mockServer.addRoute('GET', '/test', (req, res) => {
      res.json({ message: 'Hello from mock server!' })
    })

    // When making a fetch request to the mock server
    const response = await fetch(mockServer.url('/test'))
    const data = await response.json()

    // Then the mock server should respond with the expected data
    expect(data).toEqual({ message: 'Hello from mock server!' })
    expect(response.status).toBe(200)
  })

  it('handles POST requests', async () => {
    // Given a mock server with an echo endpoint
    mockServer.addRoute('POST', '/echo', (req, res) => {
      res.json({ 
        received: req.body,
        headers: req.headers,
        method: req.method 
      })
    })

    // When posting data to the mock server
    const testData = { test: 'data', number: 42 }
    const response = await fetch(mockServer.url('/echo'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testData)
    })
    const responseData = await response.json()

    // Then the server should echo back the data
    expect(responseData.received).toEqual(testData)
    expect(responseData.method).toBe('POST')
    expect(responseData.headers['content-type']).toBe('application/json')
  })

  it('can simulate different HTTP status codes', async () => {
    // Given a mock server that returns different status codes
    mockServer.addRoute('GET', '/success', (req, res) => {
      res.status(200).json({ status: 'ok' })
    })

    mockServer.addRoute('GET', '/error', (req, res) => {
      res.status(500).json({ error: 'Internal Server Error' })
    })

    mockServer.addRoute('GET', '/not-found', (req, res) => {
      res.status(404).json({ error: 'Not Found' })
    })

    // When making requests to different endpoints
    const successResponse = await fetch(mockServer.url('/success'))
    const errorResponse = await fetch(mockServer.url('/error'))
    const notFoundResponse = await fetch(mockServer.url('/not-found'))

    // Then the appropriate status codes should be returned
    expect(successResponse.status).toBe(200)
    expect(errorResponse.status).toBe(500)
    expect(notFoundResponse.status).toBe(404)
  })

  it('can simulate authentication flow', async () => {
    // Given a mock server that checks for authentication
    mockServer.addRoute('GET', '/protected', (req, res) => {
      const authHeader = req.headers.authorization
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({ error: 'Unauthorized' })
        return
      }
      
      const token = authHeader.substring(7) // Remove 'Bearer ' prefix
      
      if (token === 'valid-token') {
        res.json({ message: 'Access granted', user: 'test-user' })
      } else {
        res.status(401).json({ error: 'Invalid token' })
      }
    })

    // When making a request without authentication
    const unauthResponse = await fetch(mockServer.url('/protected'))
    expect(unauthResponse.status).toBe(401)

    // When making a request with invalid token
    const invalidTokenResponse = await fetch(mockServer.url('/protected'), {
      headers: { Authorization: 'Bearer invalid-token' }
    })
    expect(invalidTokenResponse.status).toBe(401)

    // When making a request with valid token
    const validTokenResponse = await fetch(mockServer.url('/protected'), {
      headers: { Authorization: 'Bearer valid-token' }
    })
    expect(validTokenResponse.status).toBe(200)
    
    const data = await validTokenResponse.json()
    expect(data).toEqual({ message: 'Access granted', user: 'test-user' })
  })
})
