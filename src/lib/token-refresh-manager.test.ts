import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest'

const mockTokenStore = new Map<string, any>()
const mockTokenStates = new Map<string, any>()
const mockRegistrations = new Map<string, any>()
const mockLocks = new Map<string, number>()
let currentTime = 1_700_000_000_000

vi.mock('./mcp-auth-config', () => {
  return {
    listServerHashesWithTokens: vi.fn(async () => Array.from(mockTokenStore.keys())),
    readServerRegistration: vi.fn(async (hash: string) => mockRegistrations.get(hash)),
    saveServerRegistration: vi.fn(async (hash: string, registration: any) => {
      mockRegistrations.set(hash, registration)
    }),
    readTokenState: vi.fn(async (hash: string) => mockTokenStates.get(hash)),
    writeTokenState: vi.fn(async (hash: string, state: any) => {
      const existing = mockTokenStates.get(hash) ?? {}
      mockTokenStates.set(hash, { ...existing, ...state })
    }),
    tryAcquireRefreshLock: vi.fn(async (hash: string, ttlMs: number) => {
      const now = Date.now()
      const lockUntil = mockLocks.get(hash)
      if (lockUntil && lockUntil > now) {
        return false
      }
      mockLocks.set(hash, now + ttlMs)
      return true
    }),
    releaseRefreshLock: vi.fn(async (hash: string) => {
      mockLocks.delete(hash)
    }),
  }
})

vi.mock('./node-oauth-client-provider', () => {
  class MockNodeOAuthClientProvider {
    private readonly serverUrlHash: string

    constructor(options: any) {
      this.serverUrlHash = options.serverUrlHash
    }

    async clientInformation() {
      return {
        client_id: 'test-client',
        redirect_uris: ['http://127.0.0.1:3335/oauth/callback'],
        token_endpoint_auth_method: 'none',
      }
    }

    async tokens() {
      return mockTokenStore.get(this.serverUrlHash)
    }

    async saveTokens(tokens: any) {
      mockTokenStore.set(this.serverUrlHash, tokens)
    }

    get addClientAuthentication() {
      return undefined
    }
  }

  return { NodeOAuthClientProvider: MockNodeOAuthClientProvider }
})

const clientMocks = vi.hoisted(() => {
  const refreshAuthorization = vi.fn(async (_url: string | URL, { refreshToken }: { refreshToken: string }) => ({
    access_token: `new-token-for-${refreshToken}`,
    refresh_token: refreshToken,
    token_type: 'Bearer',
    expires_in: 3600,
  }))
  const discoverAuthorizationServerMetadata = vi.fn(async () => ({ token_endpoint: 'https://auth.example/token' }))
  const discoverOAuthProtectedResourceMetadata = vi.fn(async () => ({
    authorization_servers: ['https://auth.example'],
    resource: 'https://resource.example',
  }))
  const selectResourceURL = vi.fn(async () => new URL('https://resource.example'))

  return {
    refreshAuthorization,
    discoverAuthorizationServerMetadata,
    discoverOAuthProtectedResourceMetadata,
    selectResourceURL,
  }
})

vi.mock('@modelcontextprotocol/sdk/client/auth.js', () => clientMocks)
const {
  refreshAuthorization,
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
  selectResourceURL,
} = clientMocks

const errorMocks = vi.hoisted(() => {
  class MockOAuthError extends Error {
    constructor(message?: string, public errorCode?: string) {
      super(message)
      this.name = 'OAuthError'
    }
  }

  return { MockOAuthError }
})

vi.mock('@modelcontextprotocol/sdk/server/auth/errors.js', () => ({
  OAuthError: errorMocks.MockOAuthError,
}))

vi.mock('./utils', async () => {
  const originalModule = await vi.importActual<typeof import('./utils')>('./utils')
  return originalModule
})

import { TokenRefreshManager, isTokenExpiringSoon } from './token-refresh-manager'

const dateNowSpy = vi.spyOn(Date, 'now').mockImplementation(() => currentTime)

function seedServer(serverHash: string, { token, state }: { token: any; state: any }) {
  mockRegistrations.set(serverHash, {
    serverUrl: 'https://remote.example/sse',
    host: 'localhost',
  })
  mockTokenStore.set(serverHash, token)
  mockTokenStates.set(serverHash, state)
}

describe('Feature: Token Expiration Helper', () => {
  it('Scenario: Returns false when no token state exists', () => {
    expect(isTokenExpiringSoon(undefined, 600_000, currentTime)).toBe(false)
  })

  it('Scenario: Returns true when token already expired', () => {
    const state = { issuedAt: currentTime - 10_000, expiresAt: currentTime - 1000 }
    expect(isTokenExpiringSoon(state, 600_000, currentTime)).toBe(true)
  })

  it('Scenario: Returns true when token expires within lead window', () => {
    const state = { issuedAt: currentTime - 1000, expiresAt: currentTime + 30_000 }
    expect(isTokenExpiringSoon(state, 60_000, currentTime)).toBe(true)
  })

  it('Scenario: Returns false when token expires beyond lead window', () => {
    const state = { issuedAt: currentTime - 1000, expiresAt: currentTime + 120_000 }
    expect(isTokenExpiringSoon(state, 60_000, currentTime)).toBe(false)
  })
})

describe('Feature: Token Refresh Manager', () => {
  beforeEach(() => {
    mockTokenStore.clear()
    mockTokenStates.clear()
    mockRegistrations.clear()
    mockLocks.clear()
    refreshAuthorization.mockClear()
    discoverAuthorizationServerMetadata.mockClear()
    discoverOAuthProtectedResourceMetadata.mockClear()
    selectResourceURL.mockClear()
    currentTime = 1_700_000_000_000
  })

  afterAll(() => {
    dateNowSpy.mockRestore()
  })

  it('Scenario: Refreshes tokens when they are expiring soon', async () => {
    const serverHash = 'hash-success'
    seedServer(serverHash, {
      token: { access_token: 'old', refresh_token: 'refresh-1', token_type: 'Bearer', expires_in: 30 },
      state: { issuedAt: currentTime - 1000, expiresAt: currentTime + 30_000 },
    })

    const manager = new TokenRefreshManager({ enabled: true, leadTimeMs: 60_000 })
    await (manager as any).refreshIfNeeded(serverHash)

    expect(refreshAuthorization).toHaveBeenCalledTimes(1)
    expect(mockTokenStore.get(serverHash)?.access_token).toBe('new-token-for-refresh-1')
    expect(mockTokenStates.get(serverHash)?.lastRefreshAttempt).toBe(currentTime)
    expect(mockTokenStates.get(serverHash)?.lastRefreshError).toBeUndefined()
    expect(mockLocks.size).toBe(0)
  })

  it('Scenario: Skips refresh when another process holds the lock', async () => {
    const serverHash = 'hash-lock'
    seedServer(serverHash, {
      token: { access_token: 'old', refresh_token: 'refresh-lock', token_type: 'Bearer', expires_in: 30 },
      state: { issuedAt: currentTime - 1000, expiresAt: currentTime + 10_000 },
    })
    mockLocks.set(serverHash, currentTime + 60_000)

    const manager = new TokenRefreshManager({ enabled: true, leadTimeMs: 60_000 })
    await (manager as any).refreshIfNeeded(serverHash)

    expect(refreshAuthorization).not.toHaveBeenCalled()
    expect(mockLocks.get(serverHash)).toBe(currentTime + 60_000)
  })

  it('Scenario: Backs off and retries after a failed refresh attempt', async () => {
    const serverHash = 'hash-backoff'
    seedServer(serverHash, {
      token: { access_token: 'old', refresh_token: 'refresh-backoff', token_type: 'Bearer', expires_in: 30 },
      state: { issuedAt: currentTime - 1000, expiresAt: currentTime + 10_000 },
    })

    const manager = new TokenRefreshManager({ enabled: true, leadTimeMs: 60_000, failureBackoffMs: 60_000 })

    refreshAuthorization.mockRejectedValueOnce(new Error('refresh failed'))

    await (manager as any).refreshIfNeeded(serverHash)

    expect(mockTokenStates.get(serverHash)?.lastRefreshError).toBe('refresh failed')
    expect(refreshAuthorization).toHaveBeenCalledTimes(1)

    await (manager as any).refreshIfNeeded(serverHash)
    expect(refreshAuthorization).toHaveBeenCalledTimes(1)

    currentTime += 120_000
    await (manager as any).refreshIfNeeded(serverHash)
    expect(refreshAuthorization).toHaveBeenCalledTimes(2)
    expect(mockTokenStore.get(serverHash)?.access_token).toBe('new-token-for-refresh-backoff')
    expect(mockTokenStates.get(serverHash)?.lastRefreshError).toBeUndefined()
  })
})
