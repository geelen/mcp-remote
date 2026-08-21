import { describe, it, expect, vi, beforeEach } from 'vitest'

// Shared state for the mocked SDK transports/clients. `vi.hoisted` lets the `vi.mock`
// factories (which are hoisted above imports) reference this safely.
const mockState = vi.hoisted(() => ({
  // Every StreamableHTTPClientTransport constructed, in order.
  httpTransports: [] as Array<{ start: ReturnType<typeof vi.fn>; finishAuth: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> }>,
  // Number of remaining `Client.connect` calls that should fail with an auth error.
  connectFailuresRemaining: 1,
}))

vi.mock('@modelcontextprotocol/sdk/client/streamableHttp.js', () => {
  class StreamableHTTPError extends Error {
    code?: number
    constructor(message: string, code?: number) {
      super(message)
      this.code = code
    }
  }
  class StreamableHTTPClientTransport {
    start = vi.fn().mockResolvedValue(undefined)
    finishAuth = vi.fn().mockResolvedValue(undefined)
    close = vi.fn().mockResolvedValue(undefined)
    constructor(
      public url: URL,
      public opts: unknown,
    ) {
      mockState.httpTransports.push(this)
    }
  }
  return { StreamableHTTPClientTransport, StreamableHTTPError }
})

vi.mock('@modelcontextprotocol/sdk/client/sse.js', () => {
  class SSEClientTransport {
    start = vi.fn().mockResolvedValue(undefined)
    finishAuth = vi.fn().mockResolvedValue(undefined)
    close = vi.fn().mockResolvedValue(undefined)
    constructor(
      public url: URL,
      public opts: unknown,
    ) {}
  }
  return { SSEClientTransport }
})

vi.mock('@modelcontextprotocol/sdk/client/index.js', () => {
  class Client {
    constructor(
      public info: unknown,
      public caps: unknown,
    ) {}
    async connect() {
      // The one-off "fallback test" client is what actually probes the server. Simulate the
      // server answering that probe with a 401, so the *test* transport is the one that receives
      // (and stores) the challenge — exactly as happens in real proxy mode.
      if (mockState.connectFailuresRemaining > 0) {
        mockState.connectFailuresRemaining--
        throw new Error('Unauthorized')
      }
    }
  }
  return { Client }
})

// Import after mocks are registered.
import { connectToRemoteServer } from './utils'

describe('connectToRemoteServer', () => {
  beforeEach(() => {
    mockState.httpTransports.length = 0
    mockState.connectFailuresRemaining = 1
    // Keep test output quiet; connectToRemoteServer logs to stderr.
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('completes auth on the transport that received the 401 challenge in proxy mode (regression: #270)', async () => {
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => 'auth-code-123',
      skipBrowserAuth: false,
    })

    // Proxy mode passes `client = null`. This branch reuses the *same* transport for the
    // capability probe rather than building a throwaway one, so the 401 - and the
    // resource_metadata URL the SDK stores from it - lands on the transport we finish auth on.
    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    expect(mockState.httpTransports.length).toBeGreaterThanOrEqual(1)
    const [challengeTransport] = mockState.httpTransports

    // The invariant behind #270: finishAuth must run on whichever transport handled the
    // challenge, so the stored resource_metadata URL drives token_endpoint discovery.
    expect(challengeTransport.finishAuth).toHaveBeenCalledTimes(1)
    expect(challengeTransport.finishAuth).toHaveBeenCalledWith('auth-code-123')
  })

  it('completes auth on the main transport in with-client mode (parity with the working standalone client path)', async () => {
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => 'auth-code-456',
      skipBrowserAuth: false,
    })

    // The standalone `mcp-remote-client` binary passes a real Client, so `client.connect(transport)`
    // sends the request through the *main* transport, which receives the 401 itself. This path
    // already works (per #270); this test guards against regressing it. The first connect attempt
    // fails with an auth error (the 401), the retry after auth succeeds.
    let clientConnectCalls = 0
    const client = {
      connect: async () => {
        if (clientConnectCalls++ === 0) throw new Error('Unauthorized')
      },
    } as any

    await connectToRemoteServer(client, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // No throwaway test transport is created in with-client mode, so the first (and only auth-time)
    // transport is the main one, and finishAuth must run on it.
    const [mainTransport] = mockState.httpTransports
    expect(mainTransport.finishAuth).toHaveBeenCalledTimes(1)
    expect(mainTransport.finishAuth).toHaveBeenCalledWith('auth-code-456')
  })
})
