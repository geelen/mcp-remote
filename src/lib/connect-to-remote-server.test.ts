import { describe, it, expect, vi, beforeEach } from 'vitest'

// Shared state for the mocked SDK transports/clients. `vi.hoisted` lets the `vi.mock`
// factories (which are hoisted above imports) reference this safely.
const mockState = vi.hoisted(() => ({
  // Every StreamableHTTPClientTransport constructed, in order.
  httpTransports: [] as Array<{ start: ReturnType<typeof vi.fn>; finishAuth: ReturnType<typeof vi.fn>; close: ReturnType<typeof vi.fn> }>,
  // Number of remaining `Client.connect` calls that should fail with an auth error.
  connectFailuresRemaining: 1,
  // Every authorization code handed to `finishAuth`, in order.
  finishAuthCalls: [] as string[],
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
    finishAuth = vi.fn(async (code: string) => {
      mockState.finishAuthCalls.push(code)
    })
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
    mockState.finishAuthCalls.length = 0
    mockState.connectFailuresRemaining = 1
    // Keep test output quiet; connectToRemoteServer logs to stderr.
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('completes auth on the transport that received the 401 challenge in proxy mode (regression: #270)', async () => {
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => 'auth-code-123',
      skipBrowserAuth: false,
    })

    // Proxy mode passes `client = null`, which drives the throwaway test-transport probe path.
    await connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')

    // Instances, in construction order:
    //   [0] first attempt's main transport   (never sees the 401)
    //   [1] first attempt's test transport    (receives the 401 -> stores resource_metadata)
    //   [2] second attempt's main transport   (connects successfully after auth)
    //   [3] second attempt's test transport
    const [mainTransport, testTransport] = mockState.httpTransports
    expect(mockState.httpTransports.length).toBeGreaterThanOrEqual(2)

    // The fix: finishAuth must run on the transport that actually handled the challenge,
    // so the stored resource_metadata URL drives token_endpoint discovery.
    expect(testTransport.finishAuth).toHaveBeenCalledTimes(1)
    expect(testTransport.finishAuth).toHaveBeenCalledWith('auth-code-123')

    // Regression guard: it must NOT be called on the main transport (which never saw the 401).
    expect(mainTransport.finishAuth).not.toHaveBeenCalled()
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

  // What `coordinateAuth` hands a secondary instance once a sibling has finished the browser flow:
  // there is no code to wait for, so awaiting one blocks until the MCP host times the server out.
  const secondaryInstanceAuth = () => ({
    waitForAuthCode: vi.fn(() => new Promise<string>(() => {})),
    skipBrowserAuth: true,
  })

  it('reconnects instead of awaiting a code when a sibling completed the sign-in (regression: #322)', async () => {
    const authState = secondaryInstanceAuth()
    const authInitializer = vi.fn().mockResolvedValue(authState)

    const connecting = connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')
    const HUNG = Symbol('hung')
    const outcome = await Promise.race([
      connecting.then(() => 'connected'),
      new Promise((resolve) => setTimeout(() => resolve(HUNG), 1000)),
    ])

    expect(outcome).toBe('connected')

    // The sibling already redeemed the authorization code, so there is nothing to exchange here
    expect(authState.waitForAuthCode).not.toHaveBeenCalled()
    expect(mockState.finishAuthCalls).toEqual([])
  })

  it('gives up rather than looping when a sibling instance tokens still do not work (regression: #322)', async () => {
    const authInitializer = vi.fn().mockResolvedValue(secondaryInstanceAuth())
    // Server keeps rejecting even after reading the sibling's tokens
    mockState.connectFailuresRemaining = Number.MAX_SAFE_INTEGER

    await expect(connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')).rejects.toThrow(
      'Already attempted reconnection',
    )
  })

  it('does not re-exchange a spent authorization code when the retry also fails (regression: #322)', async () => {
    // A real callback server retains the code it received, so a second call yields the same one
    const authInitializer = vi.fn().mockResolvedValue({
      waitForAuthCode: async () => 'auth-code-789',
      skipBrowserAuth: false,
    })
    mockState.connectFailuresRemaining = Number.MAX_SAFE_INTEGER

    // Without the guard ordering, the second exchange of 'auth-code-789' fails with invalid_grant,
    // masking the real reason the connection is being abandoned.
    await expect(connectToRemoteServer(null, 'https://mcp.example.com/mcp', {} as any, {}, authInitializer, 'http-first')).rejects.toThrow(
      'Already attempted reconnection',
    )

    expect(mockState.finishAuthCalls).toEqual(['auth-code-789'])
  })
})
