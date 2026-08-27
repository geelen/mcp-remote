import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { authorizeWithDeviceCode, supportsDeviceAuthorization, DEVICE_CODE_GRANT_TYPE } from './device-authorization'
import { log } from './utils'

vi.mock('./utils', () => ({ log: vi.fn(), debugLog: vi.fn() }))

const metadata = {
  issuer: 'https://auth.example.com',
  token_endpoint: 'https://auth.example.com/token',
  device_authorization_endpoint: 'https://auth.example.com/device',
}

const clientInformation = { client_id: 'c1' }

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })

const issued = {
  device_code: 'dev-code',
  user_code: 'WDJB-MJHT',
  verification_uri: 'https://auth.example.com/activate',
  expires_in: 1800,
  interval: 1,
}

const tokens = { access_token: 'at', refresh_token: 'rt', token_type: 'Bearer', expires_in: 3600 }

/** Runs the flow with timers faked, so the poll interval costs nothing. */
async function runFlow(request: Parameters<typeof authorizeWithDeviceCode>[0]) {
  const flow = authorizeWithDeviceCode(request)
  // Let each poll's delay elapse without waiting on it for real
  const pump = (async () => {
    for (let tick = 0; tick < 40; tick++) {
      await vi.advanceTimersByTimeAsync(10_000)
    }
  })()
  const result = await flow
  await pump
  return result
}

describe('Feature: Signing in without a browser', () => {
  let fetchMock: any

  beforeEach(() => {
    vi.useFakeTimers()
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.clearAllMocks()
  })

  describe('detection', () => {
    it('Scenario: A server offering the endpoint and the grant can do this', () => {
      expect(supportsDeviceAuthorization({ ...metadata, grant_types_supported: ['authorization_code', DEVICE_CODE_GRANT_TYPE] })).toBe(true)
    })

    it('Scenario: A server with no device endpoint cannot', () => {
      expect(supportsDeviceAuthorization({ issuer: 'https://auth.example.com' })).toBe(false)
      expect(supportsDeviceAuthorization(undefined)).toBe(false)
    })

    it('Scenario: A server listing grants but not this one cannot', () => {
      expect(supportsDeviceAuthorization({ ...metadata, grant_types_supported: ['authorization_code'] })).toBe(false)
    })

    it('Scenario: A server that lists no grants at all is taken at the endpoint it published', () => {
      // Plenty of deployments offer the endpoint and advertise nothing; refusing those would
      // rule out working servers over a missing line of metadata
      expect(supportsDeviceAuthorization(metadata)).toBe(true)
    })
  })

  it('Scenario: The code is shown, then polled until someone approves it', async () => {
    // Given a server that keeps someone waiting for two polls
    fetchMock
      .mockResolvedValueOnce(json(200, issued))
      .mockResolvedValueOnce(json(400, { error: 'authorization_pending' }))
      .mockResolvedValueOnce(json(400, { error: 'authorization_pending' }))
      .mockResolvedValueOnce(json(200, tokens))

    const result = await runFlow({ metadata, clientInformation, scope: 'openid email' })

    // Then the person is told where to go and what to type
    const printed = vi.mocked(log).mock.calls.flat().join('\n')
    expect(printed).toContain('https://auth.example.com/activate')
    expect(printed).toContain('WDJB-MJHT')

    // And the tokens come back once they approve, refresh token included, which is what
    // makes the next run non-interactive
    expect(result.access_token).toBe('at')
    expect(result.refresh_token).toBe('rt')

    // And the request asked for what this client was configured with
    const authorizationBody = new URLSearchParams(fetchMock.mock.calls[0][1].body.toString())
    expect(authorizationBody.get('client_id')).toBe('c1')
    expect(authorizationBody.get('scope')).toBe('openid email')

    const tokenBody = new URLSearchParams(fetchMock.mock.calls[3][1].body.toString())
    expect(tokenBody.get('grant_type')).toBe(DEVICE_CODE_GRANT_TYPE)
    expect(tokenBody.get('device_code')).toBe('dev-code')
  })

  it('Scenario: A link carrying the code is offered instead of asking anyone to type it', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, { ...issued, verification_uri_complete: 'https://auth.example.com/activate?code=WDJB-MJHT' }))
      .mockResolvedValueOnce(json(200, tokens))

    await runFlow({ metadata, clientInformation })

    const printed = vi.mocked(log).mock.calls.flat().join('\n')
    expect(printed).toContain('https://auth.example.com/activate?code=WDJB-MJHT')
    expect(printed).not.toContain('And enter the code')
  })

  it('Scenario: A server asking us to slow down is obeyed for the rest of the flow', async () => {
    // Given a server that pushes back once
    fetchMock
      .mockResolvedValueOnce(json(200, issued))
      .mockResolvedValueOnce(json(400, { error: 'slow_down' }))
      .mockResolvedValueOnce(json(400, { error: 'authorization_pending' }))
      .mockResolvedValueOnce(json(200, tokens))

    const started = Date.now()
    await runFlow({ metadata, clientInformation })

    // Then the interval grows by the 5s RFC 8628 3.5 prescribes and stays grown: the first
    // poll waits 1s, and the two after it 6s each
    expect(Date.now() - started).toBeGreaterThanOrEqual(13_000)
  })

  it('Scenario: A refused authorization stops rather than polling on', async () => {
    fetchMock.mockResolvedValueOnce(json(200, issued)).mockResolvedValueOnce(json(400, { error: 'access_denied' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('Authorization was denied')
  })

  it('Scenario: An expired device code stops', async () => {
    fetchMock.mockResolvedValueOnce(json(200, issued)).mockResolvedValueOnce(json(400, { error: 'expired_token' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('expired before it was approved')
  })

  it('Scenario: Polling gives up once the code cannot still be valid', async () => {
    // Given a code good for one interval and nobody approving it. A fresh Response per call,
    // because a body can only be read once.
    fetchMock
      .mockResolvedValueOnce(json(200, { ...issued, expires_in: 2 }))
      .mockImplementation(async () => json(400, { error: 'authorization_pending' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('expired before it was approved')
  })

  it('Scenario: An unrecognised error surfaces what the server said', async () => {
    fetchMock
      .mockResolvedValueOnce(json(200, issued))
      .mockResolvedValueOnce(json(400, { error: 'invalid_client', error_description: 'client is not allowed this grant' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('client is not allowed this grant')
  })

  it('Scenario: A refused device authorization request says so', async () => {
    fetchMock.mockResolvedValueOnce(new Response('no such client', { status: 401, statusText: 'Unauthorized' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('Device authorization request failed (HTTP 401)')
  })

  it('Scenario: An incomplete response is not treated as a device authorization', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { device_code: 'dev-code' }))

    await expect(runFlow({ metadata, clientInformation })).rejects.toThrow('incomplete device authorization response')
  })

  it('Scenario: A confidential client authenticates on both requests', async () => {
    // Given a client the server issued a secret to, and a server taking it in the body
    fetchMock.mockResolvedValueOnce(json(200, issued)).mockResolvedValueOnce(json(200, tokens))

    await runFlow({
      metadata: { ...metadata, token_endpoint_auth_methods_supported: ['client_secret_post'] },
      clientInformation: { client_id: 'c1', client_secret: 'shh' },
    })

    for (const call of fetchMock.mock.calls) {
      expect(new URLSearchParams(call[1].body.toString()).get('client_secret')).toBe('shh')
    }
  })

  it('Scenario: A server wanting basic auth gets it in the header, never the body', async () => {
    fetchMock.mockResolvedValueOnce(json(200, issued)).mockResolvedValueOnce(json(200, tokens))

    await runFlow({
      metadata: { ...metadata, token_endpoint_auth_methods_supported: ['client_secret_basic'] },
      clientInformation: { client_id: 'c1', client_secret: 'shh' },
    })

    for (const call of fetchMock.mock.calls) {
      expect(call[1].headers.get('Authorization')).toBe(`Basic ${Buffer.from('c1:shh').toString('base64')}`)
      expect(new URLSearchParams(call[1].body.toString()).get('client_secret')).toBeNull()
    }
  })

  it('Scenario: The resource indicator is sent on both requests, as RFC 8707 requires', async () => {
    fetchMock.mockResolvedValueOnce(json(200, issued)).mockResolvedValueOnce(json(200, tokens))

    await runFlow({ metadata, clientInformation, resource: new URL('https://mcp.example.com/mcp') })

    for (const call of fetchMock.mock.calls) {
      expect(new URLSearchParams(call[1].body.toString()).get('resource')).toBe('https://mcp.example.com/mcp')
    }
  })

  it('Scenario: A server with no device endpoint is refused before anything is sent', async () => {
    await expect(authorizeWithDeviceCode({ metadata: { issuer: 'https://auth.example.com' }, clientInformation })).rejects.toThrow(
      'does not offer a device authorization endpoint',
    )

    expect(fetchMock).not.toHaveBeenCalled()
  })
})
