import { describe, it, expect } from 'vitest'
import { parseSocksUrl, redactProxyUrl } from './socks-dispatcher'

describe('Feature: SOCKS Proxy URL Parsing', () => {
  it('Scenario: Parse socks5:// URL', () => {
    const config = parseSocksUrl('socks5://proxy.example.com:1080')
    expect(config.type).toBe(5)
    expect(config.proxyDns).toBe(false)
    expect(config.host).toBe('proxy.example.com')
    expect(config.port).toBe(1080)
    expect(config.userId).toBeUndefined()
    expect(config.password).toBeUndefined()
  })

  it('Scenario: Parse socks5h:// URL with proxy-side DNS', () => {
    const config = parseSocksUrl('socks5h://proxy.example.com:1080')
    expect(config.type).toBe(5)
    expect(config.proxyDns).toBe(true)
    expect(config.host).toBe('proxy.example.com')
    expect(config.port).toBe(1080)
  })

  it('Scenario: Parse socks4:// URL', () => {
    const config = parseSocksUrl('socks4://proxy.example.com:1080')
    expect(config.type).toBe(4)
    expect(config.proxyDns).toBe(false)
  })

  it('Scenario: Parse socks4a:// URL with proxy-side DNS', () => {
    const config = parseSocksUrl('socks4a://proxy.example.com:1080')
    expect(config.type).toBe(4)
    expect(config.proxyDns).toBe(true)
  })

  it('Scenario: Parse credentials from URL', () => {
    const config = parseSocksUrl('socks5://user:pass@proxy.example.com:1080')
    expect(config.userId).toBe('user')
    expect(config.password).toBe('pass')
    expect(config.host).toBe('proxy.example.com')
    expect(config.port).toBe(1080)
  })

  it('Scenario: Default to port 1080 when port is omitted', () => {
    const config = parseSocksUrl('socks5://proxy.example.com')
    expect(config.port).toBe(1080)
  })

  it('Scenario: Throw on invalid port (out of range)', () => {
    expect(() => parseSocksUrl('socks5://proxy.example.com:0')).toThrow()
  })

  it('Scenario: Throw on invalid port (too high)', () => {
    expect(() => parseSocksUrl('socks5://proxy.example.com:99999')).toThrow()
  })

  it('Scenario: Throw on non-numeric port', () => {
    expect(() => parseSocksUrl('socks5://proxy.example.com:abc')).toThrow()
  })

  it('Scenario: Throw on unsupported protocol', () => {
    expect(() => parseSocksUrl('http://proxy.example.com:1080')).toThrow(/Unsupported SOCKS protocol/)
  })

  it('Scenario: Decode percent-encoded credentials from URL', () => {
    // user@domain → user%40domain, p:ss → p%3Ass
    const config = parseSocksUrl('socks5://user%40domain:p%3Ass@proxy.example.com:1080')
    expect(config.userId).toBe('user@domain')
    expect(config.password).toBe('p:ss')
  })

  it('Scenario: Strip brackets from IPv6 proxy host', () => {
    const config = parseSocksUrl('socks5://[::1]:1080')
    expect(config.host).toBe('::1')
    expect(config.port).toBe(1080)
    expect(config.type).toBe(5)
  })

  it('Scenario: Handle full IPv6 proxy host with brackets', () => {
    const config = parseSocksUrl('socks5://[fd12:3456:789a::1]:9050')
    expect(config.host).toBe('fd12:3456:789a::1')
    expect(config.port).toBe(9050)
  })

  it('Scenario: Throw on empty hostname', () => {
    expect(() => parseSocksUrl('socks5://')).toThrow(/must include a hostname/)
  })
})

describe('Feature: SOCKS4 IPv6 Destination Rejection', () => {
  it('Scenario: Reject IPv6 destination when using SOCKS4 proxy', async () => {
    const { createSocksDispatcher } = await import('./socks-dispatcher')
    const dispatcher = createSocksDispatcher('socks4://127.0.0.1:1080')

    await expect(
      dispatcher.request({ origin: 'https://[::1]', path: '/', method: 'GET' }),
    ).rejects.toThrow(/SOCKS4 does not support IPv6/)
    await dispatcher.close()
  })
})

describe('Feature: Proxy URL Credential Redaction', () => {
  it('Scenario: Redact credentials in URL', () => {
    const redacted = redactProxyUrl('socks5://user:pass@proxy.example.com:1080')
    expect(redacted).toContain('***')
    expect(redacted).not.toContain('user')
    expect(redacted).not.toContain('pass')
    expect(redacted).toContain('proxy.example.com')
    expect(redacted).toContain('1080')
  })

  it('Scenario: Pass through URL without credentials unchanged', () => {
    const url = 'socks5://proxy.example.com:1080'
    const redacted = redactProxyUrl(url)
    expect(redacted).toContain('proxy.example.com')
    expect(redacted).toContain('1080')
    expect(redacted).not.toContain('***')
  })
})
