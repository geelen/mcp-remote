import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  parseCommandLineArgs,
  shouldIncludeTool,
  mcpProxy,
  setupOAuthCallbackServerWithLongPoll,
  getServerUrlHash,
  calculateDefaultPort,
  MCP_REMOTE_VERSION,
} from './utils'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { EventEmitter } from 'events'
import express from 'express'
import net from 'net'
import fs from 'fs'
import os from 'os'
import path from 'path'

// All sanitizeUrl tests have been moved to the strict-url-sanitise package

describe('Feature: Command Line Arguments Parsing', () => {
  it('Scenario: Show help without parsing server URL', async () => {
    // Given command line arguments with only the help flag
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as any)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit:${code}`)
    })

    // When parsing the command line arguments
    await expect(parseCommandLineArgs(['--help'], 'test usage')).rejects.toThrow('process.exit:0')

    // Then usage should be written before URL validation
    expect(stdoutSpy).toHaveBeenCalledWith('test usage\n')

    stdoutSpy.mockRestore()
    exitSpy.mockRestore()
  })

  it('Scenario: Show version without parsing server URL', async () => {
    // Given command line arguments with only the version flag
    const stdoutSpy = vi.spyOn(process.stdout, 'write').mockImplementation((() => true) as any)
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code?: string | number | null | undefined) => {
      throw new Error(`process.exit:${code}`)
    })

    // When parsing the command line arguments
    await expect(parseCommandLineArgs(['--version'], 'test usage')).rejects.toThrow('process.exit:0')

    // Then the version should be written before URL validation
    expect(stdoutSpy).toHaveBeenCalledWith(expect.stringMatching(/^\d+\.\d+\.\d+\n$/))

    stdoutSpy.mockRestore()
    exitSpy.mockRestore()
  })

  it('Scenario: Parse basic server URL', async () => {
    // Given command line arguments with only a server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the server URL should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(typeof result.serverUrl).toBe('string')
  })

  it('Scenario: Parse server URL with callback port', async () => {
    // Given command line arguments with server URL and port
    const args = ['https://example.com/sse', '3000']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then both server URL and callback port should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(3000)
  })

  it('Scenario: Default to the standard callback path when --callback-path is absent', async () => {
    // Given command line arguments without a callback path
    const args = ['https://example.com/sse']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be used
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Parse server URL with callback path', async () => {
    // Given command line arguments with a custom callback path
    const args = ['https://example.com/sse', '--callback-path', '/custom-callback']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then both server URL and callback path should be correctly extracted
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPath).toBe('/custom-callback')
  })

  it('Scenario: Ignore a callback path that is not rooted', async () => {
    // Given a callback path Express cannot route back to the redirect URI we would advertise
    const args = ['https://example.com/sse', '--callback-path', 'custom-callback']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be kept
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Ignore a callback path that shadows the long-poll endpoint', async () => {
    // Given a callback path that collides with the endpoint secondary instances poll
    const args = ['https://example.com/sse', '--callback-path', '/wait-for-auth']

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, 'test usage')

    // Then the standard callback path should be kept
    expect(result.callbackPath).toBe('/oauth/callback')
  })

  it('Scenario: Parse localhost URL with HTTP protocol', async () => {
    // Given command line arguments with localhost HTTP URL
    const args = ['http://localhost:8080/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the localhost HTTP URL should be accepted
    expect(result.serverUrl).toBe('http://localhost:8080/sse')
  })

  it('Scenario: Parse 127.0.0.1 URL with HTTP protocol', async () => {
    // Given command line arguments with 127.0.0.1 HTTP URL
    const args = ['http://127.0.0.1:8080/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the 127.0.0.1 HTTP URL should be accepted
    expect(result.serverUrl).toBe('http://127.0.0.1:8080/sse')
  })

  it('Scenario: Parse single custom header', async () => {
    // Given command line arguments with a custom header
    const args = ['https://example.com/sse', '--header', 'foo: taz']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom header should be correctly parsed
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({ foo: 'taz' })
  })

  it('Scenario: Parse multiple custom headers', async () => {
    // Given command line arguments with multiple custom headers
    const args = ['https://example.com/sse', '--header', 'Authorization: Bearer token123', '--header', 'Content-Type: application/json']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all custom headers should be correctly parsed
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({
      Authorization: 'Bearer token123',
      'Content-Type': 'application/json',
    })
  })

  it('Scenario: Never log custom header values', async () => {
    // Given a header carrying a secret
    const logSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--header', 'Authorization: Bearer super-secret-token']

    // When parsing the command line arguments
    await parseCommandLineArgs(args, 'test usage')

    // Then the header name is logged but the secret never is
    const logged = logSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n')
    expect(logged).toContain('Authorization')
    expect(logged).not.toContain('super-secret-token')

    logSpy.mockRestore()
  })

  it('Scenario: Ignore invalid header format', async () => {
    // Given command line arguments with an invalid header format
    const args = ['https://example.com/sse', '--header', 'invalid-header-format']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the invalid header should be ignored and headers should be empty
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.headers).toEqual({})
  })

  it('Scenario: Handle --allow-http flag for non-localhost URLs', async () => {
    // Given command line arguments with HTTP URL and --allow-http flag
    const args = ['http://example.com/sse', '--allow-http']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the HTTP URL should be accepted due to --allow-http flag
    expect(result.serverUrl).toBe('http://example.com/sse')
  })

  it('Scenario: Accept HTTPS URLs without --allow-http flag', async () => {
    // Given command line arguments with HTTPS URL only
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the HTTPS URL should be accepted without any additional flags
    expect(result.serverUrl).toBe('https://example.com/sse')
  })

  it('Scenario: Handle --allow-http with other arguments', async () => {
    // Given command line arguments with HTTP URL, port, --allow-http flag, and custom header
    const args = ['http://example.com/sse', '4000', '--allow-http', '--header', 'Authorization: Bearer abc123']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including HTTP URL acceptance
    expect(result.serverUrl).toBe('http://example.com/sse')
    expect(result.callbackPort).toBe(4000)
    expect(result.headers).toEqual({ Authorization: 'Bearer abc123' })
  })

  it('Scenario: Use default transport strategy when not specified', async () => {
    // Given command line arguments with only server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default transport strategy should be http-first
    expect(result.transportStrategy).toBe('http-first')
  })

  it('Scenario: Parse transport strategy sse-only', async () => {
    // Given command line arguments with --transport sse-only
    const args = ['https://example.com/sse', '--transport', 'sse-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to sse-only
    expect(result.transportStrategy).toBe('sse-only')
  })

  it('Scenario: Parse transport strategy http-only', async () => {
    // Given command line arguments with --transport http-only
    const args = ['https://example.com/sse', '--transport', 'http-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to http-only
    expect(result.transportStrategy).toBe('http-only')
  })

  it('Scenario: Parse transport strategy sse-first', async () => {
    // Given command line arguments with --transport sse-first
    const args = ['https://example.com/sse', '--transport', 'sse-first']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to sse-first
    expect(result.transportStrategy).toBe('sse-first')
  })

  it('Scenario: Parse transport strategy http-first', async () => {
    // Given command line arguments with --transport http-first
    const args = ['https://example.com/sse', '--transport', 'http-first']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the transport strategy should be set to http-first
    expect(result.transportStrategy).toBe('http-first')
  })

  it('Scenario: Ignore invalid transport strategy and use default', async () => {
    // Given command line arguments with invalid transport strategy
    const args = ['https://example.com/sse', '--transport', 'invalid-strategy']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the invalid strategy should be ignored and default should be used
    expect(result.transportStrategy).toBe('http-first') // Should fallback to default
  })

  it('Scenario: Use default host when not specified', async () => {
    // Given command line arguments with only server URL
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default host should be localhost
    expect(result.host).toBe('localhost')
  })

  it('Scenario: Default to the IPv4 loopback literal on Windows', async () => {
    // Given Windows, where `localhost` often resolves to ::1 first while the
    // callback server binds 127.0.0.1, so the redirect lands on a closed socket
    const original = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })

    try {
      // When parsing without an explicit --host
      const result = await parseCommandLineArgs(['https://example.com/sse'], 'test usage')

      // Then the redirect URI names the address the listener is actually on
      expect(result.host).toBe('127.0.0.1')
    } finally {
      Object.defineProperty(process, 'platform', original)
    }
  })

  it('Scenario: An explicit --host still wins on Windows', async () => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform')!
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })

    try {
      const result = await parseCommandLineArgs(['https://example.com/sse', '--host', 'myserver.local'], 'test usage')

      expect(result.host).toBe('myserver.local')
    } finally {
      Object.defineProperty(process, 'platform', original)
    }
  })

  it('Scenario: Parse custom IP host', async () => {
    // Given command line arguments with custom IP host
    const args = ['https://example.com/sse', '--host', '127.0.0.1']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom IP host should be correctly set
    expect(result.host).toBe('127.0.0.1')
  })

  it('Scenario: Parse custom domain host', async () => {
    // Given command line arguments with custom domain host
    const args = ['https://example.com/sse', '--host', 'myserver.local']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom domain host should be correctly set
    expect(result.host).toBe('myserver.local')
  })

  it('Scenario: Handle host with multiple other arguments', async () => {
    // Given command line arguments with host, port, and transport strategy
    const args = ['https://example.com/sse', '3000', '--host', 'custom.host.com', '--transport', 'sse-only']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including the host
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(3000)
    expect(result.host).toBe('custom.host.com')
    expect(result.transportStrategy).toBe('sse-only')
  })

  it('Scenario: Return empty ignored tools array when none specified', async () => {
    // Given command line arguments without --ignore-tool flags
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should be empty
    expect(result.ignoredTools).toEqual([])
  })

  it('Scenario: Parse single ignored tool', async () => {
    // Given command line arguments with one --ignore-tool flag
    const args = ['https://example.com/sse', '--ignore-tool', 'foo']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should contain the specified tool
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.ignoredTools).toEqual(['foo'])
  })

  it('Scenario: Parse multiple ignored tools', async () => {
    // Given command line arguments with multiple --ignore-tool flags
    const args = ['https://example.com/sse', '--ignore-tool', 'foo', '--ignore-tool', 'bar', '--ignore-tool', 'baz']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the ignored tools array should contain all specified tools
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.ignoredTools).toEqual(['foo', 'bar', 'baz'])
  })

  it('Scenario: Handle ignored tools with other arguments', async () => {
    // Given command line arguments with ignored tools mixed with other arguments
    const args = [
      'https://example.com/sse',
      '4000',
      '--ignore-tool',
      'tool1',
      '--host',
      'localhost',
      '--ignore-tool',
      'tool2',
      '--transport',
      'sse-only',
    ]
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then all arguments should be correctly parsed including ignored tools
    expect(result.serverUrl).toBe('https://example.com/sse')
    expect(result.callbackPort).toBe(4000)
    expect(result.host).toBe('localhost')
    expect(result.transportStrategy).toBe('sse-only')
    expect(result.ignoredTools).toEqual(['tool1', 'tool2'])
  })

  it('Scenario: Use default auth timeout when not specified', async () => {
    // Given command line arguments without --auth-timeout flag
    const args = ['https://example.com/sse']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default auth timeout should be 30000ms
    expect(result.authTimeoutMs).toBe(30000)
  })

  it('Scenario: Parse valid auth timeout in seconds and convert to milliseconds', async () => {
    // Given command line arguments with valid --auth-timeout
    const args = ['https://example.com/sse', '--auth-timeout', '60']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the timeout should be converted to milliseconds
    expect(result.authTimeoutMs).toBe(60000)
  })

  it('Scenario: Use default timeout when invalid auth timeout value is provided', async () => {
    // Given command line arguments with invalid --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', 'invalid']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: invalid. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Use default timeout when negative auth timeout value is provided', async () => {
    // Given command line arguments with negative --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '-30']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: -30. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Use default timeout when zero auth timeout value is provided', async () => {
    // Given command line arguments with zero --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '0']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the default timeout should be used and warning logged
    expect(result.authTimeoutMs).toBe(30000)
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Warning: Ignoring invalid auth timeout value: 0. Must be a positive number.'),
    )

    consoleSpy.mockRestore()
  })

  it('Scenario: Log when using custom auth timeout', async () => {
    // Given command line arguments with custom --auth-timeout value
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '45']
    const usage = 'test usage'

    // When parsing the command line arguments
    const result = await parseCommandLineArgs(args, usage)

    // Then the custom timeout should be used and logged
    expect(result.authTimeoutMs).toBe(45000)
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Using auth callback timeout: 45 seconds'))

    consoleSpy.mockRestore()
  })

  it('Scenario: Suppresses LOG when using --silent', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const args = ['https://example.com/sse', '--auth-timeout', '45', '--silent']
    const usage = 'test usage'

    const result = await parseCommandLineArgs(args, usage)

    expect(result.authTimeoutMs).toBe(45000)
    expect(consoleSpy).not.toHaveBeenCalled()

    consoleSpy.mockRestore()
  })
})

describe('Feature: Tool Filtering with Ignore Patterns', () => {
  it('Scenario: Single wildcard pattern ignores matching tools', () => {
    // Given ignore patterns with create* wildcard
    const ignorePatterns = ['create*']

    // When checking if createTask should be included
    const result1 = shouldIncludeTool(ignorePatterns, 'createTask')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking if getTask should be included
    const result2 = shouldIncludeTool(ignorePatterns, 'getTask')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })

  it('Scenario: Multiple wildcard patterns ignore matching tools', () => {
    // Given ignore patterns with create* and put* wildcards
    const ignorePatterns = ['create*', 'put*']

    // When checking if createTask should be included
    const result1 = shouldIncludeTool(ignorePatterns, 'createTask')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking if infoTask should be included
    const result2 = shouldIncludeTool(ignorePatterns, 'infoTask')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })

  it('Scenario: Suffix wildcard pattern ignores matching tools', () => {
    // Given ignore patterns with *account suffix wildcard
    const ignorePatterns = ['*account']

    // When checking various account-related tools
    const result1 = shouldIncludeTool(ignorePatterns, 'getAccount')
    const result2 = shouldIncludeTool(ignorePatterns, 'putAccount')
    const result3 = shouldIncludeTool(ignorePatterns, 'account')

    // Then all should be excluded (return false)
    expect(result1).toBe(false)
    expect(result2).toBe(false)
    expect(result3).toBe(false)
  })

  it('Scenario: Empty ignore patterns include all tools', () => {
    // Given empty ignore patterns
    const ignorePatterns: string[] = []

    // When checking any tool
    const result = shouldIncludeTool(ignorePatterns, 'anyTool')

    // Then it should be included (return true)
    expect(result).toBe(true)
  })

  it('Scenario: Non-matching patterns include tools', () => {
    // Given ignore patterns that don't match the tool
    const ignorePatterns = ['delete*', 'remove*']

    // When checking a tool that doesn't match any pattern
    const result = shouldIncludeTool(ignorePatterns, 'createTask')

    // Then it should be included (return true)
    expect(result).toBe(true)
  })

  it('Scenario: Exact match without wildcards', () => {
    // Given ignore patterns with exact tool names
    const ignorePatterns = ['exactTool', 'anotherTool']

    // When checking the exact tool name
    const result1 = shouldIncludeTool(ignorePatterns, 'exactTool')
    // Then it should be excluded (return false)
    expect(result1).toBe(false)

    // When checking a different tool name
    const result2 = shouldIncludeTool(ignorePatterns, 'differentTool')
    // Then it should be included (return true)
    expect(result2).toBe(true)
  })
})

describe('Feature: MCP Proxy', () => {
  const mockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  it('Scenario: Proxy initialize message from client to server', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when client sends an initialize message
    const initializeMessage = {
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: {
        clientInfo: {
          name: 'Test Client',
          version: '1.0.0',
        },
      },
    }

    // Simulate client sending a message by calling the message handler directly
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(initializeMessage)
    }

    // Then the message should be forwarded to the server
    expect(mockTransportToServer.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        method: 'initialize',
        id: '1',
        params: expect.objectContaining({
          clientInfo: expect.objectContaining({
            name: expect.stringContaining('Test Client'),
            version: '1.0.0',
          }),
        }),
      }),
    )
  })

  it('Scenario: Negotiated protocol version is set on the remote transport', async () => {
    // Given mock transports where the remote one records the negotiated version
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const setProtocolVersion = vi.fn()
    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      setProtocolVersion,
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client initializes and the server answers with a protocol version
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)

    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '1',
      result: { protocolVersion: '2025-11-25', capabilities: {}, serverInfo: { name: 'Test Server', version: '1.0.0' } },
    } as any)

    // Then the remote transport is told which version was negotiated, so later
    // requests carry the MCP-Protocol-Version header
    expect(setProtocolVersion).toHaveBeenCalledWith('2025-11-25')
  })

  it('Scenario: A later response carrying a protocolVersion does not change the negotiated version', async () => {
    // Given a proxy that has already completed the initialize handshake
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const setProtocolVersion = vi.fn()
    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      setProtocolVersion,
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '1',
      result: { protocolVersion: '2025-11-25' },
    } as any)
    setProtocolVersion.mockClear()

    // When an unrelated tool result happens to carry a protocolVersion field
    mockTransportToServer.onmessage?.({
      jsonrpc: '2.0' as const,
      id: '2',
      result: { protocolVersion: 'not-a-negotiated-version' },
    } as any)

    // Then it is ignored
    expect(setProtocolVersion).not.toHaveBeenCalled()
  })

  it('Scenario: Proxy server response back to client', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // First simulate client sending a request (so there's a pending request)
    const clientRequest = {
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: {
        clientInfo: {
          name: 'Test Client',
          version: '1.0.0',
        },
      },
    }

    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientRequest)
    }

    // Clear the previous call
    vi.clearAllMocks()

    // Now simulate server sending a response message
    const serverResponse = {
      jsonrpc: '2.0' as const,
      id: '1',
      result: {
        capabilities: {
          tools: {
            listChanged: true,
          },
        },
        serverInfo: {
          name: 'Atlassian MCP',
          version: '1.0.0',
        },
      },
    }

    // Simulate server sending a response by calling the message handler directly
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverResponse)
    }

    // Then the response should be forwarded to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '1',
        result: {
          capabilities: {
            tools: {
              listChanged: true,
            },
          },
          serverInfo: {
            name: 'Atlassian MCP',
            version: '1.0.0',
          },
        },
      }),
    )
  })

  it('Scenario: Close server transport when client transport closes', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when client transport closes
    if (mockTransportToClient.onclose) {
      mockTransportToClient.onclose()
    }

    // Then server transport should also be closed
    expect(mockTransportToServer.close).toHaveBeenCalled()
  })

  it('Scenario: Close client transport when server transport closes', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server transport closes
    if (mockTransportToServer.onclose) {
      mockTransportToServer.onclose()
    }

    // Then client transport should also be closed
    expect(mockTransportToClient.close).toHaveBeenCalled()
  })

  it('Scenario: Filter tools in tools/list response when ignoredTools is configured', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy with ignored tools
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*', 'remove*'],
    })

    // First simulate client sending a tools/list request
    const toolsListRequest = {
      jsonrpc: '2.0' as const,
      method: 'tools/list',
      id: '2',
      params: {},
    }

    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(toolsListRequest)
    }

    // Clear the previous call
    vi.clearAllMocks()

    // Now simulate server sending a tools/list response with various tools
    const serverToolsResponse = {
      jsonrpc: '2.0' as const,
      id: '2',
      result: {
        tools: [
          { name: 'createTask', description: 'Create a new task' },
          { name: 'deleteTask', description: 'Delete a task' },
          { name: 'updateTask', description: 'Update a task' },
          { name: 'removeUser', description: 'Remove a user' },
          { name: 'listTasks', description: 'List all tasks' },
        ],
      },
    }

    // Simulate server sending a response
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverToolsResponse)
    }

    // Then the response should be forwarded to the client with filtered tools
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '2',
        result: {
          tools: [
            { name: 'createTask', description: 'Create a new task' },
            { name: 'updateTask', description: 'Update a task' },
            { name: 'listTasks', description: 'List all tasks' },
          ],
        },
      }),
    )
  })

  it('Scenario: Forward an error response to tools/list instead of dropping it', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And a tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 2, method: 'tools/list' } as any)

    // When the server answers it with a JSON-RPC error rather than a result
    mockTransportToServer.onmessage!({
      jsonrpc: '2.0',
      id: 2,
      error: { code: -32600, message: 'Session not initialized' },
    } as any)

    // Then the error reaches the client, rather than the request going unanswered
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 2,
        error: { code: -32600, message: 'Session not initialized' },
      }),
    )
  })

  it('Scenario: Forward a tools/list result that carries no tools', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And a tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 3, method: 'tools/list' } as any)

    // When the server answers with a result that omits the tools array
    mockTransportToServer.onmessage!({ jsonrpc: '2.0', id: 3, result: {} } as any)

    // Then the result is forwarded untouched
    expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: 3, result: {} }))
  })

  it('Scenario: A server-initiated request does not consume a pending request with the same id', async () => {
    // Given a proxy between mock transports
    const mockTransportToClient = mockTransport()
    const mockTransportToServer = mockTransport()

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And an in-flight tools/list request from the client
    mockTransportToClient.onmessage!({ jsonrpc: '2.0', id: 1, method: 'tools/list' } as any)

    // When the server sends a request of its own that happens to reuse id 1, the two directions
    // numbering their requests independently
    mockTransportToServer.onmessage!({ jsonrpc: '2.0', id: 1, method: 'ping' } as any)

    // Then the ping reaches the client untouched
    expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: 1, method: 'ping' }))

    // And the client's request is still pending, so its real answer is filtered as configured
    mockTransportToServer.onmessage!({
      jsonrpc: '2.0',
      id: 1,
      result: { tools: [{ name: 'deleteTask' }, { name: 'listTasks' }] },
    } as any)

    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        id: 1,
        result: { tools: [{ name: 'listTasks' }] },
      }),
    )
  })

  it('Scenario: Block tools/call for ignored tools with delete* filter', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy with delete* filter
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: ['delete*'],
    })

    // And when client tries to call a deleteTask tool
    const toolsCallMessage = {
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '3',
      params: {
        name: 'deleteTask',
        arguments: {
          taskId: '1',
        },
        _meta: {
          progressToken: 1,
        },
      },
    }

    // Simulate client sending the tools/call message
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(toolsCallMessage)
    }

    // Then the call should NOT be forwarded to the server
    expect(mockTransportToServer.send).not.toHaveBeenCalled()

    // And an error response should be sent back to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: '3',
        error: expect.objectContaining({
          code: expect.any(Number),
          message: expect.stringContaining('Tool "deleteTask" is not available'),
        }),
      }),
    )
  })

  it('Scenario: Handle server-initiated requests (without corresponding client request)', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server sends a ping message (server-initiated, no corresponding client request)
    const serverPingMessage = {
      jsonrpc: '2.0' as const,
      method: 'ping',
      id: 'server-ping-1',
    }

    // Simulate server sending the message
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(serverPingMessage)
    }

    // Then the message should be forwarded to the client without errors
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        method: 'ping',
        id: 'server-ping-1',
      }),
    )
  })

  it('Scenario: Handle server-initiated response messages without corresponding request', async () => {
    // Given mock transports for client and server
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // When setting up the proxy
    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // And when server sends a response with an ID that has no corresponding request
    const orphanedResponse = {
      jsonrpc: '2.0' as const,
      id: 'unknown-request-id',
      result: {},
    }

    // Simulate server sending a response without a matching request
    if (mockTransportToServer.onmessage) {
      mockTransportToServer.onmessage(orphanedResponse)
    }

    // Then the response should still be forwarded to the client
    expect(mockTransportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: 'unknown-request-id',
        result: {},
      }),
    )
  })

  it('Scenario: Re-establish the session when the server has expired it', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a server transport that 404s the first tools/call, as a server does
    // once it has dropped the session, then answers the fresh handshake
    const sent: any[] = []
    let expireNextCall = true
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (typeof message.id === 'string' && message.id.startsWith('mcp-remote-reinit-')) {
          setTimeout(
            () =>
              (mockTransportToServer as any).onmessage?.({
                jsonrpc: '2.0',
                id: message.id,
                result: { protocolVersion: '2025-11-25' },
              }),
            0,
          )
          return
        }
        if (expireNextCall && message.method === 'tools/call') {
          expireNextCall = false
          throw new StreamableHTTPError(404, 'Error POSTing to endpoint: Session terminated')
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      setProtocolVersion: vi.fn(),
      sessionId: 'session-2',
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client initializes and then calls a tool
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '2',
      params: { name: 'ping', arguments: {} },
    } as any)

    await vi.waitFor(() => expect(sent.map((m) => m.method)).toContain('notifications/initialized'))

    // Then a fresh initialize was sent, carrying the client's own parameters
    const reinitialize = sent.find((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))
    expect(reinitialize).toBeDefined()
    expect(reinitialize.method).toBe('initialize')
    expect(reinitialize.params.clientInfo.name).toContain('Test Client')

    // And the version the new session negotiated is what later requests announce
    expect((mockTransportToServer as any).setProtocolVersion).toHaveBeenCalledWith('2025-11-25')

    // And the call that triggered it was retried on the new session
    expect(sent.filter((m) => m.method === 'tools/call' && m.id === '2')).toHaveLength(2)

    // And the handshake response was consumed by the proxy, never shown to the client
    expect(mockTransportToClient.send).not.toHaveBeenCalledWith(expect.objectContaining({ id: reinitialize.id }))
  })

  it('Scenario: Concurrent requests hitting a dead session share one new session', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a server that 404s every tools/call until the session is re-established
    const sent: any[] = []
    let sessionAlive = false
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (typeof message.id === 'string' && message.id.startsWith('mcp-remote-reinit-')) {
          // Answer on a later tick, so a second caller can arrive while this is in flight
          setTimeout(() => {
            sessionAlive = true
            ;(mockTransportToServer as any).onmessage?.({ jsonrpc: '2.0', id: message.id, result: {} })
          }, 5)
          return
        }
        if (!sessionAlive && message.method === 'tools/call') {
          throw new StreamableHTTPError(404, 'Error POSTing to endpoint: Session terminated')
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      sessionId: 'expired-session',
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)

    // When two requests are in flight when the session dies
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'a' } } as any)
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '3', params: { name: 'b' } } as any)

    await vi.waitFor(() => expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(4))

    // Then they share a single handshake instead of opening a session each. Racing
    // handshakes would also blank the session id under a retry already in flight,
    // and a server that requires one answers that with 400.
    const handshakes = sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))
    expect(handshakes).toHaveLength(1)
    expect(sent.filter((m) => m.method === 'notifications/initialized')).toHaveLength(1)

    // And both requests were retried on it
    expect(sent.filter((m) => m.method === 'tools/call' && m.params.name === 'a')).toHaveLength(2)
    expect(sent.filter((m) => m.method === 'tools/call' && m.params.name === 'b')).toHaveLength(2)
  })

  it('Scenario: A 404 without a session id is not treated as an expired session', async () => {
    // Given a client transport
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    // And a stateless server that never issued a session id, 404ing a bad endpoint
    const sent: any[] = []
    const mockTransportToServer = {
      send: vi.fn(async (message: any) => {
        sent.push(message)
        if (message.method === 'tools/call') {
          throw new StreamableHTTPError(404, 'Error POSTing to endpoint: Not Found')
        }
      }),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
      sessionId: undefined,
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: '1',
      params: { clientInfo: { name: 'Test Client', version: '1.0.0' } },
    } as any)
    mockTransportToClient.onmessage?.({ jsonrpc: '2.0' as const, method: 'tools/call', id: '2', params: { name: 'ping' } } as any)

    // Then the failure goes straight back to the client, with no pointless handshake
    await vi.waitFor(() => expect(mockTransportToClient.send).toHaveBeenCalledWith(expect.objectContaining({ id: '2' })))
    expect(sent.filter((m) => typeof m.id === 'string' && m.id.startsWith('mcp-remote-reinit-'))).toHaveLength(0)
    expect(sent.filter((m) => m.method === 'tools/call')).toHaveLength(1)
  })
  it('Scenario: Answer the client when a request cannot be delivered', async () => {
    // Given a server transport that fails for a reason a new session cannot fix
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('connection reset')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client sends a request
    mockTransportToClient.onmessage?.({
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: '7',
      params: { name: 'ping', arguments: {} },
    } as any)

    // Then it gets an error rather than waiting forever for a reply
    await vi.waitFor(() =>
      expect(mockTransportToClient.send).toHaveBeenCalledWith(
        expect.objectContaining({
          jsonrpc: '2.0',
          id: '7',
          error: expect.objectContaining({ code: -32001 }),
        }),
      ),
    )
  })

  it('Scenario: Failed forward of a notification does not produce a response', async () => {
    // Given a server transport whose send() rejects
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('Error POSTing to endpoint (HTTP 404): Session not found')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client sends a notification (no id)
    const clientNotification = {
      jsonrpc: '2.0' as const,
      method: 'notifications/initialized',
    }
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientNotification)
    }

    // Then no response is sent back — JSON-RPC forbids replies to notifications
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(mockTransportToClient.send).not.toHaveBeenCalled()
  })

  it('Scenario: Failed forward of a client response does not produce a response', async () => {
    // Given a server transport whose send() rejects
    const mockTransportToClient = {
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    const mockTransportToServer = {
      send: vi.fn().mockRejectedValue(new Error('Error POSTing to endpoint (HTTP 404): Session not found')),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    } as unknown as Transport

    mcpProxy({
      transportToClient: mockTransportToClient,
      transportToServer: mockTransportToServer,
      ignoredTools: [],
    })

    // When the client answers a server-initiated request (an id, but no method)
    const clientResponse = {
      jsonrpc: '2.0' as const,
      id: 7,
      result: {},
    }
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientResponse)
    }

    // Then no error response is sent back. Answering a response would make the
    // local SDK raise "Received a response for an unknown message ID"
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(mockTransportToClient.send).not.toHaveBeenCalled()
  })
})

describe('setupOAuthCallbackServerWithLongPoll', () => {
  let server: any
  let events: EventEmitter

  beforeEach(() => {
    events = new EventEmitter()
  })

  afterEach(() => {
    if (server) {
      server.close()
      server = null
    }
  })

  it('should use custom timeout when authTimeoutMs is provided', async () => {
    const customTimeout = 5000
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events,
      authTimeoutMs: customTimeout,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    // Test that the server was created
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })

  it('should use default timeout when authTimeoutMs is not provided', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0, // Use any available port
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    // Test that the server was created with defaults
    expect(server).toBeDefined()
    expect(typeof result.waitForAuthCode).toBe('function')
  })

  it('should return actualPort matching the bound port on success', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server
    const boundPort = (server.address() as net.AddressInfo).port
    expect(result.actualPort).toBe(boundPort)
    expect(result.actualPort).toBeGreaterThan(0)
  })

  it('surfaces EADDRINUSE instead of moving to a random port', async () => {
    // The deterministic port is what lets concurrent instances agree on one owner. An instance
    // that quietly moved elsewhere would advertise a redirect_uri no browser can deliver a code
    // to, so a taken port has to be reported rather than worked around.
    const blocker = net.createServer()
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })

    try {
      await expect(
        setupOAuthCallbackServerWithLongPoll({
          port: blockedPort,
          path: '/oauth/callback',
          events,
          serverUrlHash: 'test-hash',
        }),
      ).rejects.toMatchObject({ code: 'EADDRINUSE', requestedPort: blockedPort })
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()))
    }
  })

  it('reports a denied authorization instead of waiting for a code that is not coming', async () => {
    // ?error= is how "the user clicked Deny", an org policy block or invalid_scope arrives. Waiting
    // for a code holds the callback port for the life of the process and tells the user nothing.
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'test-hash',
    })
    server = result.server
    // A handler is attached synchronously: the callback arrives during the await below, and a
    // rejection with nothing attached yet is reported as unhandled even though it is asserted on
    const settled = result.waitForAuthCode().then(
      () => new Error('expected no authorization code'),
      (error: Error) => error,
    )

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?error=access_denied&error_description=User%20denied`)

    expect(response.status).toBe(400)
    await expect(response.text()).resolves.toContain('User denied')
    expect((await settled).message).toMatch(/access_denied/)
  })

  it('answers an identity probe, so a losing instance can tell a sibling from a stranger', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/oauth/callback',
      events,
      serverUrlHash: 'a-particular-server',
    })
    server = result.server

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/.mcp-remote/id`)

    await expect(response.json()).resolves.toEqual({ mcpRemote: true, serverUrlHash: 'a-particular-server' })
  })

  it('should serve the callback on the configured path', async () => {
    const result = await setupOAuthCallbackServerWithLongPoll({
      port: 0,
      path: '/custom/callback',
      events,
      serverUrlHash: 'test-hash',
    })

    server = result.server

    const response = await fetch(`http://127.0.0.1:${result.actualPort}/custom/callback?code=test-code`)
    expect(response.status).toBe(200)
    await expect(result.waitForAuthCode()).resolves.toEqual({ code: 'test-code', state: undefined })

    // The default path must not be served when it was overridden, otherwise the redirect URI
    // we advertise and the endpoint we listen on can silently disagree
    const defaultPath = await fetch(`http://127.0.0.1:${result.actualPort}/oauth/callback?code=test-code`)
    expect(defaultPath.status).toBe(404)
  })

  it('should reject with EADDRINUSE error when strictPort is true and port is already in use', async () => {
    const blocker = net.createServer()
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })

    try {
      await expect(
        setupOAuthCallbackServerWithLongPoll({
          port: blockedPort,
          path: '/oauth/callback',
          events,
          serverUrlHash: 'test-hash',
        }),
      ).rejects.toMatchObject({
        code: 'EADDRINUSE',
        requestedPort: blockedPort,
      })
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()))
    }
  })
})

describe('Feature: Server URL Hash Generation', () => {
  it('Scenario: Generate consistent hash for same config', () => {
    const hash1 = getServerUrlHash('https://example.com', 'resource1', { Auth: 'token' })
    const hash2 = getServerUrlHash('https://example.com', 'resource1', { Auth: 'token' })
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Generate different hash for different resources', () => {
    const hash1 = getServerUrlHash('https://example.com', 'resource1')
    const hash2 = getServerUrlHash('https://example.com', 'resource2')
    expect(hash1).not.toBe(hash2)
  })

  it('Scenario: Generate different hash for different headers', () => {
    const hash1 = getServerUrlHash('https://example.com', '', { Auth: 'token1' })
    const hash2 = getServerUrlHash('https://example.com', '', { Auth: 'token2' })
    expect(hash1).not.toBe(hash2)
  })

  it('Scenario: Handle header key ordering consistently', () => {
    const hash1 = getServerUrlHash('https://example.com', '', { B: '2', A: '1' })
    const hash2 = getServerUrlHash('https://example.com', '', { A: '1', B: '2' })
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Backward compatible with no resource or headers', () => {
    const hash1 = getServerUrlHash('https://example.com')
    const hash2 = getServerUrlHash('https://example.com', '', {})
    expect(hash1).toBe(hash2)
  })

  it('Scenario: Empty string resource same as undefined', () => {
    const hash1 = getServerUrlHash('https://example.com', '')
    const hash2 = getServerUrlHash('https://example.com')
    expect(hash1).toBe(hash2)
  })
})

describe('Feature: Stale Client Registration Invalidation', () => {
  const originalConfigDir = process.env.MCP_REMOTE_CONFIG_DIR
  let baseDir: string
  let versionDir: string

  const clientInfoPath = (serverUrl: string, headers: Record<string, string> = {}) =>
    path.join(versionDir, `${getServerUrlHash(serverUrl, undefined, headers)}_client_info.json`)

  const writeRegistration = (serverUrl: string, redirectUris: string[]) => {
    fs.mkdirSync(versionDir, { recursive: true })
    fs.writeFileSync(clientInfoPath(serverUrl), JSON.stringify({ client_id: 'registered-id', redirect_uris: redirectUris }))
  }

  beforeEach(() => {
    baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-remote-test-'))
    process.env.MCP_REMOTE_CONFIG_DIR = baseDir
    versionDir = path.join(baseDir, `mcp-remote-${MCP_REMOTE_VERSION}`)
  })

  afterEach(() => {
    if (originalConfigDir === undefined) delete process.env.MCP_REMOTE_CONFIG_DIR
    else process.env.MCP_REMOTE_CONFIG_DIR = originalConfigDir
    fs.rmSync(baseDir, { recursive: true, force: true })
  })

  it('Scenario: Reuse a registration whose redirect_uri still matches', async () => {
    // Given a registration made against the port this server derives
    const serverUrl = 'https://reuse.example.com/mcp'
    const derivedPort = calculateDefaultPort(getServerUrlHash(serverUrl))
    writeRegistration(serverUrl, [`http://localhost:${derivedPort}/oauth/callback`])

    // When starting with no port override
    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    // Then the derived port is used and the registration is kept
    expect(result.callbackPort).toBe(derivedPort)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(true)
  })

  it('Scenario: Every instance derives the same port, so none is taken from a cached registration', async () => {
    // A registration left behind on some other port must not pull this instance off the port its
    // siblings will derive - agreeing on one port is what lets them agree on one owner.
    const serverUrl = 'https://derived.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    expect(result.callbackPort).toBe(calculateDefaultPort(getServerUrlHash(serverUrl)))
    expect(result.callbackPort).not.toBe(5599)
    // and the registration that named the other port is discarded rather than reused
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration whose redirect_uri is not reachable locally', async () => {
    // Given a registration pointing at a reverse proxy - no local port can be derived from it.
    // This used to throw "Cannot find localhost callback URI" and kill the process.
    const serverUrl = 'https://proxied.example.com/mcp'
    writeRegistration(serverUrl, ['https://proxy.example.com/oauth/callback'])

    // When starting
    const result = await parseCommandLineArgs([serverUrl], 'test usage')

    // Then it does not throw, and the unusable registration is gone so the next request
    // re-registers with a redirect_uri the authorization server will actually accept
    expect(result.callbackPort).toBeGreaterThan(0)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration when the callback host changes', async () => {
    // Given a registration made against localhost
    const serverUrl = 'https://hostchange.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    // When the same server is started with a different callback host
    const result = await parseCommandLineArgs([serverUrl, '--host', '127.0.0.1'], 'test usage')

    // Then the registration is discarded - 127.0.0.1 and localhost are distinct redirect_uris
    expect(result.callbackPort).toBe(calculateDefaultPort(getServerUrlHash(serverUrl)))
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Discard a registration when an explicit port conflicts', async () => {
    // Given a registration on one port
    const serverUrl = 'https://portconflict.example.com/mcp'
    writeRegistration(serverUrl, ['http://localhost:5599/oauth/callback'])

    // When a different port is demanded
    const result = await parseCommandLineArgs([serverUrl, '7788'], 'test usage')

    // Then the stale registration is discarded
    expect(result.callbackPort).toBe(7788)
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(false)
  })

  it('Scenario: Never discard a user-pinned static client registration', async () => {
    // Given a registration that does not match, but static client info was supplied
    const serverUrl = 'https://static.example.com/mcp'
    writeRegistration(serverUrl, ['https://proxy.example.com/oauth/callback'])

    // When starting with --static-oauth-client-info
    await parseCommandLineArgs(
      [serverUrl, '--static-oauth-client-info', '{"client_id":"pinned","redirect_uris":["https://proxy.example.com/oauth/callback"]}'],
      'test usage',
    )

    // Then it is left alone - the user pinned it deliberately
    expect(fs.existsSync(clientInfoPath(serverUrl))).toBe(true)
  })
})

describe('Feature: Resource Indicator Flags', () => {
  it('Scenario: Parse --resource', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--resource', 'https://tenant.example.com/'], 'test usage')
    expect(result.authorizeResource).toBe('https://tenant.example.com/')
    expect(result.skipResourceParameter).toBe(false)
  })

  it('Scenario: Reject a --resource value that is not an absolute URI', async () => {
    // RFC 8707 requires an absolute URI; failing here beats an opaque error from the server
    await expect(parseCommandLineArgs(['https://example.com/mcp', '--resource', 'not-a-uri'], 'test usage')).rejects.toThrow(/absolute URI/)
  })

  it('Scenario: Disable the resource parameter', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--disable-resource-parameter'], 'test usage')
    expect(result.skipResourceParameter).toBe(true)
    expect(result.authorizeResource).toBeUndefined()
  })

  it('Scenario: Treat an empty --resource as disabling it', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp', '--resource', ''], 'test usage')
    expect(result.skipResourceParameter).toBe(true)
    expect(result.authorizeResource).toBeUndefined()
  })

  it('Scenario: Disabling wins over an explicit resource, without splitting the cache', async () => {
    const withBoth = await parseCommandLineArgs(
      ['https://example.com/mcp', '--resource', 'https://tenant.example.com/', '--disable-resource-parameter'],
      'test usage',
    )
    const withDisableOnly = await parseCommandLineArgs(['https://example.com/mcp', '--disable-resource-parameter'], 'test usage')

    expect(withBoth.skipResourceParameter).toBe(true)
    expect(withBoth.authorizeResource).toBeUndefined()
    // Both send identical requests, so they must share one credential cache
    expect(withBoth.serverUrlHash).toBe(withDisableOnly.serverUrlHash)
  })

  it('Scenario: Existing caches are unaffected when no resource flags are used', async () => {
    const result = await parseCommandLineArgs(['https://example.com/mcp'], 'test usage')
    expect(result.serverUrlHash).toBe(getServerUrlHash('https://example.com/mcp', undefined, {}))
  })
})
