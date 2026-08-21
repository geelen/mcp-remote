import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  parseCommandLineArgs,
  shouldIncludeTool,
  mcpProxy,
  setupOAuthCallbackServerWithLongPoll,
  getServerUrlHash,
  createDeferredMcpBridge,
} from './utils'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { EventEmitter } from 'events'
import express from 'express'
import net from 'net'

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

  it('Scenario: Failed forward of a request surfaces a JSON-RPC error to the client', async () => {
    // Given a server transport whose send() rejects, e.g. because the
    // server expired the session and answers HTTP 404 (issue #106)
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

    // When the client sends a request (a message with an id)
    const clientRequest = {
      jsonrpc: '2.0' as const,
      method: 'tools/call',
      id: 42,
      params: { name: 'SomeTool', arguments: {} },
    }
    if (mockTransportToClient.onmessage) {
      mockTransportToClient.onmessage(clientRequest)
    }

    // Then the client receives a JSON-RPC error response for that id
    // instead of waiting forever for a reply that never arrives
    await vi.waitFor(() => {
      expect(mockTransportToClient.send).toHaveBeenCalledWith(
        expect.objectContaining({
          jsonrpc: '2.0',
          id: 42,
          error: expect.objectContaining({
            code: -32603,
            message: expect.stringContaining('HTTP 404'),
          }),
        }),
      )
    })
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
    })

    server = result.server
    const boundPort = (server.address() as net.AddressInfo).port
    expect(result.actualPort).toBe(boundPort)
    expect(result.actualPort).toBeGreaterThan(0)
  })

  it('should fall back to a random port when the requested port is already in use', async () => {
    // Hold a port so the callback server cannot bind to it
    const blocker = net.createServer()
    const blockedPort = await new Promise<number>((resolve) => {
      blocker.listen(0, '127.0.0.1', () => resolve((blocker.address() as net.AddressInfo).port))
    })

    try {
      const result = await setupOAuthCallbackServerWithLongPoll({
        port: blockedPort,
        path: '/oauth/callback',
        events,
      })

      server = result.server
      expect(result.actualPort).toBeGreaterThan(0)
      expect(result.actualPort).not.toBe(blockedPort)
    } finally {
      await new Promise<void>((resolve) => blocker.close(() => resolve()))
    }
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
          strictPort: true,
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

describe('Feature: Deferred MCP bridge (respond to initialize before OAuth completes)', () => {
  const makeMockTransport = () =>
    ({
      send: vi.fn().mockResolvedValue(undefined),
      close: vi.fn().mockResolvedValue(undefined),
      start: vi.fn().mockResolvedValue(undefined),
      onmessage: vi.fn(),
      onclose: vi.fn(),
      onerror: vi.fn(),
    }) as unknown as Transport

  const findSentMessage = (transport: Transport, matcher: (msg: any) => boolean): any | undefined => {
    const sendMock = transport.send as unknown as ReturnType<typeof vi.fn>
    return sendMock.mock.calls.map((c) => c[0]).find(matcher)
  }

  it('Scenario: Answer initialize locally within milliseconds while remote OAuth pends', async () => {
    // Given a local STDIO transport awaiting a deferred bridge (cold cache, OAuth not done yet)
    const transportToClient = makeMockTransport()
    createDeferredMcpBridge({ transportToClient, ignoredTools: [] })

    // When the client sends the JSON-RPC initialize request
    const initializeMessage = {
      jsonrpc: '2.0' as const,
      method: 'initialize',
      id: 'init-1',
      params: {
        protocolVersion: '2025-03-26',
        clientInfo: { name: 'Claude Desktop', version: '0.9.0' },
        capabilities: {},
      },
    }
    const t0 = Date.now()
    transportToClient.onmessage!(initializeMessage as any)
    // Drain microtasks so async send() resolves
    await Promise.resolve()
    const elapsed = Date.now() - t0

    // Then a valid initialize response is sent back to the client within 1s,
    // declaring empty capabilities with listChanged: true on all three lists.
    expect(elapsed).toBeLessThan(1000)
    expect(transportToClient.send).toHaveBeenCalledWith(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: 'init-1',
        result: expect.objectContaining({
          protocolVersion: '2025-03-26',
          capabilities: expect.objectContaining({
            tools: { listChanged: true },
            resources: { listChanged: true },
            prompts: { listChanged: true },
          }),
          serverInfo: expect.objectContaining({ name: 'mcp-remote' }),
        }),
      }),
    )
  })

  it('Scenario: Pre-handshake list requests return empty results, not errors', async () => {
    // Given a bridge that has answered initialize
    const transportToClient = makeMockTransport()
    createDeferredMcpBridge({ transportToClient, ignoredTools: [] })
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'initialize', id: 'i', params: {} } as any)

    // When the client asks for tools, resources, prompts and resource templates
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'tools/list', id: 't' } as any)
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'resources/list', id: 'r' } as any)
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'prompts/list', id: 'p' } as any)
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'resources/templates/list', id: 'rt' } as any)
    await Promise.resolve()

    // Then each gets an empty-list result (not -32002, otherwise Claude shows a red banner)
    const toolsReply = findSentMessage(transportToClient, (m) => m.id === 't')
    expect(toolsReply).toEqual(expect.objectContaining({ result: { tools: [] } }))
    expect(toolsReply.error).toBeUndefined()
    expect(findSentMessage(transportToClient, (m) => m.id === 'r')).toEqual(expect.objectContaining({ result: { resources: [] } }))
    expect(findSentMessage(transportToClient, (m) => m.id === 'p')).toEqual(expect.objectContaining({ result: { prompts: [] } }))
    expect(findSentMessage(transportToClient, (m) => m.id === 'rt')).toEqual(expect.objectContaining({ result: { resourceTemplates: [] } }))
  })

  it('Scenario: Pre-handshake tools/call rejects with a clear -32002 error', async () => {
    const transportToClient = makeMockTransport()
    createDeferredMcpBridge({ transportToClient, ignoredTools: [] })
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'initialize', id: 'i', params: {} } as any)

    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'tools/call',
      id: 'call-1',
      params: { name: 'doStuff', arguments: {} },
    } as any)
    await Promise.resolve()

    const reply = findSentMessage(transportToClient, (m) => m.id === 'call-1')
    expect(reply).toEqual(
      expect.objectContaining({
        jsonrpc: '2.0',
        id: 'call-1',
        error: expect.objectContaining({ code: -32002, message: expect.stringContaining('not yet authorized') }),
      }),
    )
  })

  it('Scenario: Slow 90s OAuth — initialize still <1s, list_changed sent once remote attached', async () => {
    // Given a bridge with a slow upstream (simulating 90s OAuth — well past the
    // 60s client timeout that would have killed the proxy in the old design)
    const transportToClient = makeMockTransport()
    const remoteTransport = makeMockTransport()
    const bridge = createDeferredMcpBridge({ transportToClient, ignoredTools: [] })

    // When the client sends initialize first
    const t0 = Date.now()
    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'initialize',
      id: 'init',
      params: { protocolVersion: '2024-11-05', clientInfo: { name: 'C', version: '1' }, capabilities: {} },
    } as any)
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'notifications/initialized' } as any)
    await Promise.resolve()
    const initElapsed = Date.now() - t0
    expect(initElapsed).toBeLessThan(1000)
    expect(findSentMessage(transportToClient, (m) => m.id === 'init')).toBeDefined()

    // And then upstream takes 90 simulated seconds to come up
    // (we just delay before calling attachRemote)
    // Set up the remote transport to ACK our synthetic initialize promptly.
    const sendMock = remoteTransport.send as unknown as ReturnType<typeof vi.fn>
    sendMock.mockImplementation(async (msg: any) => {
      if (msg.method === 'initialize') {
        // Fire ack on the next microtask, advertising all three capabilities so
        // the bridge emits all three list_changed notifications.
        queueMicrotask(() => {
          remoteTransport.onmessage!({
            jsonrpc: '2.0',
            id: msg.id,
            result: { capabilities: { tools: {}, resources: {}, prompts: {} } },
          } as any)
        })
      }
    })

    await bridge.attachRemote(remoteTransport)

    // Then the bridge sent our synthetic initialize upstream
    expect(sendMock).toHaveBeenCalledWith(
      expect.objectContaining({
        method: 'initialize',
        params: expect.objectContaining({
          clientInfo: expect.objectContaining({ name: expect.stringContaining('via mcp-remote') }),
        }),
      }),
    )
    // And forwarded notifications/initialized upstream
    expect(sendMock).toHaveBeenCalledWith(expect.objectContaining({ method: 'notifications/initialized' }))
    // And told the client to refresh its lists
    const clientSendMock = transportToClient.send as unknown as ReturnType<typeof vi.fn>
    const sentMethods = clientSendMock.mock.calls.map((c) => c[0]?.method).filter(Boolean)
    expect(sentMethods).toContain('notifications/tools/list_changed')
    expect(sentMethods).toContain('notifications/resources/list_changed')
    expect(sentMethods).toContain('notifications/prompts/list_changed')
  }, 15_000)

  it('Scenario: capability mirroring — upstream advertises only tools, bridge skips resources/prompts list_changed', async () => {
    const transportToClient = makeMockTransport()
    const remoteTransport = makeMockTransport()
    const bridge = createDeferredMcpBridge({ transportToClient, ignoredTools: [] })

    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'initialize',
      id: 'init',
      params: { protocolVersion: '2024-11-05', clientInfo: { name: 'C', version: '1' }, capabilities: {} },
    } as any)
    await Promise.resolve()

    const sendMock = remoteTransport.send as unknown as ReturnType<typeof vi.fn>
    sendMock.mockImplementation(async (msg: any) => {
      if (msg.method === 'initialize') {
        queueMicrotask(() => {
          remoteTransport.onmessage!({
            jsonrpc: '2.0',
            id: msg.id,
            // Tools-only server (e.g. SpeakUp's own MCP server)
            result: { capabilities: { tools: {} } },
          } as any)
        })
      }
    })

    await bridge.attachRemote(remoteTransport)

    // Then only tools/list_changed is emitted; resources/prompts list_changed is skipped
    const clientSendMock = transportToClient.send as unknown as ReturnType<typeof vi.fn>
    const sentMethods = clientSendMock.mock.calls.map((c) => c[0]?.method).filter(Boolean)
    expect(sentMethods).toContain('notifications/tools/list_changed')
    expect(sentMethods).not.toContain('notifications/resources/list_changed')
    expect(sentMethods).not.toContain('notifications/prompts/list_changed')

    // And post-attach, resources/list / prompts/list are short-circuited to empty
    // by the capability filter (instead of forwarding upstream for a -32601)
    clientSendMock.mockClear()
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'resources/list', id: 'rl' } as any)
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'prompts/list', id: 'pl' } as any)
    await Promise.resolve()

    expect(findSentMessage(transportToClient, (m) => m.id === 'rl')).toEqual(expect.objectContaining({ result: { resources: [] } }))
    expect(findSentMessage(transportToClient, (m) => m.id === 'pl')).toEqual(expect.objectContaining({ result: { prompts: [] } }))
    // And those calls were NOT forwarded to the remote (would have been a -32601 round-trip)
    const remoteMethodsAfter = sendMock.mock.calls.map((c) => c[0]?.method).filter(Boolean)
    expect(remoteMethodsAfter).not.toContain('resources/list')
    expect(remoteMethodsAfter).not.toContain('prompts/list')
  })

  it('Scenario: remote closes mid-handshake — attachRemote rejects fast instead of waiting 30s', async () => {
    const transportToClient = makeMockTransport()
    const remoteTransport = makeMockTransport()
    const bridge = createDeferredMcpBridge({ transportToClient, ignoredTools: [] })

    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'initialize',
      id: 'init',
      params: { protocolVersion: '2024-11-05', clientInfo: { name: 'C', version: '1' }, capabilities: {} },
    } as any)
    await Promise.resolve()

    // Simulate the remote socket closing right after we send initialize upstream
    const sendMock = remoteTransport.send as unknown as ReturnType<typeof vi.fn>
    sendMock.mockImplementation(async (msg: any) => {
      if (msg.method === 'initialize') {
        queueMicrotask(() => {
          if (remoteTransport.onclose) remoteTransport.onclose()
        })
      }
    })

    const t0 = Date.now()
    await expect(bridge.attachRemote(remoteTransport)).rejects.toThrow(/closed during upstream initialize/)
    const elapsed = Date.now() - t0
    expect(elapsed).toBeLessThan(5000) // not 30s
  })

  it('Scenario: post-attach list_changed send fails → bridge closes local transport so client reconnects', async () => {
    const transportToClient = makeMockTransport()
    const remoteTransport = makeMockTransport()
    const bridge = createDeferredMcpBridge({ transportToClient, ignoredTools: [] })

    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'initialize',
      id: 'init',
      params: { protocolVersion: '2024-11-05', clientInfo: { name: 'C', version: '1' }, capabilities: {} },
    } as any)
    await Promise.resolve()

    // Upstream acks normally with all 3 caps
    const sendMock = remoteTransport.send as unknown as ReturnType<typeof vi.fn>
    sendMock.mockImplementation(async (msg: any) => {
      if (msg.method === 'initialize') {
        queueMicrotask(() => {
          remoteTransport.onmessage!({
            jsonrpc: '2.0',
            id: msg.id,
            result: { capabilities: { tools: {}, resources: {}, prompts: {} } },
          } as any)
        })
      }
    })

    // But the local client send pipe breaks right when we try to emit list_changed.
    // The initialize reply already went out via the pre-handshake handler before
    // we install this failure, so we only fail later sends.
    const clientSendMock = transportToClient.send as unknown as ReturnType<typeof vi.fn>
    let callCount = 0
    clientSendMock.mockImplementation(async (msg: any) => {
      callCount++
      if (msg?.method?.includes('list_changed')) {
        throw new Error('local pipe closed (EPIPE)')
      }
    })

    await expect(bridge.attachRemote(remoteTransport)).rejects.toThrow(/EPIPE/)
    // Bridge closed the local transport so the MCP client reconnects cleanly
    // instead of being stuck with the empty lists we replied with pre-handshake.
    expect(transportToClient.close).toHaveBeenCalled()
    expect(callCount).toBeGreaterThan(0)
  })

  it('Scenario: fail() makes subsequent client requests return a structured error', async () => {
    const transportToClient = makeMockTransport()
    const bridge = createDeferredMcpBridge({ transportToClient, ignoredTools: [] })
    transportToClient.onmessage!({ jsonrpc: '2.0', method: 'initialize', id: 'i', params: {} } as any)
    await Promise.resolve()

    bridge.fail(new Error('Browser closed without completing OAuth'))

    transportToClient.onmessage!({
      jsonrpc: '2.0',
      method: 'tools/call',
      id: 'call-after-fail',
      params: { name: 'x' },
    } as any)
    await Promise.resolve()

    const reply = findSentMessage(transportToClient, (m) => m.id === 'call-after-fail')
    expect(reply?.error).toEqual(
      expect.objectContaining({
        code: -32002,
        message: expect.stringContaining('authorization failed'),
      }),
    )
    expect(reply?.error.message).toContain('Browser closed without completing OAuth')
  })
})
