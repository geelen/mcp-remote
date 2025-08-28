import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { parseCommandLineArgs, shouldIncludeTool, mcpProxy, setupOAuthCallbackServerWithLongPoll } from './utils'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { EventEmitter } from 'events'
import express from 'express'

// All sanitizeUrl tests have been moved to the strict-url-sanitise package

describe('Feature: Command Line Arguments Parsing', () => {
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
})
