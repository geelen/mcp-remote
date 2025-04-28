#!/usr/bin/env node

/**
 * MCP Client with OAuth support
 * A command-line client that connects to an MCP server using StreamableHTTP with OAuth authentication.
 *
 * Run with: npx tsx client.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { ListResourcesResultSchema, ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { parseCommandLineArgs, setupSignalHandlers, log, MCP_REMOTE_VERSION, getServerUrlHash } from './lib/utils'
import { coordinateAuth } from './lib/coordination'

/**
 * Main function to run the client
 */
async function runClient(serverUrl: string, callbackPort: number, headers: Record<string, string>, useStreamableHttp: boolean = false) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Get the server URL hash for lockfile operations
  const serverUrlHash = getServerUrlHash(serverUrl)

  // Coordinate authentication with other instances
  const { server, waitForAuthCode, skipBrowserAuth } = await coordinateAuth(serverUrlHash, callbackPort, events)

  // Create the OAuth client provider
  const authProvider = new NodeOAuthClientProvider({
    serverUrl,
    callbackPort,
    clientName: 'MCP CLI Client',
  })

  // If auth was completed by another instance, just log that we'll use the auth from disk
  if (skipBrowserAuth) {
    log('Authentication was completed by another instance - will use tokens from disk...')
    // TODO: remove, the callback is happening before the tokens are exchanged
    //  so we're slightly too early
    await new Promise((res) => setTimeout(res, 1_000))
  }

  // Create the client
  const client = new Client(
    {
      name: 'mcp-remote',
      version: MCP_REMOTE_VERSION,
    },
    {
      capabilities: {},
    },
  )

  // Create the transport factory
  const url = new URL(serverUrl)
  function initTransport() {
    // Choose between Streamable HTTP or SSE transport based on flag
    const transport = useStreamableHttp 
      ? new StreamableHTTPClientTransport(url, {
          authProvider,
          requestInit: { headers },
          reconnectionOptions: {
            initialReconnectionDelay: 1000,
            maxReconnectionDelay: 10000,
            reconnectionDelayGrowFactor: 1.5,
            maxRetries: 10,
          },
        })
      : new SSEClientTransport(url, {
          authProvider,
          requestInit: { headers }
        })

    // Set up message and error handlers
    transport.onmessage = (message) => {
      log('Received message:', JSON.stringify(message, null, 2))
    }

    transport.onerror = (error) => {
      log('Transport error:', error)
    }

    transport.onclose = () => {
      log('Connection closed.')
      process.exit(0)
    }
    return transport
  }

  const transport = initTransport()

  // Set up cleanup handler
  const cleanup = async () => {
    log('\nClosing connection...')
    await client.close()
    server.close()
  }
  setupSignalHandlers(cleanup)

  // Try to connect
  try {
    log('Connecting to server...')
    await client.connect(transport)
    log('Connected successfully!')
  } catch (error) {
    if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      log('Authentication required. Waiting for authorization...')

      // Wait for the authorization code from the callback or another instance
      const code = await waitForAuthCode()

      try {
        log('Completing authorization...')
        await transport.finishAuth(code)

        // Reconnect after authorization with a new transport
        log('Connecting after authorization...')
        await client.connect(initTransport())

        log('Connected successfully!')

        // Request tools list after auth
        log('Requesting tools list...')
        const tools = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
        log('Tools:', JSON.stringify(tools, null, 2))

        // Request resources list after auth
        log('Requesting resource list...')
        const resources = await client.request({ method: 'resources/list' }, ListResourcesResultSchema)
        log('Resources:', JSON.stringify(resources, null, 2))

        log('Listening for messages. Press Ctrl+C to exit.')
      } catch (authError) {
        log('Authorization error:', authError)
        server.close()
        process.exit(1)
      }
    } else {
      log('Connection error:', error)
      server.close()
      process.exit(1)
    }
  }

  try {
    // Request tools list
    log('Requesting tools list...')
    const tools = await client.request({ method: 'tools/list' }, ListToolsResultSchema)
    log('Tools:', JSON.stringify(tools, null, 2))
  } catch (e) {
    log('Error requesting tools list:', e)
  }

  try {
    // Request resources list
    log('Requesting resource list...')
    const resources = await client.request({ method: 'resources/list' }, ListResourcesResultSchema)
    log('Resources:', JSON.stringify(resources, null, 2))
  } catch (e) {
    log('Error requesting resources list:', e)
  }

  log('Listening for messages. Press Ctrl+C to exit.')
}

// Parse command-line arguments and run the client
parseCommandLineArgs(process.argv.slice(2), 3333, 'Usage: npx tsx client.ts <https://server-url> [callback-port] [--streamableHttp]')
  .then(({ serverUrl, callbackPort, headers, useStreamableHttp }) => {
    return runClient(serverUrl, callbackPort, headers, useStreamableHttp)
  })
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
