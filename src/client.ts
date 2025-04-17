#!/usr/bin/env node

/**
 * MCP Client with OAuth support
 * A command-line client that connects to an MCP server using SSE with OAuth authentication.
 *
 * Run with: npx tsx client.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { ListResourcesResultSchema, ListToolsResultSchema } from '@modelcontextprotocol/sdk/types.js'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import {
  parseCommandLineArgs,
  setupSignalHandlers,
  log,
  MCP_REMOTE_VERSION,
  getServerUrlHash,
  connectToRemoteServer,
  TransportStrategy,
} from './lib/utils'
import { coordinateAuth } from './lib/coordination'

/**
 * Main function to run the client
 */
async function runClient(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
) {
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

  try {
    // Connect to remote server with authentication
    const transport = await connectToRemoteServer(serverUrl, authProvider, headers, waitForAuthCode, skipBrowserAuth, transportStrategy)

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

    // Set up cleanup handler
    const cleanup = async () => {
      log('\nClosing connection...')
      await client.close()
      server.close()
    }
    setupSignalHandlers(cleanup)

    // Connect the client
    log('Connecting client...')
    await client.connect(transport)
    log('Connected successfully!')

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
  } catch (error) {
    log('Fatal error:', error)
    server.close()
    process.exit(1)
  }
}

// Parse command-line arguments and run the client
parseCommandLineArgs(process.argv.slice(2), 3333, 'Usage: npx tsx client.ts <https://server-url> [callback-port]')
  .then(({ serverUrl, callbackPort, headers, transportStrategy }) => {
    return runClient(serverUrl, callbackPort, headers, transportStrategy)
  })
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
