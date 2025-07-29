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
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import { createLazyAuthCoordinator } from './lib/coordination'

/**
 * Main function to run the client
 */
async function runClient(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  host: string,
  staticOAuthClientMetadata: StaticOAuthClientMetadata,
  staticOAuthClientInfo: StaticOAuthClientInformationFull,
  insecure: boolean = false,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Get the server URL hash for lockfile operations
  const serverUrlHash = getServerUrlHash(serverUrl)

  // Create a lazy auth coordinator
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events)

  // Create the OAuth client provider
  const authProvider = new NodeOAuthClientProvider({
    serverUrl,
    callbackPort,
    host,
    clientName: 'MCP CLI Client',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
  })

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

  // Keep track of the server instance for cleanup
  let server: any = null

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, just log that we'll use the auth from disk
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk...')
      // TODO: remove, the callback is happening before the tokens are exchanged
      //  so we're slightly too early
      await new Promise((res) => setTimeout(res, 1_000))
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication
    const transport = await connectToRemoteServer(
      client,
      serverUrl,
      authProvider,
      headers,
      authInitializer,
      transportStrategy,
      new Set(),
      insecure,
    )

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
      // If auth was initialized and server was created, close it
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)

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

    // log('Listening for messages. Press Ctrl+C to exit.')
    log('Exiting OK...')
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(0)
  } catch (error) {
    log('Fatal error:', error)
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the client
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx client.ts <https://server-url> [callback-port] [--debug]')
  .then(({ serverUrl, callbackPort, headers, transportStrategy, host, staticOAuthClientMetadata, staticOAuthClientInfo, insecure }) => {
    return runClient(serverUrl, callbackPort, headers, transportStrategy, host, staticOAuthClientMetadata, staticOAuthClientInfo, insecure)
  })
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
