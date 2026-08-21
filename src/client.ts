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
  debugLog,
  MCP_REMOTE_VERSION,
  connectToRemoteServer,
  TransportStrategy,
  discoverOAuthServerInfo,
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
  authTimeoutMs: number,
  serverUrlHash: string,
) {
  // Set up event emitter for auth flow
  const events = new EventEmitter()

  // Create a lazy auth coordinator
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs)

  // Discover OAuth server info via Protected Resource Metadata (RFC 9728)
  // This probes the MCP server for WWW-Authenticate header and fetches PRM
  log('Discovering OAuth server configuration...')
  const discoveryResult = await discoverOAuthServerInfo(serverUrl, headers)

  if (discoveryResult.protectedResourceMetadata) {
    log(`Discovered authorization server: ${discoveryResult.authorizationServerUrl}`)
    if (discoveryResult.protectedResourceMetadata.scopes_supported) {
      debugLog('Protected Resource Metadata scopes', {
        scopes_supported: discoveryResult.protectedResourceMetadata.scopes_supported,
      })
    }
  } else {
    debugLog('No Protected Resource Metadata found, using server URL as authorization server')
  }

  // Keep track of the callback server instance for cleanup.
  let server: any = null

  // Create the OAuth client provider with discovered server info
  const authProvider = new NodeOAuthClientProvider({
    serverUrl: discoveryResult.authorizationServerUrl,
    callbackPort,
    host,
    clientName: 'MCP CLI Client',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
    authTimeoutMs,
    prepareAuthorization: async () => {
      const authState = await authCoordinator.initializeAuth()
      server = authState.server
      if (!authState.skipBrowserAuth) {
        authState.beginAuthorization()
      }
      return { skipBrowserAuth: authState.skipBrowserAuth }
    },
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

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, reconnect with its persisted token.
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk...')
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      waitForSharedAuthorization: authState.waitForSharedAuthorization,
      markAuthCompleted: authState.markAuthCompleted,
      abortAuthorization: authState.abortAuthorization,
      authTimeoutMs: authState.authTimeoutMs,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication
    const transport = await connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy)

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
  .then(
    ({
      serverUrl,
      callbackPort,
      headers,
      transportStrategy,
      host,
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authTimeoutMs,
      serverUrlHash,
    }) => {
      return runClient(
        serverUrl,
        callbackPort,
        headers,
        transportStrategy,
        host,
        staticOAuthClientMetadata,
        staticOAuthClientInfo,
        authTimeoutMs,
        serverUrlHash,
      )
    },
  )
  .catch((error) => {
    console.error('Fatal error:', error)
    process.exit(1)
  })
