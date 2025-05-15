#!/usr/bin/env node

/**
 * MCP Proxy with OAuth support
 * A bidirectional proxy between a local STDIO MCP server and a remote SSE server with OAuth authentication.
 *
 * Run with: npx tsx proxy.ts https://example.remote/server [callback-port]
 *
 * If callback-port is not specified, an available port will be automatically selected.
 */

import { EventEmitter } from 'events'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  connectToRemoteServer,
  log,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  getServerUrlHash,
  MCP_REMOTE_VERSION,
  TransportStrategy,
} from './lib/utils'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { createLazyAuthCoordinator } from './lib/coordination'

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPort: number,
  headers: Record<string, string>,
  transportStrategy: TransportStrategy = 'http-first',
  shortTimeout: boolean = false,
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
    clientName: 'MCP CLI Proxy',
  })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Keep track of the server instance for cleanup
  let server: any = null

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, just log that we'll use the auth from disk
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk')
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
    const remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy, shortTimeout)

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
    })

    // Start the local STDIO server
    await localTransport.start()
    log('Local STDIO server running')
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
    log('Press Ctrl+C to exit')

    // Setup cleanup handler
    const cleanup = async () => {
      await remoteTransport.close()
      await localTransport.close()
      // Only close the server if it was initialized
      if (server) {
        server.close()
      }
    }
    setupSignalHandlers(cleanup)
  } catch (error) {
    log('Fatal error:', error)
    if (error instanceof Error && error.message.includes('self-signed certificate in certificate chain')) {
      log(`You may be behind a VPN!

If you are behind a VPN, you can try setting the NODE_EXTRA_CA_CERTS environment variable to point
to the CA certificate file. If using claude_desktop_config.json, this might look like:

{
  "mcpServers": {
    "\${mcpServerName}": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://remote.mcp.server/sse"
      ],
      "env": {
        "NODE_EXTRA_CA_CERTS": "\${your CA certificate file path}.pem"
      }
    }
  }
}
        `)
    }
    // Only close the server if it was initialized
    if (server) {
      server.close()
    }
    process.exit(1)
  }
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx proxy.ts <https://server-url> [callback-port]')
  .then(({ serverUrl, callbackPort, headers, transportStrategy, shortTimeout }) => {
    return runProxy(serverUrl, callbackPort, headers, transportStrategy, shortTimeout)
  })
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
