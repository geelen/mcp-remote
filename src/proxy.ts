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
  finishOAuthAuthorization,
  log,
  debugLog,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  TransportStrategy,
  discoverOAuthServerInfo,
} from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
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
  host: string,
  staticOAuthClientMetadata: StaticOAuthClientMetadata,
  staticOAuthClientInfo: StaticOAuthClientInformationFull,
  authorizeResource: string,
  ignoredTools: string[],
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
    clientName: 'MCP CLI Proxy',
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
    prepareAuthorization: async () => {
      const authState = await authCoordinator.initializeAuth()
      server = authState.server
      if (!authState.skipBrowserAuth) {
        authState.beginAuthorization()
      }
      return { skipBrowserAuth: authState.skipBrowserAuth }
    },
  })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Define an auth initializer function
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If auth was completed by another instance, reconnect with its persisted token.
    if (authState.skipBrowserAuth) {
      log('Authentication was completed by another instance - will use tokens from disk')
    }

    return {
      waitForAuthCode: authState.waitForAuthCode,
      waitForNextAuthCode: authState.waitForNextAuthCode,
      waitForSharedAuthorization: authState.waitForSharedAuthorization,
      markAuthCompleted: authState.markAuthCompleted,
      authTimeoutMs: authState.authTimeoutMs,
      skipBrowserAuth: authState.skipBrowserAuth,
    }
  }

  try {
    // Connect to remote server with lazy authentication
    const remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)

    const authorizationRecovery = async () => {
      const authState = await authInitializer()
      if (authState.skipBrowserAuth) {
        const sharedAuthorizationCompleted = await authState.waitForSharedAuthorization()
        if (!sharedAuthorizationCompleted) {
          throw new Error(`Shared OAuth authorization did not complete within ${authState.authTimeoutMs / 1000} seconds`)
        }
        log('OAuth was completed by another process; verifying the shared token')
        return
      }

      const authorizationDeadlineMs = Date.now() + authState.authTimeoutMs
      const code = await authState.waitForNextAuthCode()
      const oauthTransport = remoteTransport as typeof remoteTransport & {
        finishAuth?: (authorizationCode: string) => Promise<void>
      }
      if (!oauthTransport.finishAuth) {
        throw new Error('Remote transport does not support OAuth authorization completion')
      }
      log('Completing renewed authorization...')
      await finishOAuthAuthorization(oauthTransport.finishAuth.bind(oauthTransport), code, authState.authTimeoutMs, authorizationDeadlineMs)
      authState.markAuthCompleted()
      log('Renewed OAuth token; verifying it with the remote MCP server')
    }

    // Set up bidirectional proxy between local and remote transports
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      authorizationRecovery,
      onAuthorizationVerified: () => authProvider.markRemoteAuthorizationVerified(),
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
parseCommandLineArgs(process.argv.slice(2), 'Usage: npx tsx proxy.ts <https://server-url> [callback-port] [--debug]')
  .then(
    ({
      serverUrl,
      callbackPort,
      headers,
      transportStrategy,
      host,
      debug,
      staticOAuthClientMetadata,
      staticOAuthClientInfo,
      authorizeResource,
      ignoredTools,
      authTimeoutMs,
      serverUrlHash,
    }) => {
      return runProxy(
        serverUrl,
        callbackPort,
        headers,
        transportStrategy,
        host,
        staticOAuthClientMetadata,
        staticOAuthClientInfo,
        authorizeResource,
        ignoredTools,
        authTimeoutMs,
        serverUrlHash,
      )
    },
  )
  .catch((error) => {
    log('Fatal error:', error)
    process.exit(1)
  })
