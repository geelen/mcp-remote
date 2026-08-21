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
import { OAuthTokens, OAuthTokensSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import {
  connectToRemoteServer,
  log,
  debugLog,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers,
  TransportStrategy,
  discoverOAuthServerInfo,
  createDeferredMcpBridge,
} from './lib/utils'
import { StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './lib/types'
import { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
import { createLazyAuthCoordinator } from './lib/coordination'
import { readJsonFile } from './lib/mcp-auth-config'

/**
 * Main function to run the proxy
 */
async function runProxy(
  serverUrl: string,
  callbackPort: number,
  specifiedPort: number | undefined,
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

  const strictPort = !!specifiedPort || !!staticOAuthClientInfo

  // Create a lazy auth coordinator
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs, strictPort)

  // Probe the on-disk token cache BEFORE running OAuth discovery. If a valid
  // access token already exists, we can use the original synchronous flow
  // (warm path) without any behavioural change. Otherwise — first attach or
  // expired tokens — we switch to the deferred bridge so the MCP client's
  // 60s initialize timeout never fires while OAuth runs.
  const cachedTokens = await readJsonFile<OAuthTokens>(serverUrlHash, 'tokens.json', OAuthTokensSchema).catch(() => undefined)
  const TOKEN_GRACE_SECONDS = 30
  const warmCache = !!(cachedTokens && typeof cachedTokens.expires_in === 'number' && cachedTokens.expires_in > TOKEN_GRACE_SECONDS)
  debugLog('Token cache probe', { warmCache, hasTokens: !!cachedTokens, expiresIn: cachedTokens?.expires_in })

  // Create the STDIO transport for local connections
  const localTransport = new StdioServerTransport()

  // Keep track of the OAuth callback server instance for cleanup
  let server: any = null

  // Define an auth initializer function (shared by both warm and cold paths)
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth()

    // Store server in outer scope for cleanup
    server = authState.server

    // If the callback server bound to a different port (EADDRINUSE fallback), update the provider
    if (authState.actualPort !== callbackPort) {
      log(`Callback port changed from ${callbackPort} to ${authState.actualPort} (original port was unavailable)`)
      authProvider.setCallbackPort(authState.actualPort)
      if (!staticOAuthClientInfo) {
        log('Invalidating cached client registration so it re-registers with the new redirect_uri')
        await authProvider.invalidateCredentials('client')
      }
    }

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

  // Build the authProvider after running OAuth server discovery. Returns the
  // remote transport once connected. Used by both warm and cold paths.
  const discoverAndConnect = async () => {
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
    })

    return connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy)
  }

  const fatalErrorHint = (error: unknown) => {
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
  }

  // Holder so the cleanup handler can close the remote even when it is
  // attached asynchronously after OAuth completes (cold path).
  let remoteTransportRef: { current: Awaited<ReturnType<typeof discoverAndConnect>> | null } = { current: null }

  const cleanup = async () => {
    if (remoteTransportRef.current) {
      await remoteTransportRef.current.close().catch(() => {})
    }
    await localTransport.close().catch(() => {})
    if (server) {
      server.close()
    }
  }
  setupSignalHandlers(cleanup)

  if (warmCache) {
    // === Warm path (behaviour-preserving for cached users) ===
    try {
      const remoteTransport = await discoverAndConnect()
      remoteTransportRef.current = remoteTransport

      mcpProxy({
        transportToClient: localTransport,
        transportToServer: remoteTransport,
        ignoredTools,
      })

      await localTransport.start()
      log('Local STDIO server running (warm-cache path)')
      log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`)
      log('Press Ctrl+C to exit')
    } catch (error) {
      log('Fatal error:', error)
      fatalErrorHint(error)
      if (server) server.close()
      process.exit(1)
    }
    return
  }

  // === Cold path (no/expired tokens) — deferred bridge ===
  // Start the local STDIO transport IMMEDIATELY with a pre-handshake handler
  // so the MCP client's `initialize` request gets answered locally (with
  // empty capabilities + listChanged:true) within milliseconds, well under
  // the 60 s client-side timeout. OAuth + remote connect run in background.
  const bridge = createDeferredMcpBridge({ transportToClient: localTransport, ignoredTools })

  await localTransport.start()
  log('Local STDIO server running (deferred bridge — answering initialize while OAuth completes in background)')
  log('Press Ctrl+C to exit')

  discoverAndConnect()
    .then(async (remoteTransport) => {
      remoteTransportRef.current = remoteTransport
      try {
        await bridge.attachRemote(remoteTransport)
        log(`Proxy established (deferred path) between local STDIO and remote ${remoteTransport.constructor.name}`)
      } catch (attachErr) {
        log('Failed to attach remote after OAuth:', attachErr)
        bridge.fail(attachErr instanceof Error ? attachErr : new Error(String(attachErr)))
      }
    })
    .catch((error) => {
      log('Remote connect / OAuth failed:', error)
      fatalErrorHint(error)
      bridge.fail(error instanceof Error ? error : new Error(String(error)))
    })
}

// Parse command-line arguments and run the proxy
parseCommandLineArgs(process.argv.slice(2), 'Usage: mcp-remote <https://server-url> [callback-port] [--debug]')
  .then(
    ({
      serverUrl,
      callbackPort,
      specifiedPort,
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
        specifiedPort,
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
