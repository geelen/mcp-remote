#!/usr/bin/env node
import {
  JSONRPCMessageSchema,
  NodeOAuthClientProvider,
  OAuthCallbackStateError,
  connectToRemoteServer,
  createLazyAuthCoordinator,
  debugLog,
  discoverOAuthServerInfo,
  finishOAuthCallbackAuthorization,
  log,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers
} from "./chunk-BJUMBZCX.js";

// src/proxy.ts
import { EventEmitter } from "events";

// node_modules/.pnpm/@modelcontextprotocol+sdk@1.25.3_hono@4.11.7_zod@4.1.13/node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js
import process2 from "node:process";

// node_modules/.pnpm/@modelcontextprotocol+sdk@1.25.3_hono@4.11.7_zod@4.1.13/node_modules/@modelcontextprotocol/sdk/dist/esm/shared/stdio.js
var ReadBuffer = class {
  append(chunk) {
    this._buffer = this._buffer ? Buffer.concat([this._buffer, chunk]) : chunk;
  }
  readMessage() {
    if (!this._buffer) {
      return null;
    }
    const index = this._buffer.indexOf("\n");
    if (index === -1) {
      return null;
    }
    const line = this._buffer.toString("utf8", 0, index).replace(/\r$/, "");
    this._buffer = this._buffer.subarray(index + 1);
    return deserializeMessage(line);
  }
  clear() {
    this._buffer = void 0;
  }
};
function deserializeMessage(line) {
  return JSONRPCMessageSchema.parse(JSON.parse(line));
}
function serializeMessage(message) {
  return JSON.stringify(message) + "\n";
}

// node_modules/.pnpm/@modelcontextprotocol+sdk@1.25.3_hono@4.11.7_zod@4.1.13/node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js
var StdioServerTransport = class {
  constructor(_stdin = process2.stdin, _stdout = process2.stdout) {
    this._stdin = _stdin;
    this._stdout = _stdout;
    this._readBuffer = new ReadBuffer();
    this._started = false;
    this._ondata = (chunk) => {
      this._readBuffer.append(chunk);
      this.processReadBuffer();
    };
    this._onerror = (error) => {
      this.onerror?.(error);
    };
  }
  /**
   * Starts listening for messages on stdin.
   */
  async start() {
    if (this._started) {
      throw new Error("StdioServerTransport already started! If using Server class, note that connect() calls start() automatically.");
    }
    this._started = true;
    this._stdin.on("data", this._ondata);
    this._stdin.on("error", this._onerror);
  }
  processReadBuffer() {
    while (true) {
      try {
        const message = this._readBuffer.readMessage();
        if (message === null) {
          break;
        }
        this.onmessage?.(message);
      } catch (error) {
        this.onerror?.(error);
      }
    }
  }
  async close() {
    this._stdin.off("data", this._ondata);
    this._stdin.off("error", this._onerror);
    const remainingDataListeners = this._stdin.listenerCount("data");
    if (remainingDataListeners === 0) {
      this._stdin.pause();
    }
    this._readBuffer.clear();
    this.onclose?.();
  }
  send(message) {
    return new Promise((resolve) => {
      const json = serializeMessage(message);
      if (this._stdout.write(json)) {
        resolve();
      } else {
        this._stdout.once("drain", resolve);
      }
    });
  }
};

// src/proxy.ts
async function runProxy(serverUrl, callbackPort, headers, transportStrategy = "http-first", host, staticOAuthClientMetadata, staticOAuthClientInfo, authorizeResource, ignoredTools, authTimeoutMs, serverUrlHash) {
  const events = new EventEmitter();
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs);
  log("Discovering OAuth server configuration...");
  const discoveryResult = await discoverOAuthServerInfo(serverUrl, headers);
  if (discoveryResult.protectedResourceMetadata) {
    log(`Discovered authorization server: ${discoveryResult.authorizationServerUrl}`);
    if (discoveryResult.protectedResourceMetadata.scopes_supported) {
      debugLog("Protected Resource Metadata scopes", {
        scopes_supported: discoveryResult.protectedResourceMetadata.scopes_supported
      });
    }
  } else {
    debugLog("No Protected Resource Metadata found, using server URL as authorization server");
  }
  let server = null;
  const authProvider = new NodeOAuthClientProvider({
    serverUrl: discoveryResult.authorizationServerUrl,
    callbackPort,
    host,
    clientName: "MCP CLI Proxy",
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    serverUrlHash,
    authorizationServerMetadata: discoveryResult.authorizationServerMetadata,
    protectedResourceMetadata: discoveryResult.protectedResourceMetadata,
    wwwAuthenticateScope: discoveryResult.wwwAuthenticateScope,
    authTimeoutMs,
    prepareAuthorization: async () => {
      const authState = await authCoordinator.initializeAuth();
      server = authState.server;
      if (!authState.skipBrowserAuth) {
        authState.beginAuthorization();
      }
      return { skipBrowserAuth: authState.skipBrowserAuth };
    }
  });
  const localTransport = new StdioServerTransport();
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth();
    server = authState.server;
    if (authState.skipBrowserAuth) {
      log("Authentication was completed by another instance - will use tokens from disk");
    }
    return {
      waitForAuthCode: authState.waitForAuthCode,
      waitForNextAuthCode: authState.waitForNextAuthCode,
      waitForSharedAuthorization: authState.waitForSharedAuthorization,
      markAuthCompleted: authState.markAuthCompleted,
      abortAuthorization: authState.abortAuthorization,
      authTimeoutMs: authState.authTimeoutMs,
      skipBrowserAuth: authState.skipBrowserAuth
    };
  };
  try {
    const remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy);
    let markRecoveredAuthorizationCompleted;
    const authorizationRecovery = async () => {
      const authState = await authInitializer();
      if (authState.skipBrowserAuth) {
        const sharedAuthorizationCompleted = await authState.waitForSharedAuthorization();
        if (!sharedAuthorizationCompleted) {
          throw new Error(`Shared OAuth authorization did not complete within ${authState.authTimeoutMs / 1e3} seconds`);
        }
        log("OAuth was completed by another process; verifying the shared token");
        return;
      }
      const authorizationDeadlineMs = Date.now() + authState.authTimeoutMs;
      const oauthTransport = remoteTransport;
      if (!oauthTransport.finishAuth) {
        throw new Error("Remote transport does not support OAuth authorization completion");
      }
      while (true) {
        const remainingMs = authorizationDeadlineMs - Date.now();
        if (remainingMs <= 0) {
          throw new Error("OAuth authorization deadline expired before token exchange");
        }
        const callback = await authState.waitForNextAuthCode(remainingMs);
        try {
          log("Completing renewed authorization...");
          await finishOAuthCallbackAuthorization(
            authProvider,
            callback,
            oauthTransport.finishAuth.bind(oauthTransport),
            authState.authTimeoutMs,
            authorizationDeadlineMs
          );
        } catch (error) {
          if (error instanceof OAuthCallbackStateError) {
            log("Ignoring stale OAuth callback and waiting for the active authorization");
            continue;
          }
          throw error;
        }
        markRecoveredAuthorizationCompleted = authState.markAuthCompleted;
        break;
      }
      log("Renewed OAuth token; verifying it with the remote MCP server");
    };
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      authorizationRecovery,
      onAuthorizationVerified: async () => {
        await authProvider.markRemoteAuthorizationVerified();
        await markRecoveredAuthorizationCompleted?.();
        markRecoveredAuthorizationCompleted = void 0;
      },
      onAuthorizationRecoveryFailed: async (error) => {
        await authProvider.handleAuthorizationFailure(error);
        await authCoordinator.abortAuthorization();
      }
    });
    await localTransport.start();
    log("Local STDIO server running");
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`);
    log("Press Ctrl+C to exit");
    const cleanup = async () => {
      await remoteTransport.close();
      await localTransport.close();
      if (server) {
        server.close();
      }
    };
    setupSignalHandlers(cleanup);
  } catch (error) {
    log("Fatal error:", error);
    if (error instanceof Error && error.message.includes("self-signed certificate in certificate chain")) {
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
        `);
    }
    if (server) {
      server.close();
    }
    process.exit(1);
  }
}
parseCommandLineArgs(process.argv.slice(2), "Usage: npx tsx proxy.ts <https://server-url> [callback-port] [--debug]").then(
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
    serverUrlHash
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
      serverUrlHash
    );
  }
).catch((error) => {
  log("Fatal error:", error);
  process.exit(1);
});
