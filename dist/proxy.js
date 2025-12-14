#!/usr/bin/env node
import {
  JSONRPCMessageSchema,
  NodeOAuthClientProvider,
  connectToRemoteServer,
  createLazyAuthCoordinator,
  debugLog,
  fetchAuthorizationServerMetadata,
  log,
  mcpProxy,
  parseCommandLineArgs,
  setupSignalHandlers
} from "./chunk-2DBJLY3Y.js";

// src/proxy.ts
import { EventEmitter } from "events";

// node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js
import process2 from "process";

// node_modules/@modelcontextprotocol/sdk/dist/esm/shared/stdio.js
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

// node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js
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
      var _a;
      (_a = this.onerror) === null || _a === void 0 ? void 0 : _a.call(this, error);
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
    var _a, _b;
    while (true) {
      try {
        const message = this._readBuffer.readMessage();
        if (message === null) {
          break;
        }
        (_a = this.onmessage) === null || _a === void 0 ? void 0 : _a.call(this, message);
      } catch (error) {
        (_b = this.onerror) === null || _b === void 0 ? void 0 : _b.call(this, error);
      }
    }
  }
  async close() {
    var _a;
    this._stdin.off("data", this._ondata);
    this._stdin.off("error", this._onerror);
    const remainingDataListeners = this._stdin.listenerCount("data");
    if (remainingDataListeners === 0) {
      this._stdin.pause();
    }
    this._readBuffer.clear();
    (_a = this.onclose) === null || _a === void 0 ? void 0 : _a.call(this);
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
async function runProxy(serverUrl, callbackPort, headers, transportStrategy = "http-first", host, staticOAuthClientMetadata, staticOAuthClientInfo, authorizeResource, ignoredTools, authTimeoutMs, serverUrlHash, reconnectOptions) {
  const events = new EventEmitter();
  const authCoordinator = createLazyAuthCoordinator(serverUrlHash, callbackPort, events, authTimeoutMs);
  let authorizationServerMetadata;
  try {
    authorizationServerMetadata = await fetchAuthorizationServerMetadata(serverUrl);
    if (authorizationServerMetadata?.scopes_supported) {
      debugLog("Pre-fetched authorization server metadata", {
        scopes_supported: authorizationServerMetadata.scopes_supported
      });
    }
  } catch (error) {
    debugLog("Failed to pre-fetch authorization server metadata", error);
  }
  const authProvider = new NodeOAuthClientProvider({
    serverUrl,
    callbackPort,
    host,
    clientName: "MCP CLI Proxy",
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    serverUrlHash,
    authorizationServerMetadata
  });
  const localTransport = new StdioServerTransport();
  let server = null;
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth();
    server = authState.server;
    if (authState.skipBrowserAuth) {
      log("Authentication was completed by another instance - will use tokens from disk");
      await new Promise((res) => setTimeout(res, 1e3));
    }
    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth
    };
  };
  try {
    const remoteTransport = await connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy);
    const reconnectFn = async () => {
      log("Creating new connection to remote server...");
      return connectToRemoteServer(null, serverUrl, authProvider, headers, authInitializer, transportStrategy);
    };
    mcpProxy({
      transportToClient: localTransport,
      transportToServer: remoteTransport,
      ignoredTools,
      reconnectFn,
      reconnectOptions
    });
    await localTransport.start();
    log("Local STDIO server running");
    log(`Proxy established successfully between local STDIO and remote ${remoteTransport.constructor.name}`);
    if (reconnectOptions.enabled) {
      log(`Auto-reconnect enabled (max ${reconnectOptions.maxAttempts} attempts, base delay ${reconnectOptions.baseDelayMs}ms)`);
    }
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
    serverUrlHash,
    reconnectOptions
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
      reconnectOptions
    );
  }
).catch((error) => {
  log("Fatal error:", error);
  process.exit(1);
});
