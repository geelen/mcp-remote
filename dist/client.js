#!/usr/bin/env node
import {
  Client,
  ListResourcesResultSchema,
  ListToolsResultSchema,
  NodeOAuthClientProvider,
  connectToRemoteServer,
  createLazyAuthCoordinator,
  debugLog,
  fetchAuthorizationServerMetadata,
  log,
  parseCommandLineArgs,
  setupSignalHandlers,
  version
} from "./chunk-2DBJLY3Y.js";

// src/client.ts
import { EventEmitter } from "events";
async function runClient(serverUrl, callbackPort, headers, transportStrategy = "http-first", host, staticOAuthClientMetadata, staticOAuthClientInfo, authTimeoutMs, serverUrlHash) {
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
    clientName: "MCP CLI Client",
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    serverUrlHash,
    authorizationServerMetadata
  });
  const client = new Client(
    {
      name: "mcp-remote",
      version
    },
    {
      capabilities: {}
    }
  );
  let server = null;
  const authInitializer = async () => {
    const authState = await authCoordinator.initializeAuth();
    server = authState.server;
    if (authState.skipBrowserAuth) {
      log("Authentication was completed by another instance - will use tokens from disk...");
      await new Promise((res) => setTimeout(res, 1e3));
    }
    return {
      waitForAuthCode: authState.waitForAuthCode,
      skipBrowserAuth: authState.skipBrowserAuth
    };
  };
  try {
    const transport = await connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy);
    transport.onmessage = (message) => {
      log("Received message:", JSON.stringify(message, null, 2));
    };
    transport.onerror = (error) => {
      log("Transport error:", error);
    };
    transport.onclose = () => {
      log("Connection closed.");
      process.exit(0);
    };
    const cleanup = async () => {
      log("\nClosing connection...");
      await client.close();
      if (server) {
        server.close();
      }
    };
    setupSignalHandlers(cleanup);
    log("Connected successfully!");
    try {
      log("Requesting tools list...");
      const tools = await client.request({ method: "tools/list" }, ListToolsResultSchema);
      log("Tools:", JSON.stringify(tools, null, 2));
    } catch (e) {
      log("Error requesting tools list:", e);
    }
    try {
      log("Requesting resource list...");
      const resources = await client.request({ method: "resources/list" }, ListResourcesResultSchema);
      log("Resources:", JSON.stringify(resources, null, 2));
    } catch (e) {
      log("Error requesting resources list:", e);
    }
    log("Exiting OK...");
    if (server) {
      server.close();
    }
    process.exit(0);
  } catch (error) {
    log("Fatal error:", error);
    if (server) {
      server.close();
    }
    process.exit(1);
  }
}
parseCommandLineArgs(process.argv.slice(2), "Usage: npx tsx client.ts <https://server-url> [callback-port] [--debug]").then(
  ({
    serverUrl,
    callbackPort,
    headers,
    transportStrategy,
    host,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authTimeoutMs,
    serverUrlHash
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
      serverUrlHash
    );
  }
).catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
