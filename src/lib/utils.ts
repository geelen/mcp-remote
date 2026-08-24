import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { OAuthClientInformationFull, OAuthClientInformationFullSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthCallbackServerOptions, StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './types'
import { getConfigDir, getConfigFilePath, readJsonFile } from './mcp-auth-config'
import {
  discoverProtectedResourceMetadata,
  parseWWWAuthenticateHeader,
  getAuthorizationServerUrl,
  type ProtectedResourceMetadata,
} from './protected-resource-metadata'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import express from 'express'
import net, { AddressInfo } from 'net'
import { Server } from 'http'
import crypto from 'crypto'
import fs from 'fs'
import { readFile, rm } from 'fs/promises'
import path from 'path'
import { version as MCP_REMOTE_VERSION } from '../../package.json'
import { EnvHttpProxyAgent, fetch, Headers, RequestInit, setGlobalDispatcher } from 'undici'

// Global type declaration for typescript
declare global {
  var currentServerUrlHash: string | undefined
}

// Connection constants
export const REASON_AUTH_NEEDED = 'authentication-needed'
export const REASON_TRANSPORT_FALLBACK = 'falling-back-to-alternate-transport'

// Transport strategy types
export type TransportStrategy = 'sse-only' | 'http-only' | 'sse-first' | 'http-first'
export { MCP_REMOTE_VERSION }

const pid = process.pid
// Global debug flag
export let DEBUG = false
export let SILENT = false

// Helper function for timestamp formatting
function getTimestamp(): string {
  const now = new Date()
  return now.toISOString()
}

// Debug logging function
export function debugLog(message: string, ...args: any[]) {
  if (!DEBUG) return

  const serverUrlHash = global.currentServerUrlHash
  if (!serverUrlHash) {
    console.error('[DEBUG LOG ERROR] global.currentServerUrlHash is not set. Cannot write debug log.')
    return
  }

  try {
    // Format with timestamp and PID
    const formattedMessage = `[${getTimestamp()}][${pid}] ${message}`

    // Log to console
    console.error(formattedMessage, ...args)

    // Ensure config directory exists
    const configDir = getConfigDir()
    fs.mkdirSync(configDir, { recursive: true })

    // Append to log file
    const logPath = path.join(configDir, `${serverUrlHash}_debug.log`)
    const logMessage = `${formattedMessage} ${args.map((arg) => (typeof arg === 'object' ? JSON.stringify(arg) : String(arg))).join(' ')}\n`

    fs.appendFileSync(logPath, logMessage, { encoding: 'utf8' })
  } catch (error) {
    // Fallback to console if file logging fails
    console.error(`[DEBUG LOG ERROR] ${error}`)
  }
}

export function log(str: string, ...rest: unknown[]) {
  if (!SILENT) {
    // Using stderr so that it doesn't interfere with stdout
    console.error(`[${pid}] ${str}`, ...rest)
  }

  // If debug mode is on, also log to debug file
  debugLog(str, ...rest)
}

type Message = any
const MESSAGE_BLOCKED = Symbol('MessageBlocked')
const isMessageBlocked = (value: any): value is typeof MESSAGE_BLOCKED => value === MESSAGE_BLOCKED

export function createMessageTransformer({
  transformRequestFunction,
  transformResponseFunction,
}: {
  transformRequestFunction?: null | ((request: Message) => Message | typeof MESSAGE_BLOCKED)
  transformResponseFunction?: null | ((request: Message, response: Message) => Message)
} = {}) {
  const pendingRequests = new Map<string, Message>()

  const interceptRequest = (message: Message) => {
    const messageId = message.id
    if (!messageId) return message
    pendingRequests.set(messageId, message)
    return transformRequestFunction?.(message) ?? message
  }

  const interceptResponse = (message: Message) => {
    const messageId = message.id
    if (!messageId) return message
    const originalRequest = pendingRequests.get(messageId)
    if (!originalRequest) return message
    pendingRequests.delete(messageId)
    return transformResponseFunction?.(originalRequest, message) ?? message
  }

  return {
    interceptRequest,
    interceptResponse,
  }
}

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
export function mcpProxy({
  transportToClient,
  transportToServer,
  ignoredTools = [],
}: {
  transportToClient: Transport
  transportToServer: Transport
  ignoredTools?: string[]
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false
  let initializeRequestId: string | number | undefined
  let lastInitialize: Message | null = null
  let reinitSeq = 0
  const pendingReinit = new Map<string, (message: Message) => void>()

  const messageTransformer = createMessageTransformer({
    transformRequestFunction: (request: Message) => {
      // Block tools/call for ignored tools
      if (request.method === 'tools/call' && request.params?.name) {
        const toolName = request.params.name
        if (!shouldIncludeTool(ignoredTools, toolName)) {
          // Send error response back to client immediately
          const errorResponse = {
            jsonrpc: '2.0' as const,
            id: request.id,
            error: {
              code: -32603,
              message: `Tool "${toolName}" is not available`,
            },
          }
          transportToClient.send(errorResponse).catch(onClientError)
          // Return symbol to indicate this request should not be forwarded
          return MESSAGE_BLOCKED
        }
      }
      return request
    },
    transformResponseFunction: (req: Message, res: Message) => {
      if (req.method === 'tools/list') {
        return {
          ...res,
          result: {
            ...res.result,
            tools: res.result.tools.filter((tool: any) => shouldIncludeTool(ignoredTools, tool.name)),
          },
        }
      }
      return res
    },
  })

  transportToClient.onmessage = (_message) => {
    // TODO: fix types
    const message = messageTransformer.interceptRequest(_message as any)

    // If interceptor returns MESSAGE_BLOCKED, don't forward the message
    if (isMessageBlocked(message)) {
      return
    }

    log('[Local→Remote]', message.method || message.id)

    debugLog('Local → Remote message', {
      method: message.method,
      id: message.id,
      params: message.params ? JSON.stringify(message.params).substring(0, 500) : undefined,
    })

    if (message.method === 'initialize') {
      initializeRequestId = message.id
      const { clientInfo } = message.params
      if (clientInfo) clientInfo.name = `${clientInfo.name} (via mcp-remote ${MCP_REMOTE_VERSION})`
      log(JSON.stringify(message, null, 2))

      debugLog('Initialize message with modified client info', { clientInfo })

      lastInitialize = message
    }

    sendToServer(message)
  }

  transportToServer.onmessage = (_message) => {
    // Responses to our own re-initialize handshake are ours to consume, not the client's
    const reinitId = (_message as any).id
    if (typeof reinitId === 'string' && pendingReinit.has(reinitId)) {
      const settle = pendingReinit.get(reinitId)!
      pendingReinit.delete(reinitId)
      settle(_message as any)
      return
    }

    // TODO: fix types
    const message = messageTransformer.interceptResponse(_message as any)
    log('[Remote→Local]', message.method || message.id)

    debugLog('Remote → Local message', {
      method: message.method,
      id: message.id,
      result: message.result ? 'result-present' : undefined,
      error: message.error,
    })

    // A Client normally calls setProtocolVersion() on its transport once the
    // initialize response comes back, so every later request carries the
    // MCP-Protocol-Version header. In proxy mode no Client drives the remote
    // transport, so without this the header is missing and servers that only
    // accept the newest version reject every post-initialize request (see #66).
    if (initializeRequestId !== undefined && message.id === initializeRequestId) {
      initializeRequestId = undefined
      applyNegotiatedProtocolVersion(message)
    }

    transportToClient.send(message).catch(onClientError)
  }

  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return
    }

    transportToClientClosed = true
    debugLog('Local transport closed, closing remote transport')
    transportToServer.close().catch(onServerError)
  }

  transportToServer.onclose = () => {
    if (transportToClientClosed) {
      return
    }
    transportToServerClosed = true
    debugLog('Remote transport closed, closing local transport')
    transportToClient.close().catch(onClientError)
  }

  transportToClient.onerror = onClientError
  transportToServer.onerror = onServerError

  function onClientError(error: Error) {
    log('Error from local client:', error)
    debugLog('Error from local client', { stack: error.stack })
  }

  function applyNegotiatedProtocolVersion(response: Message) {
    const protocolVersion = response.result?.protocolVersion
    if (typeof protocolVersion === 'string') {
      debugLog('Setting negotiated protocol version on remote transport', protocolVersion)
      transportToServer.setProtocolVersion?.(protocolVersion)
    }
  }

  function onServerError(error: Error) {
    log('Error from remote server:', error)
    debugLog('Error from remote server', { stack: error.stack })
  }

  /**
   * A 404 to a request that carried a session id means the server dropped the
   * session (idle expiry, restart, eviction). The spec says the client must then
   * start a new session with a fresh InitializeRequest.
   *
   * The session id has to be there: a 404 without one is an ordinary "no such
   * endpoint" from a stateless server or a mistyped URL, and re-initializing
   * would just add a doomed handshake to every failing request.
   */
  function isSessionExpired(error: Error) {
    return error instanceof StreamableHTTPError && error.code === 404 && transportToServer.sessionId !== undefined
  }

  let reinitInFlight: Promise<void> | null = null

  /** Coalesces concurrent callers so several in-flight 404s produce one new session, not one each */
  function reinitializeSession(): Promise<void> {
    if (!reinitInFlight) {
      reinitInFlight = doReinitializeSession().finally(() => {
        reinitInFlight = null
      })
    }
    return reinitInFlight
  }

  async function doReinitializeSession() {
    if (!lastInitialize) {
      throw new Error('no initialize request was seen, cannot re-establish the session')
    }

    // Must be cleared before we send, or the transport re-attaches the dead id
    // and the server 404s the handshake too. The SDK exposes sessionId read-only.
    ;(transportToServer as unknown as { _sessionId?: string })._sessionId = undefined

    const id = `mcp-remote-reinit-${++reinitSeq}`
    const response = await new Promise<Message>((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingReinit.delete(id)
        reject(new Error('timed out waiting for the re-initialize response'))
      }, 30000)
      pendingReinit.set(id, (message) => {
        clearTimeout(timer)
        resolve(message)
      })
      transportToServer.send({ ...lastInitialize, id }).catch((error) => {
        clearTimeout(timer)
        pendingReinit.delete(id)
        reject(error)
      })
    })

    if (response.error) {
      throw new Error(`server rejected re-initialize: ${JSON.stringify(response.error)}`)
    }

    // The new session negotiates its own version; the MCP-Protocol-Version header
    // has to follow it or the server 400s everything sent afterwards
    applyNegotiatedProtocolVersion(response)

    // Not ceremony: the SDK only (re)opens the GET SSE stream when it sees this
    // notification, so without it the server could no longer push to the client.
    await transportToServer.send({ jsonrpc: '2.0', method: 'notifications/initialized' })

    // The client is never told any of this happened, so whatever the server kept
    // per session - subscriptions, roots, progress tokens - is quietly gone. The
    // spec mandates the new session anyway; there is no way to replay that state.
    log(`Re-established session ${transportToServer.sessionId ?? '(none)'} after server expiry`)
  }

  async function sendToServer(message: Message) {
    try {
      await transportToServer.send(message)
      return
    } catch (error) {
      // Re-initializing in response to a failed initialize would loop
      if (!isSessionExpired(error as Error) || message.method === 'initialize') {
        onServerError(error as Error)
        replyWithError(message, error as Error)
        return
      }

      log('Remote session expired, re-initializing')
      debugLog('Remote session expired', { id: message.id, method: message.method })

      try {
        await reinitializeSession()
        await transportToServer.send(message)
      } catch (retryError) {
        onServerError(retryError as Error)
        replyWithError(message, retryError as Error)
      }
    }
  }

  /**
   * Without this a failed send leaves the client waiting forever on a request
   * that will never be answered.
   */
  function replyWithError(message: Message, error: Error) {
    // Only requests may be answered. Notifications carry no id, and this handler
    // also sees the client's *responses* to server-initiated requests - those
    // carry an id but no method, and answering one makes the local SDK raise
    // "Received a response for an unknown message ID".
    if (message.method === undefined || message.id === undefined || message.id === null) {
      return
    }
    transportToClient
      .send({
        jsonrpc: '2.0',
        id: message.id,
        error: { code: -32001, message: `mcp-remote: ${error.message ?? String(error)}` },
      })
      .catch(onClientError)
  }
}

/**
 * Result of OAuth server discovery
 */
export interface OAuthServerDiscoveryResult {
  /** The URL of the authorization server to use for OAuth */
  authorizationServerUrl: string
  /** Authorization server metadata (if successfully fetched) */
  authorizationServerMetadata?: AuthorizationServerMetadata
  /** Protected resource metadata (if discovered) */
  protectedResourceMetadata?: ProtectedResourceMetadata
  /** Scope extracted from WWW-Authenticate header */
  wwwAuthenticateScope?: string
}

/**
 * Probes the MCP server to discover the authorization server via Protected Resource Metadata.
 *
 * This implements the MCP Authorization Server Discovery flow:
 * 1. Make a request to the MCP server
 * 2. If we get a 401, extract the WWW-Authenticate header
 * 3. Use the resource_metadata URL from the header (if present) or well-known URIs
 * 4. Fetch Protected Resource Metadata to get the authorization server URL
 * 5. Fetch Authorization Server Metadata from the discovered server
 *
 * @param serverUrl The MCP server URL
 * @param headers Optional headers to include in the probe request
 * @returns Discovery result with authorization server URL and metadata
 */
export async function discoverOAuthServerInfo(
  serverUrl: string,
  headers: Record<string, string> = {},
): Promise<OAuthServerDiscoveryResult> {
  debugLog('Starting OAuth server discovery', { serverUrl })

  let wwwAuthenticateHeader: string | undefined
  let wwwAuthenticateScope: string | undefined

  // Step 1: Probe the MCP server to get WWW-Authenticate header
  try {
    debugLog('Probing MCP server for WWW-Authenticate header')
    const response = await fetch(serverUrl, {
      method: 'GET',
      headers: {
        ...headers,
        Accept: 'application/json, text/event-stream',
      },
      signal: AbortSignal.timeout(10000),
    })

    // If we get a successful response, the server doesn't require auth
    // Fall back to using serverUrl as authorization server
    if (response.ok) {
      debugLog('Server responded OK without auth, using server URL as authorization server')
      const authServerMetadata = await fetchAuthorizationServerMetadata(serverUrl)
      return {
        authorizationServerUrl: serverUrl,
        authorizationServerMetadata: authServerMetadata,
      }
    }

    // Check for 401 Unauthorized
    if (response.status === 401) {
      wwwAuthenticateHeader = response.headers.get('WWW-Authenticate') || undefined
      debugLog('Received 401 with WWW-Authenticate header', {
        hasHeader: !!wwwAuthenticateHeader,
        header: wwwAuthenticateHeader,
      })

      // Parse scope from WWW-Authenticate header if present
      if (wwwAuthenticateHeader) {
        const params = parseWWWAuthenticateHeader(wwwAuthenticateHeader)
        wwwAuthenticateScope = params.scope
      }
    }
  } catch (error) {
    debugLog('Error probing MCP server', {
      error: error instanceof Error ? error.message : String(error),
    })
    // Continue with discovery even if probe fails
  }

  // Step 2: Discover Protected Resource Metadata
  const protectedResourceMetadata = await discoverProtectedResourceMetadata(serverUrl, wwwAuthenticateHeader)

  // Step 3: Determine authorization server URL
  let authorizationServerUrl: string

  if (protectedResourceMetadata) {
    const discoveredUrl = getAuthorizationServerUrl(protectedResourceMetadata)
    if (discoveredUrl) {
      authorizationServerUrl = discoveredUrl
      debugLog('Using authorization server from Protected Resource Metadata', {
        authorizationServerUrl,
      })
    } else {
      // PRM found but no authorization_servers - fall back to server URL
      authorizationServerUrl = serverUrl
      debugLog('PRM found but no authorization_servers, falling back to server URL')
    }
  } else {
    // No PRM found - fall back to server URL (current behavior)
    authorizationServerUrl = serverUrl
    debugLog('No Protected Resource Metadata found, falling back to server URL as authorization server')
  }

  // Step 4: Fetch Authorization Server Metadata
  const authorizationServerMetadata = await fetchAuthorizationServerMetadata(authorizationServerUrl)

  return {
    authorizationServerUrl,
    authorizationServerMetadata,
    protectedResourceMetadata,
    wwwAuthenticateScope,
  }
}

/**
 * Type for the auth initialization function
 */
export type AuthInitializer = () => Promise<{
  waitForAuthCode: () => Promise<string>
  skipBrowserAuth: boolean
}>

/**
 * Creates and connects to a remote server with OAuth authentication
 * @param client The client to connect with
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param headers Additional headers to send with the request
 * @param authInitializer Function to initialize authentication when needed
 * @param transportStrategy Strategy for selecting transport type ('sse-only', 'http-only', 'sse-first', 'http-first')
 * @param recursionReasons Set of reasons for recursive calls (internal use)
 * @returns The connected transport
 */
export async function connectToRemoteServer(
  client: Client | null,
  serverUrl: string,
  authProvider: OAuthClientProvider,
  headers: Record<string, string>,
  authInitializer: AuthInitializer,
  transportStrategy: TransportStrategy = 'http-first',
  recursionReasons: Set<string> = new Set(),
): Promise<Transport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  // Create transport with eventSourceInit to pass Authorization header if present
  const eventSourceInit = {
    fetch: (url: string | URL, init?: RequestInit) => {
      return Promise.resolve(authProvider?.tokens?.()).then((tokens) =>
        fetch(url, {
          ...init,
          headers: {
            ...(init?.headers instanceof Headers
              ? Object.fromEntries(init?.headers.entries())
              : (init?.headers as Record<string, string>) || {}),
            ...headers,
            ...(tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
            Accept: 'text/event-stream',
          } as Record<string, string>,
        }),
      )
    },
  }

  log(`Using transport strategy: ${transportStrategy}`)
  // Determine if we should attempt to fallback on error
  // Choose transport based on user strategy and recursion history
  const shouldAttemptFallback = transportStrategy === 'http-first' || transportStrategy === 'sse-first'

  // Create transport instance based on the strategy
  const sseTransport = transportStrategy === 'sse-only' || transportStrategy === 'sse-first'
  const transport = sseTransport
    ? new SSEClientTransport(url, {
        authProvider,
        requestInit: { headers },
        eventSourceInit,
      })
    : new StreamableHTTPClientTransport(url, {
        authProvider,
        requestInit: { headers },
      })

  // When connecting without a Client (proxy mode), the auth challenge (401) is not received by
  // `transport` itself but by the one-off `testTransport` created below. The SDK stores the
  // `resource_metadata` URL from the WWW-Authenticate header on the transport that received the
  // 401, and `finishAuth` reads it back to discover the authorization server. If we call
  // `finishAuth` on `transport` (which never saw the 401) that URL is missing, so the token
  // exchange falls back to POSTing at the resource origin instead of the discovered
  // `token_endpoint` (see https://github.com/geelen/mcp-remote/issues/270). Track the transport
  // that actually handled the challenge so we can complete auth on it.
  let authChallengeTransport: SSEClientTransport | StreamableHTTPClientTransport | undefined

  try {
    debugLog('Attempting to connect to remote server', { sseTransport })

    if (client) {
      debugLog('Connecting client to transport')
      await client.connect(transport)
    } else {
      debugLog('Starting transport directly')
      await transport.start()
      if (!sseTransport) {
        // Extremely hacky, but we didn't actually send a request when calling transport.start() above, so we don't
        // know if we're even talking to an HTTP server. But if we forced that now we'd get an error later saying that
        // the client is already connected. So let's just create a one-off client to make a single request and figure
        // out if we're actually talking to an HTTP server or not.
        debugLog('Creating test transport for HTTP-only connection test')
        const testTransport = new StreamableHTTPClientTransport(url, { authProvider, requestInit: { headers } })
        // This transport is the one that will receive (and store the metadata from) any 401 challenge.
        authChallengeTransport = testTransport
        const testClient = new Client({ name: 'mcp-remote-fallback-test', version: '0.0.0' }, { capabilities: {} })
        await testClient.connect(testTransport)
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`)

    return transport
  } catch (error: any) {
    // Check if it's a protocol error and we should attempt fallback
    // StreamableHTTPError has a `code` property with the HTTP status code
    const isStreamableHTTPError = error instanceof StreamableHTTPError
    const httpStatusCode = isStreamableHTTPError ? error.code : null
    const shouldFallbackOnError =
      shouldAttemptFallback &&
      error instanceof Error &&
      (httpStatusCode === 404 ||
        httpStatusCode === 405 ||
        error.message.includes('405') ||
        error.message.includes('Method Not Allowed') ||
        error.message.includes('404') ||
        error.message.includes('Not Found'))

    if (shouldFallbackOnError) {
      log(`Received error (status ${httpStatusCode ?? 'unknown'}): ${error.message}`)

      // If we've already tried falling back once, throw an error
      if (recursionReasons.has(REASON_TRANSPORT_FALLBACK)) {
        const errorMessage = `Already attempted transport fallback. Giving up.`
        log(errorMessage)
        throw new Error(errorMessage)
      }

      log(`Recursively reconnecting for reason: ${REASON_TRANSPORT_FALLBACK}`)

      // Add to recursion reasons set
      recursionReasons.add(REASON_TRANSPORT_FALLBACK)

      // Recursively call connectToRemoteServer with the updated recursion tracking
      return connectToRemoteServer(
        client,
        serverUrl,
        authProvider,
        headers,
        authInitializer,
        sseTransport ? 'http-only' : 'sse-only',
        recursionReasons,
      )
    } else if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      log('Authentication required. Initializing auth...')
      debugLog('Authentication error detected', {
        errorCode: error instanceof OAuthError ? error.errorCode : undefined,
        errorMessage: error.message,
        stack: error.stack,
      })

      // Initialize authentication on-demand
      debugLog('Calling authInitializer to start auth flow')
      const { waitForAuthCode, skipBrowserAuth } = await authInitializer()

      if (skipBrowserAuth) {
        log('Authentication required but skipping browser auth - using shared auth')
      } else {
        log('Authentication required. Waiting for authorization...')
      }

      // Wait for the authorization code from the callback
      debugLog('Waiting for auth code from callback server')
      const code = await waitForAuthCode()
      debugLog('Received auth code from callback server')

      try {
        log('Completing authorization...')
        // Complete auth on the transport that received the 401 challenge (in proxy mode this is the
        // one-off test transport, not `transport`), so the stored resource_metadata URL is used to
        // discover the correct token_endpoint. Falls back to `transport` for the with-client path.
        await (authChallengeTransport ?? transport).finishAuth(code)
        debugLog('Authorization completed successfully')

        if (recursionReasons.has(REASON_AUTH_NEEDED)) {
          const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`
          log(errorMessage)
          debugLog('Already attempted auth reconnection, giving up', {
            recursionReasons: Array.from(recursionReasons),
          })
          throw new Error(errorMessage)
        }

        // Track this reason for recursion
        recursionReasons.add(REASON_AUTH_NEEDED)
        log(`Recursively reconnecting for reason: ${REASON_AUTH_NEEDED}`)
        debugLog('Recursively reconnecting after auth', { recursionReasons: Array.from(recursionReasons) })

        // Recursively call connectToRemoteServer with the updated recursion tracking
        return connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy, recursionReasons)
      } catch (authError: any) {
        log('Authorization error:', authError)
        debugLog('Authorization error during finishAuth', {
          errorMessage: authError.message,
          stack: authError.stack,
        })
        throw authError
      }
    } else {
      log('Connection error:', error)
      debugLog('Connection error', {
        errorMessage: error.message,
        stack: error.stack,
        transportType: transport.constructor.name,
      })
      throw error
    }
  }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns A promise resolving to an object with the server, actualPort, authCode, and waitForAuthCode function
 */
export async function setupOAuthCallbackServerWithLongPoll(options: OAuthCallbackServerOptions): Promise<{
  server: Server
  actualPort: number
  authCode: string | null
  waitForAuthCode: () => Promise<string>
  authCompletedPromise: Promise<string>
}> {
  let authCode: string | null = null
  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (code: string) => void
  const authCompletedPromise = new Promise<string>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint
  app.get(LONG_POLL_PATH, (req, res) => {
    if (authCode) {
      // Auth already completed - just return 200 without the actual code
      // Secondary instances will read tokens from disk
      log('Auth already completed, returning 200')
      res.status(200).send('Authentication completed')
      return
    }

    if (req.query.poll === 'false') {
      log('Client requested no long poll, responding with 202')
      res.status(202).send('Authentication in progress')
      return
    }

    // Long poll - wait for up to 30 seconds
    const longPollTimeout = setTimeout(() => {
      log('Long poll timeout reached, responding with 202')
      res.status(202).send('Authentication in progress')
    }, options.authTimeoutMs || 30000)

    // If auth completes while we're waiting, send the response immediately
    authCompletedPromise
      .then(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth completed during long poll, responding with 200')
          res.status(200).send('Authentication completed')
        }
      })
      .catch(() => {
        clearTimeout(longPollTimeout)
        if (!res.headersSent) {
          log('Auth failed during long poll, responding with 500')
          res.status(500).send('Authentication failed')
        }
      })
  })

  // OAuth callback endpoint
  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    authCode = code
    log('Auth code received, resolving promise')
    authCompletedResolve(code)

    res.send(`
      Authorization successful!
      You may close this window and return to the CLI.
      <script>
        // If this is a non-interactive session (no manual approval step was required) then
        // this should automatically close the window. If not, this will have no effect and
        // the user will see the message above.
        window.close();
      </script>
    `)

    // Notify main flow that auth code is available
    options.events.emit('auth-code-received', code)
  })

  // Bind the server, falling back to a random port on EADDRINUSE (unless strictPort is set)
  const { server, actualPort } = await new Promise<{ server: Server; actualPort: number }>((resolve, reject) => {
    const httpServer = app.listen(options.port, '127.0.0.1')

    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        if (options.strictPort) {
          reject(
            Object.assign(
              new Error(
                `Callback port ${options.port} is already in use. The port is mandatory (it was specified explicitly or is pinned by --static-oauth-client-info). Close the process holding that port or restart your machine.`,
              ),
              { code: 'EADDRINUSE', requestedPort: options.port },
            ),
          )
          return
        }
        log(`Warning: callback port ${options.port} is already in use, falling back to a random port`)
        // Retry with an OS-assigned port
        const fallback = app.listen(0, '127.0.0.1')
        fallback.once('error', reject)
        fallback.once('listening', () => {
          const addr = fallback.address() as AddressInfo
          log(`OAuth callback server running at http://127.0.0.1:${addr.port} (fallback from ${options.port})`)
          resolve({ server: fallback, actualPort: addr.port })
        })
      } else {
        reject(err)
      }
    })

    httpServer.once('listening', () => {
      const addr = httpServer.address() as AddressInfo
      log(`OAuth callback server running at http://127.0.0.1:${addr.port}`)
      resolve({ server: httpServer, actualPort: addr.port })
    })
  })

  const waitForAuthCode = (): Promise<string> => {
    return new Promise((resolve) => {
      if (authCode) {
        resolve(authCode)
        return
      }

      options.events.once('auth-code-received', (code) => {
        resolve(code)
      })
    })
  }

  return { server, actualPort, authCode, waitForAuthCode, authCompletedPromise }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns A promise resolving to an object with the server, authCode, and waitForAuthCode function
 */
export async function setupOAuthCallbackServer(options: OAuthCallbackServerOptions) {
  const { server, authCode, waitForAuthCode } = await setupOAuthCallbackServerWithLongPoll(options)
  return { server, authCode, waitForAuthCode }
}

/** The callback path the OAuth redirect URI is built on, unless --callback-path overrides it. */
export const DEFAULT_CALLBACK_PATH = '/oauth/callback'

/** Endpoint secondary instances long-poll to await the auth flow the primary instance is running. */
export const LONG_POLL_PATH = '/wait-for-auth'

/**
 * Builds the OAuth redirect URI for a given host/port. Kept in one place because the value
 * registered with the authorization server and the value checked against a cached
 * registration must match exactly - see invalidateMismatchedClientRegistration.
 */
export function buildRedirectUrl(host: string, port: number, callbackPath: string = DEFAULT_CALLBACK_PATH): string {
  return `http://${host}:${port}${callbackPath}`
}

async function findExistingClientPort(serverUrlHash: string): Promise<number | undefined> {
  const clientInfo = await readJsonFile<OAuthClientInformationFull>(serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  if (!clientInfo) {
    return undefined
  }

  const localhostRedirectUri = clientInfo.redirect_uris
    .map((uri) => new URL(uri))
    .find(({ hostname }) => hostname === 'localhost' || hostname === '127.0.0.1')
  if (!localhostRedirectUri) {
    // A registration that points somewhere we cannot listen (e.g. it was made behind a reverse
    // proxy, or by an earlier `--host` run) yields no reusable port. Fall back to picking one;
    // invalidateMismatchedClientRegistration then discards the unusable registration.
    return undefined
  }

  return parseInt(localhostRedirectUri.port)
}

/**
 * Deletes a cached client registration whose redirect_uris do not include the redirect URI
 * this session will send, forcing a fresh dynamic registration on the next request.
 */
async function invalidateMismatchedClientRegistration(serverUrlHash: string, redirectUrl: string): Promise<void> {
  const clientInfo = await readJsonFile<OAuthClientInformationFull>(serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  if (!clientInfo || clientInfo.redirect_uris.includes(redirectUrl)) {
    return
  }

  log(
    `Cached client registration is for ${clientInfo.redirect_uris.join(', ')} but this session will use ${redirectUrl}. ` +
      `Deleting it so the client re-registers.`,
  )
  await rm(getConfigFilePath(serverUrlHash, 'client_info.json'), { force: true })
}

function calculateDefaultPort(serverUrlHash: string): number {
  // Convert the first 4 bytes of the serverUrlHash into a port offset
  const offset = parseInt(serverUrlHash.substring(0, 4), 16)
  // Pick a consistent but random-seeming port from 3335 to 49151
  return 3335 + (offset % 45816)
}

/**
 * Finds an available port on the local machine
 * @param preferredPort Optional preferred port to try first
 * @returns A promise that resolves to an available port number
 */
export async function findAvailablePort(preferredPort?: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        // If preferred port is in use, get a random port
        server.listen(0)
      } else {
        reject(err)
      }
    })

    server.on('listening', () => {
      const { port } = server.address() as net.AddressInfo
      server.close(() => {
        resolve(port)
      })
    })

    // Try preferred port first, or get a random port
    server.listen(preferredPort || 0)
  })
}

/**
 * Parses command line arguments for MCP clients and proxies
 * @param args Command line arguments
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
export async function parseCommandLineArgs(args: string[], usage: string) {
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write(`${usage}\n`)
    process.exit(0)
  }

  // Deliberately no `-v` alias: it conventionally means "verbose", and this CLI
  // already has --debug, so leave -v free to become its shorthand later.
  if (args.includes('--version')) {
    process.stdout.write(`${MCP_REMOTE_VERSION}\n`)
    process.exit(0)
  }

  // Process headers
  const headers: Record<string, string> = {}
  let i = 0
  while (i < args.length) {
    if (args[i] === '--header' && i < args.length - 1) {
      const value = args[i + 1]
      const match = value.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
      if (match) {
        headers[match[1]] = match[2]
      } else {
        log(`Warning: ignoring invalid header argument: ${value}`)
      }
      args.splice(i, 2)
      // Do not increment i, as the array has shifted
      continue
    }
    i++
  }

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined
  const allowHttp = args.includes('--allow-http')

  // Check for debug flag
  const debug = args.includes('--debug')
  if (debug) {
    DEBUG = true
    log('Debug mode enabled - detailed logs will be written to ~/.mcp-auth/')
  }

  // Check for silent flag
  const silent = args.includes('--silent')
  if (silent) {
    SILENT = true
    log('Silent mode enabled - stderr output will be suppressed, except when --debug is also enabled')
  }

  const enableProxy = args.includes('--enable-proxy')
  if (enableProxy) {
    // Use env proxy
    setGlobalDispatcher(new EnvHttpProxyAgent())
    log('HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables')
  }

  // Parse transport strategy
  let transportStrategy: TransportStrategy = 'http-first' // Default
  const transportIndex = args.indexOf('--transport')
  if (transportIndex !== -1 && transportIndex < args.length - 1) {
    const strategy = args[transportIndex + 1]
    if (strategy === 'sse-only' || strategy === 'http-only' || strategy === 'sse-first' || strategy === 'http-first') {
      transportStrategy = strategy as TransportStrategy
      log(`Using transport strategy: ${transportStrategy}`)
    } else {
      log(`Warning: Ignoring invalid transport strategy: ${strategy}. Valid values are: sse-only, http-only, sse-first, http-first`)
    }
  }

  // Parse host
  let host = process.platform === 'win32' ? '127.0.0.1' : 'localhost' // Default
  const hostIndex = args.indexOf('--host')
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1]
    log(`Using callback hostname: ${host}`)
  }

  // Parse callback path. It has to be a path Express can route and that does not shadow the
  // long-poll endpoint the coordination protocol between concurrent instances relies on,
  // otherwise the authorization server redirects back to an endpoint that never resolves.
  let callbackPath = DEFAULT_CALLBACK_PATH
  const callbackPathIndex = args.indexOf('--callback-path')
  if (callbackPathIndex !== -1 && callbackPathIndex < args.length - 1) {
    const value = args[callbackPathIndex + 1]
    if (!value.startsWith('/')) {
      log(`Warning: Ignoring invalid callback path: ${value}. It must start with '/'.`)
    } else if (value === LONG_POLL_PATH) {
      log(`Warning: Ignoring reserved callback path: ${value}. It is used to coordinate concurrent instances.`)
    } else {
      callbackPath = value
      log(`Using callback path: ${callbackPath}`)
    }
  }

  let staticOAuthClientMetadata: StaticOAuthClientMetadata = null
  const staticOAuthClientMetadataIndex = args.indexOf('--static-oauth-client-metadata')
  if (staticOAuthClientMetadataIndex !== -1 && staticOAuthClientMetadataIndex < args.length - 1) {
    const staticOAuthClientMetadataArg = args[staticOAuthClientMetadataIndex + 1]
    if (staticOAuthClientMetadataArg.startsWith('@')) {
      const filePath = staticOAuthClientMetadataArg.slice(1)
      staticOAuthClientMetadata = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client metadata from file: ${filePath}`)
    } else {
      staticOAuthClientMetadata = JSON.parse(staticOAuthClientMetadataArg)
      log(`Using static OAuth client metadata from string`)
    }
  }

  // parse static OAuth client information, if provided
  // defaults to OAuth dynamic client registration
  let staticOAuthClientInfo: StaticOAuthClientInformationFull = null
  const staticOAuthClientInfoIndex = args.indexOf('--static-oauth-client-info')
  if (staticOAuthClientInfoIndex !== -1 && staticOAuthClientInfoIndex < args.length - 1) {
    const staticOAuthClientInfoArg = args[staticOAuthClientInfoIndex + 1]
    if (staticOAuthClientInfoArg.startsWith('@')) {
      const filePath = staticOAuthClientInfoArg.slice(1)
      staticOAuthClientInfo = JSON.parse(await readFile(filePath, 'utf8'))
      log(`Using static OAuth client information from file: ${filePath}`)
    } else {
      staticOAuthClientInfo = JSON.parse(staticOAuthClientInfoArg)
      log(`Using static OAuth client information from string`)
    }
  }

  // Parse the RFC 8707 resource indicator, and whether to omit it entirely
  let authorizeResource: string | undefined
  let skipResourceParameter = args.includes('--disable-resource-parameter')

  const resourceIndex = args.indexOf('--resource')
  if (resourceIndex !== -1 && resourceIndex < args.length - 1) {
    const value = args[resourceIndex + 1].trim()
    if (value.length === 0) {
      // `--resource ""` is how people have been trying to switch this off
      skipResourceParameter = true
    } else {
      authorizeResource = value
    }
  }

  if (skipResourceParameter) {
    if (authorizeResource) {
      log(`Warning: --disable-resource-parameter overrides --resource ${authorizeResource}; the resource parameter will be omitted.`)
      // Cleared so it cannot silently split the credential cache - see getServerUrlHash
      authorizeResource = undefined
    }
    log('Resource parameter disabled - it will be omitted from authorization and token requests')
  } else if (authorizeResource) {
    try {
      new URL(authorizeResource)
    } catch {
      throw new Error(`Invalid --resource value: "${authorizeResource}". RFC 8707 requires an absolute URI, e.g. https://example.com/mcp`)
    }
    log(`Using authorize resource: ${authorizeResource}`)
  }

  // Parse ignored tools
  const ignoredTools: string[] = []
  let j = 0
  while (j < args.length) {
    if (args[j] === '--ignore-tool' && j < args.length - 1) {
      const toolName = args[j + 1]
      ignoredTools.push(toolName)
      log(`Ignoring tool: ${toolName}`)
      args.splice(j, 2)
      // Do not increment j, as the array has shifted
      continue
    }
    j++
  }

  // Parse auth timeout
  let authTimeoutMs = 30000 // Default 30 seconds
  const authTimeoutIndex = args.indexOf('--auth-timeout')
  if (authTimeoutIndex !== -1 && authTimeoutIndex < args.length - 1) {
    const timeoutSeconds = parseInt(args[authTimeoutIndex + 1], 10)
    if (!isNaN(timeoutSeconds) && timeoutSeconds > 0) {
      authTimeoutMs = timeoutSeconds * 1000
      log(`Using auth callback timeout: ${timeoutSeconds} seconds`)
    } else {
      log(`Warning: Ignoring invalid auth timeout value: ${args[authTimeoutIndex + 1]}. Must be a positive number.`)
    }
  }

  if (!serverUrl) {
    log(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost || allowHttp)) {
    log('Error: Non-HTTPS URLs are only allowed for localhost or when --allow-http flag is provided')
    log(usage)
    process.exit(1)
  }
  // Calculate hash with all parsed parameters for cache isolation
  const serverUrlHash = getServerUrlHash(serverUrl, authorizeResource, headers)

  // Set server hash globally for debug logging
  global.currentServerUrlHash = serverUrlHash

  debugLog(`Starting mcp-remote with server URL: ${serverUrl}`)

  const defaultPort = calculateDefaultPort(serverUrlHash)

  // Use the specified port, or the existing client port or fallback to find an available one
  const [existingClientPort, availablePort] = await Promise.all([findExistingClientPort(serverUrlHash), findAvailablePort(defaultPort)])
  let callbackPort: number

  if (specifiedPort) {
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else if (existingClientPort) {
    log(`Using existing client port: ${existingClientPort}`)
    callbackPort = existingClientPort
  } else {
    log(`Using automatically selected callback port: ${availablePort}`)
    callbackPort = availablePort
  }

  // A cached dynamic client registration is only usable if it was registered with the exact
  // redirect_uri this run will send. If it wasn't, the authorization server rejects the
  // authorize request (RFC 6749 §3.1.2.4) and, because it refuses to redirect back, the user
  // sees an opaque error at the AS rather than anything actionable here. Worse, the callback
  // port is re-picked on each run, so it never self-heals. Dropping the registration lets the
  // next request re-register cleanly.
  //
  // Static client info is pinned by the user, so it is never discarded.
  if (!staticOAuthClientInfo) {
    await invalidateMismatchedClientRegistration(serverUrlHash, buildRedirectUrl(host, callbackPort, callbackPath))
  }

  if (Object.keys(headers).length > 0) {
    // Names only - values routinely carry bearer tokens and API keys, and this
    // goes to stderr, which MCP clients capture into their own logs.
    log(`Using custom headers: ${Object.keys(headers).join(', ')}`)
  }
  // Replace environment variables in headers
  // example `Authorization: Bearer ${TOKEN}` will read process.env.TOKEN
  for (const [key, value] of Object.entries(headers)) {
    headers[key] = value.replace(/\$\{([^}]+)}/g, (match, envVarName) => {
      const envVarValue = process.env[envVarName]

      if (envVarValue !== undefined) {
        log(`Replacing ${match} with environment value in header '${key}'`)
        return envVarValue
      } else {
        log(`Warning: Environment variable '${envVarName}' not found for header '${key}'.`)
        return ''
      }
    })
  }

  return {
    serverUrl,
    callbackPath,
    callbackPort,
    specifiedPort,
    headers,
    transportStrategy,
    host,
    debug,
    staticOAuthClientMetadata,
    staticOAuthClientInfo,
    authorizeResource,
    skipResourceParameter,
    ignoredTools,
    authTimeoutMs,
    serverUrlHash,
  }
}

/**
 * Sets up signal handlers for graceful shutdown
 * @param cleanup Cleanup function to run on shutdown
 */
export function setupSignalHandlers(cleanup: () => Promise<void>) {
  process.on('SIGINT', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })

  // Keep the process alive
  process.stdin.resume()
  process.stdin.on('end', async () => {
    log('\nShutting down...')
    await cleanup()
    process.exit(0)
  })
}

/**
 * Generates a hash for the server URL configuration
 * Includes resource and headers to isolate OAuth sessions per unique
 * server configuration (fixes #25: multi-instance support)
 * @param serverUrl The server URL
 * @param authorizeResource Optional resource parameter for OAuth
 * @param headers Optional custom headers
 * @returns MD5 hash of the configuration
 */
export function getServerUrlHash(serverUrl: string, authorizeResource?: string, headers?: Record<string, string>): string {
  // Include resource and headers in hash to isolate OAuth sessions
  // per unique server configuration (fixes #25)
  const parts = [serverUrl]
  if (authorizeResource) parts.push(authorizeResource)
  if (headers && Object.keys(headers).length > 0) {
    const sortedKeys = Object.keys(headers).sort()
    parts.push(JSON.stringify(headers, sortedKeys))
  }
  return crypto.createHash('md5').update(parts.join('|')).digest('hex')
}

/**
 * Converts a glob pattern to a regular expression
 * @param pattern The glob pattern (e.g., "create*", "*account")
 * @returns The corresponding regular expression
 */
function patternToRegex(pattern: string): RegExp {
  // Split by asterisks, escape each part, then join with .*
  const parts = pattern.split('*')
  const escapedParts = parts.map((part) => part.replace(/\W/g, '\\$&'))
  const regexPattern = escapedParts.join('.*')
  // Match the entire string from start to end, case-insensitive
  return new RegExp(`^${regexPattern}$`, 'i')
}

/**
 * Determines if a tool name should be ignored based on ignore patterns
 * @param ignorePatterns Array of patterns to ignore (supports wildcards with *)
 * @param toolName The name of the tool to check
 * @returns false if the tool should be ignored (matches a pattern), true if it should be included
 */
export function shouldIncludeTool(ignorePatterns: string[], toolName: string): boolean {
  // If no patterns are provided, include all tools
  if (!ignorePatterns || ignorePatterns.length === 0) {
    return true
  }

  // Check if the tool name matches any ignore pattern
  for (const pattern of ignorePatterns) {
    const regex = patternToRegex(pattern)
    if (regex.test(toolName)) {
      return false // Tool matches an ignore pattern, so exclude it
    }
  }

  return true // Tool doesn't match any ignore pattern, so include it
}
