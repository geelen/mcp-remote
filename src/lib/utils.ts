import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Transport, type FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { OAuthClientInformationFull, OAuthClientInformationFullSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { AuthCodeResult, OAuthCallbackServerOptions, StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './types'
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
import { Agent, EnvHttpProxyAgent, fetch, Headers, RequestInit, setGlobalDispatcher } from 'undici'

// Global type declaration for typescript
declare global {
  var currentServerUrlHash: string | undefined
}

// Connection constants
export const REASON_AUTH_NEEDED = 'authentication-needed'
export const REASON_TRANSPORT_FALLBACK = 'falling-back-to-alternate-transport'

/**
 * Which JSON-RPC methods carry an `Mcp-Name`, and where its value comes from.
 *
 * SEP-2243 sources the header from `params.name` for tools and prompts, and from
 * `params.uri` for resources.
 */
const MCP_NAME_SOURCES: Record<string, 'name' | 'uri'> = {
  'tools/call': 'name',
  'prompts/get': 'name',
  'resources/read': 'uri',
}

type MirroredMcpHeaders = { method: string; name?: string }

/**
 * Read the standard MCP request headers out of a JSON-RPC body.
 *
 * A batch body is deliberately skipped: it has no single method to mirror, and
 * mirroring one of several is worse than sending nothing.
 */
function mcpHeadersFromBody(body: RequestInit['body']): MirroredMcpHeaders | undefined {
  if (typeof body !== 'string') return undefined

  let message: unknown
  try {
    message = JSON.parse(body)
  } catch {
    return undefined
  }

  if (!message || typeof message !== 'object' || Array.isArray(message)) return undefined

  const { method, params } = message as { method?: unknown; params?: unknown }
  if (typeof method !== 'string' || method.length === 0) return undefined

  const source = MCP_NAME_SOURCES[method]
  if (!source || !params || typeof params !== 'object') return { method }

  const name = (params as Record<string, unknown>)[source]
  return typeof name === 'string' && name.length > 0 ? { method, name } : { method }
}

/**
 * Encode a header value per the SEP-2243 value rules.
 *
 * RFC 9110 field values are visible ASCII plus space and tab, with no leading or
 * trailing whitespace. Anything outside that - and any literal that would itself
 * be mistaken for the sentinel - travels Base64.
 */
export function encodeMcpHeaderValue(value: string): string {
  const headerSafe = /^[\x21-\x7e](?:[\x20-\x7e\t]*[\x21-\x7e])?$/.test(value)
  const looksEncoded = value.startsWith('=?base64?') && value.endsWith('?=')

  return headerSafe && !looksEncoded ? value : `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`
}

/**
 * Mirror the JSON-RPC method and target into the standard MCP request headers.
 *
 * SEP-2243 (spec revision 2026-07-28) requires `Mcp-Method` on every request and
 * `Mcp-Name` on `tools/call`, `resources/read` and `prompts/get`, so that gateways
 * can route and meter without parsing the body. The SDK sends neither, which is
 * what strands mcp-remote behind a method-aware gateway (#306).
 *
 * Both are derived from the exact body being sent, never from anything else: a
 * server that enforces the rule rejects a header that disagrees with the body -
 * or a required one that is missing - with `-32020 HeaderMismatch`. That is also
 * why `Mcp-Method` is never sent alone for a method that requires `Mcp-Name`;
 * a partial set is itself a mismatch.
 *
 * Caller-supplied headers win, so an explicit `--header` still overrides.
 *
 * The cast bridges types only: this module is undici-typed throughout (see the
 * import above) while `FetchLike` is declared against the global DOM types. They
 * are the same implementation at runtime on the Node versions we support.
 */
const fetchWithMcpHeaders = (async (url: string | URL, init?: RequestInit) => {
  const mirrored = mcpHeadersFromBody(init?.body)
  if (!mirrored) return fetch(url, init)

  const headers = new Headers(init?.headers)
  if (!headers.has('Mcp-Method')) headers.set('Mcp-Method', mirrored.method)
  if (mirrored.name !== undefined && !headers.has('Mcp-Name')) {
    headers.set('Mcp-Name', encodeMcpHeaderValue(mirrored.name))
  }

  return fetch(url, { ...init, headers })
}) as unknown as FetchLike

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

/** How long the client's first requests wait on `notifications/initialized` before going anyway. */
const LIFECYCLE_BARRIER_TIMEOUT_MS = 10_000

/** A timer that never keeps the process alive on its own. */
const sleep = (ms: number) =>
  new Promise<void>((resolve) => {
    setTimeout(resolve, ms).unref?.()
  })

const isMessageBlocked = (value: any): value is typeof MESSAGE_BLOCKED => value === MESSAGE_BLOCKED

export function createMessageTransformer({
  transformRequestFunction,
  transformResponseFunction,
}: {
  transformRequestFunction?: null | ((request: Message) => Message | typeof MESSAGE_BLOCKED)
  transformResponseFunction?: null | ((request: Message, response: Message) => Message)
} = {}) {
  const pendingRequests = new Map<string | number, Message>()

  /**
   * A request is the only thing worth remembering, and the only thing worth pairing a response to.
   *
   * Both directions carry messages with an `id` that are *not* requests - a response the client
   * sends back to a server-initiated call, for one - and the two directions number their requests
   * independently, so recording those would let one side's id collide with the other's and pair a
   * response with a message that never asked for it.
   */
  const isRequest = (message: Message) => message?.id != null && message.method !== undefined
  const isResponse = (message: Message) => message?.id != null && message.method === undefined

  /**
   * Runs a transform, falling back to the untouched message if it throws.
   *
   * A transform is a convenience; delivery is not. Letting one throw here would abort the
   * `onmessage` handler that was about to forward the message, so a client would be left waiting
   * on a request that was in fact answered (see https://github.com/geelen/mcp-remote/issues/310).
   */
  const applyTransform = (transform: () => Message, message: Message) => {
    try {
      return transform()
    } catch (error) {
      log('Error transforming message, forwarding it unchanged:', error)
      debugLog('Message transform failed', { id: message?.id, method: message?.method, error })
      return message
    }
  }

  const interceptRequest = (message: Message) => {
    if (!isRequest(message)) return message
    pendingRequests.set(message.id, message)
    if (!transformRequestFunction) return message
    return applyTransform(() => transformRequestFunction(message) ?? message, message)
  }

  const interceptResponse = (message: Message) => {
    if (!isResponse(message)) return message
    const originalRequest = pendingRequests.get(message.id)
    if (!originalRequest) return message
    pendingRequests.delete(message.id)
    if (!transformResponseFunction) return message
    return applyTransform(() => transformResponseFunction(originalRequest, message) ?? message, message)
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
  reauthorize,
}: {
  transportToClient: Transport
  transportToServer: Transport
  ignoredTools?: string[]
  /**
   * Completes a sign-in for a request the server refused, or undefined to answer with the error.
   *
   * Supplied by the caller rather than built here, because finishing a flow needs the auth
   * provider and the callback server, neither of which a proxy between two transports should know
   * about.
   */
  reauthorize?: () => Promise<void>
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false
  let initializeRequestId: string | number | undefined
  let lastInitialize: Message | null = null
  let reinitSeq = 0
  const pendingReinit = new Map<string, (message: Message) => void>()
  let initializedDelivered: Promise<unknown> | null = null
  let reauthorizeInFlight: Promise<void> | null = null

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
      if (req.method !== 'tools/list') return res
      // Not every answer to tools/list carries a tool list: a JSON-RPC error response has no
      // `result` at all, and a server may answer with one that omits `tools`. Filtering either
      // used to throw, and the throw took the forward down with it, so the client was left with
      // no answer rather than the error the server actually sent (see issues #164 and #310).
      const tools = res.result?.tools
      if (!Array.isArray(tools)) return res
      return {
        ...res,
        result: {
          ...res.result,
          tools: tools.filter((tool: any) => shouldIncludeTool(ignoredTools, tool.name)),
        },
      }
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

    forwardInOrder(message)
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

  /**
   * Forwards a message, keeping the client's requests behind `notifications/initialized`.
   *
   * Every forward here is an independent POST, and a client sends the notification and its first
   * requests back to back, so without this they race - and a server that enforces the lifecycle
   * answers whichever request wins with "Session not initialized". The spec puts the same rule on
   * the client, which it honours over stdio; only the proxy was re-ordering it on the wire (see
   * https://github.com/geelen/mcp-remote/issues/310).
   *
   * Nothing else is serialized. `send` for a JSON-answering server does not resolve until that
   * request's response has been read, so ordering every message this way would turn concurrent
   * requests into sequential ones.
   */
  function forwardInOrder(message: Message) {
    if (message.method === 'notifications/initialized') {
      // Bounded, because a server that never answers the notification must not leave every later
      // request queued behind it forever - racing ahead is the lesser failure.
      initializedDelivered = Promise.race([sendToServer(message), sleep(LIFECYCLE_BARRIER_TIMEOUT_MS)])
      return
    }

    if (initializedDelivered) {
      // Continuations resume in the order they were queued, so this preserves the client's order
      // among the messages waiting on it, not just their order relative to the notification.
      void initializedDelivered.then(() => sendToServer(message))
      return
    }

    void sendToServer(message)
  }

  /**
   * Whether the server refused this because nobody is signed in.
   *
   * The SDK has already opened a browser by the time this surfaces: its transport answers a 401 by
   * running `auth()`, which reaches `redirectToAuthorization` and then throws because the flow has
   * not finished. So the user is looking at a consent screen whose redirect is on its way to the
   * callback port - all that is missing is somebody to receive the code and redeem it.
   */
  function isUnauthorized(error: Error) {
    return error instanceof UnauthorizedError || error.message.includes('Unauthorized')
  }

  /** Coalesces concurrent callers, so several refused requests produce one sign-in, not one each */
  function reauthorizeOnce(): Promise<void> {
    if (!reauthorizeInFlight) {
      reauthorizeInFlight = reauthorize!().finally(() => {
        reauthorizeInFlight = null
      })
    }
    return reauthorizeInFlight
  }

  async function sendToServer(message: Message, alreadyReauthorized = false) {
    try {
      await transportToServer.send(message)
      return
    } catch (error) {
      // The sign-in the SDK started can still be completed, but only by someone holding the
      // callback port. Retried once: a second refusal is the server rejecting a token we just
      // obtained, which another flow will not fix (see issues #133, #179, #248, #256, #286).
      if (reauthorize && !alreadyReauthorized && isUnauthorized(error as Error)) {
        log('Remote server requires authorization, completing sign-in')
        debugLog('Unauthorized send, re-authorizing', { id: message.id, method: message.method })
        try {
          await reauthorizeOnce()
          await sendToServer(message, true)
        } catch (authError) {
          onServerError(authError as Error)
          replyWithError(message, authError as Error)
        }
        return
      }

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
  waitForAuthCode: () => Promise<AuthCodeResult>
  skipBrowserAuth: boolean
}>

/** The header shapes `fetch` accepts, plus the `Headers` the SDK actually hands over. */
type HeaderSource = RequestInit['headers'] | Headers | globalThis.Headers | undefined

function headerEntries(source: HeaderSource): Array<[string, string]> {
  if (!source) return []
  // Arrays have `entries` too, so this order matters - theirs yields [index, pair], not [name, value]
  if (Array.isArray(source)) return source as Array<[string, string]>
  const iterable = source as { entries?: () => Iterable<[string, string]> }
  if (typeof iterable.entries === 'function') return [...iterable.entries()]
  return Object.entries(source as Record<string, string>)
}

/**
 * Merges header sources into one plain object, with later sources winning.
 *
 * Two things make this less trivial than a spread.
 *
 * The sources are different shapes. The SDK hands over a `Headers` built from the *global* class,
 * while the check here used to be `instanceof Headers` against the one imported from undici - a
 * different class, so it never matched, and the fallback spread of a `Headers` yields no own
 * properties at all. Every header the SDK had set was dropped (see
 * https://github.com/geelen/mcp-remote/issues/157). Duck-typing on `entries` accepts either.
 *
 * And the sources disagree about case. `Headers.entries()` lowercases, while `--header` values and
 * the ones added here keep the case they were written in, so a plain merge emits `authorization`
 * *and* `Authorization` as separate keys - which `fetch` then joins into a single comma-separated
 * value that no server will accept. Merging case-insensitively keeps one entry per header, spelled
 * the way its last writer spelled it, so a server matching on `Company` still sees `Company`.
 *
 * @param sources Header collections in precedence order, lowest first
 * @returns The merged headers
 */
export function mergeHeaders(...sources: HeaderSource[]): Record<string, string> {
  const merged = new Map<string, [string, string]>()
  for (const source of sources) {
    for (const [name, value] of headerEntries(source)) {
      merged.set(name.toLowerCase(), [name, value])
    }
  }
  return Object.fromEntries(merged.values())
}

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
          headers: mergeHeaders(
            init?.headers,
            headers,
            tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : undefined,
            { Accept: 'text/event-stream' },
          ),
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
        fetch: fetchWithMcpHeaders,
      })
    : new StreamableHTTPClientTransport(url, {
        authProvider,
        requestInit: { headers },
        fetch: fetchWithMcpHeaders,
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
        // This probe sends the very first `initialize` POST, so it is the request a
        // method-aware gateway routes on. It needs the mirrored headers as much as the
        // real transport does.
        const testTransport = new StreamableHTTPClientTransport(url, {
          authProvider,
          requestInit: { headers },
          fetch: fetchWithMcpHeaders,
        })
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

      const giveUpIfAlreadyRetried = () => {
        if (!recursionReasons.has(REASON_AUTH_NEEDED)) return
        const errorMessage = `Already attempted reconnection for reason: ${REASON_AUTH_NEEDED}. Giving up.`
        log(errorMessage)
        debugLog('Already attempted auth reconnection, giving up', {
          recursionReasons: Array.from(recursionReasons),
        })
        throw new Error(errorMessage)
      }

      // A concurrent instance ran the browser flow for us and persisted the tokens. There is no
      // authorization code of our own to exchange - our callback server never received one, and
      // the sibling's code has already been redeemed - so `waitForAuthCode` here is a promise
      // that never settles (see coordinateAuth). Reconnect instead, which makes the auth provider
      // re-read the tokens the sibling wrote (see https://github.com/geelen/mcp-remote/issues/322).
      if (skipBrowserAuth) {
        log('Authentication was completed by another instance - reconnecting with the tokens it wrote')
        giveUpIfAlreadyRetried()

        recursionReasons.add(REASON_AUTH_NEEDED)
        debugLog('Recursively reconnecting using a sibling instance tokens', {
          recursionReasons: Array.from(recursionReasons),
        })
        return connectToRemoteServer(client, serverUrl, authProvider, headers, authInitializer, transportStrategy, recursionReasons)
      }

      log('Authentication required. Waiting for authorization...')

      // Wait for the authorization code from the callback
      debugLog('Waiting for auth code from callback server')
      const { code, state } = await waitForAuthCode()
      debugLog('Received auth code from callback server')

      // The code may belong to a flow another instance started, whose verifier is not this one's
      if (state && 'useAuthorizationState' in authProvider && typeof authProvider.useAuthorizationState === 'function') {
        authProvider.useAuthorizationState(state)
      }

      // Checked before the exchange, not after: an authorization code is single-use (RFC 6749
      // 4.1.2) and the callback server hands back the same retained code on a second call, so
      // exchanging it again fails with invalid_grant and masks this message.
      giveUpIfAlreadyRetried()

      try {
        log('Completing authorization...')
        // Complete auth on the transport that received the 401 challenge (in proxy mode this is the
        // one-off test transport, not `transport`), so the stored resource_metadata URL is used to
        // discover the correct token_endpoint. Falls back to `transport` for the with-client path.
        await (authChallengeTransport ?? transport).finishAuth(code)
        debugLog('Authorization completed successfully')

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
  waitForAuthCode: () => Promise<AuthCodeResult>
  authCompletedPromise: Promise<AuthCodeResult>
}> {
  /**
   * Codes that have arrived and nobody has redeemed yet, oldest first.
   *
   * A queue rather than one retained code, because a process signs in more than once: tokens are
   * revoked, refresh tokens lapse, a server starts asking for a scope it did not before. The old
   * single slot handed every later caller the *first* code it ever saw, and an authorization code
   * is single-use (RFC 6749 4.1.2), so redeeming it a second time fails with `invalid_grant`.
   */
  const unclaimedCodes: AuthCodeResult[] = []

  /** Callers waiting for a code that has not arrived yet, in the order they asked. */
  const waitingForCode: Array<{ resolve: (result: AuthCodeResult) => void; reject: (error: Error) => void }> = []

  /**
   * Whether any sign-in has ever completed here.
   *
   * Kept separate from the queue: a sibling polling the long-poll endpoint is asking "has the
   * user finished, so are there tokens on disk for me to read", which stays true once it is true.
   * Draining the queue must not make that answer go backwards.
   */
  let authEverCompleted = false

  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (result: AuthCodeResult) => void
  const authCompletedPromise = new Promise<AuthCodeResult>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint
  app.get(LONG_POLL_PATH, (req, res) => {
    if (authEverCompleted) {
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

  // Lets an instance that lost the bind identify who holds the port. Without it, EADDRINUSE from
  // an unrelated process is indistinguishable from a sibling and every instance waits forever.
  app.get(MCP_REMOTE_ID_PATH, (_req, res) => {
    res.json({ mcpRemote: true, serverUrlHash: options.serverUrlHash })
  })

  // OAuth callback endpoint
  app.get(options.path, (req, res) => {
    const code = req.query.code as string | undefined
    const state = req.query.state as string | undefined
    const authorizationError = req.query.error as string | undefined
    if (authorizationError) {
      const description = (req.query.error_description as string | undefined) ?? authorizationError
      log(`Authorization failed: ${authorizationError} - ${description}`)
      res.status(400).send(`Authorization failed: ${description}\n\nYou may close this window and return to the CLI.`)
      options.events.emit('auth-code-failed', new Error(`Authorization failed: ${authorizationError} - ${description}`))
      return
    }
    if (!code) {
      res.status(400).send('Error: No authorization code received')
      return
    }

    const received: AuthCodeResult = { code, state }
    authEverCompleted = true
    log('Auth code received, resolving promise')
    authCompletedResolve(received)

    // Hand it straight to whoever is waiting; hold it only if nobody is yet. The startup flow
    // reaches `waitForAuthCode` after the browser has already been sent here, so both orders happen.
    const waiter = waitingForCode.shift()
    if (waiter) waiter.resolve(received)
    else unclaimedCodes.push(received)

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
    options.events.emit('auth-code-received', code, state)
  })

  // Bind the server. There is deliberately no random-port fallback: the deterministic port is
  // what makes concurrent instances agree on an owner, and an instance that quietly moved
  // elsewhere would advertise a redirect_uri no browser can deliver a code to. EADDRINUSE is a
  // signal that somebody else owns this flow, and the caller decides what to do about it.
  const { server, actualPort } = await new Promise<{ server: Server; actualPort: number }>((resolve, reject) => {
    const httpServer = app.listen(options.port, '127.0.0.1')

    httpServer.once('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        reject(
          Object.assign(new Error(`Callback port ${options.port} is already in use`), { code: 'EADDRINUSE', requestedPort: options.port }),
        )
        return
      }
      reject(err)
    })

    httpServer.once('listening', () => {
      const addr = httpServer.address() as AddressInfo
      log(`OAuth callback server running at http://127.0.0.1:${addr.port}`)
      resolve({ server: httpServer, actualPort: addr.port })
    })
  })

  /** Takes the next unredeemed code, waiting for one if none has arrived. */
  const waitForAuthCode = (): Promise<AuthCodeResult> => {
    const alreadyHere = unclaimedCodes.shift()
    if (alreadyHere) return Promise.resolve(alreadyHere)

    return new Promise((resolve, reject) => {
      const entry = {
        resolve,
        // An authorization the user denied never produces a code, and waiting for one holds the
        // callback port for the life of the process
        reject: (error: Error) => {
          options.events.off('auth-code-failed', onFailure)
          reject(error)
        },
      }
      const onFailure = (error: Error) => {
        const index = waitingForCode.indexOf(entry)
        if (index !== -1) waitingForCode.splice(index, 1)
        entry.reject(error)
      }
      waitingForCode.push(entry)
      options.events.once('auth-code-failed', onFailure)
    })
  }

  return { server, actualPort, authCode: null, waitForAuthCode, authCompletedPromise }
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
export const MCP_REMOTE_ID_PATH = '/.mcp-remote/id'
export const LONG_POLL_PATH = '/wait-for-auth'

/**
 * Builds the OAuth redirect URI for a given host/port. Kept in one place because the value
 * registered with the authorization server and the value checked against a cached
 * registration must match exactly - see invalidateMismatchedClientRegistration.
 */
export function buildRedirectUrl(host: string, port: number, callbackPath: string = DEFAULT_CALLBACK_PATH): string {
  return `http://${host}:${port}${callbackPath}`
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

export function calculateDefaultPort(serverUrlHash: string): number {
  // Convert the first 4 bytes of the serverUrlHash into a port offset
  const offset = parseInt(serverUrlHash.substring(0, 4), 16)
  // Pick a consistent but random-seeming port from 3335 to 49151
  return 3335 + (offset % 45816)
}

/**
 * Parses command line arguments for MCP clients and proxies
 * @param args Command line arguments
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
/** The subset of undici dispatcher options this CLI exposes. Shared by both agent flavours. */
type DispatcherOptions = {
  connect?: { timeout?: number; family?: number }
  bodyTimeout?: number
  headersTimeout?: number
}

/**
 * Reads a flag whose value is a duration in seconds, and returns it in milliseconds.
 *
 * @param args The command line arguments
 * @param flag The flag to read
 * @param options Whether zero is meaningful for this flag - for the timeouts it means "no timeout"
 * @returns The duration in milliseconds, or undefined if the flag was absent or unusable
 */
export function parseSecondsOption(args: string[], flag: string, { allowZero = false } = {}): number | undefined {
  const index = args.indexOf(flag)
  if (index === -1 || index >= args.length - 1) return undefined

  const raw = args[index + 1]
  const seconds = Number(raw)
  if (!Number.isFinite(seconds) || seconds < 0 || (seconds === 0 && !allowZero)) {
    log(`Warning: Ignoring invalid ${flag} value: ${raw}. Must be a ${allowZero ? 'non-negative' : 'positive'} number of seconds.`)
    return undefined
  }

  return Math.round(seconds * 1000)
}

/** Splits `Name: value` into its parts, or undefined if it is not that shape. */
function parseHeaderLine(line: string): { name: string; value: string } | undefined {
  const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/)
  return match ? { name: match[1], value: match[2] } : undefined
}

/**
 * Reads headers from a file, one `Name: value` per line, `#` for comments.
 *
 * A file exists to keep credentials out of the process arguments, where every other user on the
 * machine can read them - so a file named but unreadable is fatal rather than a warning. Carrying
 * on would send the request without its credentials and turn a typo in a path into an
 * authorization error somewhere much less obvious.
 *
 * @param filePath The file to read
 * @returns The headers it declares
 */
async function readHeaderFile(filePath: string): Promise<Record<string, string>> {
  let contents: string
  try {
    contents = await readFile(filePath, 'utf8')
  } catch (error) {
    throw new Error(`Could not read the header file ${filePath}: ${(error as Error).message}`)
  }

  const headers: Record<string, string> = {}
  contents.split(/\r?\n/).forEach((line, index) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return

    const parsed = parseHeaderLine(trimmed)
    // By line number, never by content - these lines are exactly where the secrets are
    if (!parsed) {
      log(`Warning: ignoring line ${index + 1} of ${filePath}, which is not in Name:Value form`)
      return
    }
    headers[parsed.name] = parsed.value
  })

  log(`Loaded ${Object.keys(headers).length} header(s) from ${filePath}`)
  return headers
}

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
      const parsed = parseHeaderLine(value)
      // Never the argument itself: a header that failed to parse is usually one whose value
      // contains something unexpected, and the value is a credential more often than not.
      if (parsed) headers[parsed.name] = parsed.value
      else log('Warning: ignoring a --header argument that is not in Name:Value form')
      args.splice(i, 2)
      // Do not increment i, as the array has shifted
      continue
    }
    if (args[i] === '--header-file' && i < args.length - 1) {
      Object.assign(headers, await readHeaderFile(args[i + 1]))
      args.splice(i, 2)
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

  // Network tuning. These land on the global undici dispatcher, which both our own `fetch` and the
  // SDK's `globalThis.fetch` resolve through - the slot is keyed by a registered symbol, so the two
  // undici copies share it. Without a dispatcher there is no way to reach these settings at all,
  // which is why people have been patching them in with NODE_OPTIONS (see issues #107 and #263).
  const connectTimeoutMs = parseSecondsOption(args, '--connect-timeout')
  const bodyTimeoutMs = parseSecondsOption(args, '--body-timeout', { allowZero: true })
  const headersTimeoutMs = parseSecondsOption(args, '--headers-timeout', { allowZero: true })
  const forceIpv4 = args.includes('--ipv4')

  const dispatcherOptions: DispatcherOptions = {}
  if (connectTimeoutMs !== undefined || forceIpv4) {
    dispatcherOptions.connect = {
      ...(connectTimeoutMs !== undefined ? { timeout: connectTimeoutMs } : {}),
      // Happy-eyeballs tries every A and AAAA record it gets back. On a network where the IPv6
      // routes are black holes rather than refusals, those attempts time out instead of failing
      // fast and take the whole request with them, even though the IPv4 addresses are reachable.
      ...(forceIpv4 ? { family: 4 } : {}),
    }
  }
  if (bodyTimeoutMs !== undefined) dispatcherOptions.bodyTimeout = bodyTimeoutMs
  if (headersTimeoutMs !== undefined) dispatcherOptions.headersTimeout = headersTimeoutMs

  if (forceIpv4) log('Restricting connections to IPv4')
  if (connectTimeoutMs !== undefined) log(`Using connect timeout: ${connectTimeoutMs / 1000} seconds`)
  if (bodyTimeoutMs !== undefined) log(`Using body timeout: ${bodyTimeoutMs === 0 ? 'disabled' : `${bodyTimeoutMs / 1000} seconds`}`)
  if (headersTimeoutMs !== undefined) {
    log(`Using headers timeout: ${headersTimeoutMs === 0 ? 'disabled' : `${headersTimeoutMs / 1000} seconds`}`)
  }

  const enableProxy = args.includes('--enable-proxy')
  if (enableProxy) {
    // Use env proxy
    setGlobalDispatcher(new EnvHttpProxyAgent(dispatcherOptions))
    log('HTTP proxy support enabled - using system HTTP_PROXY/HTTPS_PROXY environment variables')
  } else if (Object.keys(dispatcherOptions).length > 0) {
    setGlobalDispatcher(new Agent(dispatcherOptions))
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
    } else if (value === LONG_POLL_PATH || value === MCP_REMOTE_ID_PATH) {
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

  // Derived, never probed. `findAvailablePort` used to bind the port, close it, and hand back the
  // number - so concurrent instances could each be told the same port was free, or be pushed onto
  // random ones, before any coordination ran. Whether the port is actually free is settled by
  // binding it for real, in coordinateAuth, where losing tells us somebody else owns the flow.
  let callbackPort: number
  if (specifiedPort) {
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else {
    log(`Using callback port derived from the server URL: ${defaultPort}`)
    callbackPort = defaultPort
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
