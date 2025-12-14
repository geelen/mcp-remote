import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { OAuthClientInformationFull, OAuthClientInformationFullSchema } from '@modelcontextprotocol/sdk/shared/auth.js'
import { OAuthCallbackServerOptions, StaticOAuthClientInformationFull, StaticOAuthClientMetadata } from './types'
import { getConfigDir, getConfigFilePath, readJsonFile } from './mcp-auth-config'
import express from 'express'
import net from 'net'
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

// Reconnection types
export type ReconnectFunction = () => Promise<Transport>
export interface ReconnectOptions {
  enabled: boolean
  maxAttempts: number
  baseDelayMs: number
  maxDelayMs?: number // Maximum delay between attempts (default: 30000)
  connectionTimeoutMs?: number // Timeout for each connection attempt (default: 10000)
}
export { MCP_REMOTE_VERSION }

const pid = process.pid
// Global debug flag
export let DEBUG = false

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
  // Using stderr so that it doesn't interfere with stdout
  console.error(`[${pid}] ${str}`, ...rest)

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
    pendingRequests.delete(messageId)
    return transformResponseFunction?.(originalRequest, message) ?? message
  }

  return {
    interceptRequest,
    interceptResponse,
  }
}

/**
 * Creates a bidirectional proxy between two transports with optional auto-reconnect
 * @param params The transport connections to proxy between
 */
export function mcpProxy({
  transportToClient,
  transportToServer,
  ignoredTools = [],
  reconnectFn,
  reconnectOptions = { enabled: false, maxAttempts: 5, baseDelayMs: 1000 },
}: {
  transportToClient: Transport
  transportToServer: Transport
  ignoredTools?: string[]
  reconnectFn?: ReconnectFunction
  reconnectOptions?: ReconnectOptions
}) {
  let transportToClientClosed = false
  let transportToServerClosed = false
  let currentTransportToServer = transportToServer
  let isReconnecting = false
  let reconnectAttempts = 0
  let connectionHealthy = true
  const pendingMessages: { message: Message; timestamp: number }[] = []
  const queuedMessageIds = new Set<string | number>() // Track queued message IDs to prevent duplicates
  const maxDelayMs = reconnectOptions.maxDelayMs ?? 15000
  const connectionTimeoutMs = reconnectOptions.connectionTimeoutMs ?? 5000
  const messageTimeoutMs = 60000 // Messages older than 60s will get error response
  const requestTimeoutMs = 5000 // If no response in 5s, assume connection is dead (reasonable for local gateway)
  const maxConsecutiveTimeouts = 3 // Exit process after this many consecutive timeouts
  let consecutiveTimeouts = 0
  const pendingRequests = new Map<string | number, { timeout: NodeJS.Timeout; message: Message }>()

  // Store the original initialize message to re-send after reconnection
  let savedInitializeMessage: Message | null = null
  let initializeIdCounter = 1000000 // Use high IDs for internal initialize messages to avoid conflicts

  // Helper to re-initialize MCP session after reconnection
  async function reinitializeMcpSession(transport: Transport): Promise<boolean> {
    if (!savedInitializeMessage) {
      log('[Reinit] No saved initialize message, skipping MCP re-initialization')
      return true // No initialize to send, consider it success
    }

    return new Promise((resolve) => {
      const initId = initializeIdCounter++
      const timeoutMs = 10000 // 10 second timeout for initialize

      log(`[Reinit] Re-initializing MCP session with ID ${initId}...`)

      // Create a new initialize message with our internal ID
      const initMessage = {
        jsonrpc: '2.0' as const,
        id: initId,
        method: 'initialize',
        params: savedInitializeMessage.params,
      }

      let resolved = false
      const timeout = setTimeout(() => {
        if (!resolved) {
          resolved = true
          log('[Reinit] Initialize timeout - MCP session re-initialization failed')
          resolve(false)
        }
      }, timeoutMs)

      // Temporarily intercept the response
      const originalOnMessage = transport.onmessage
      transport.onmessage = (response: any) => {
        // Check if this is the response to our initialize
        if (response.id === initId) {
          clearTimeout(timeout)
          if (!resolved) {
            resolved = true

            if (response.error) {
              log(`[Reinit] Initialize failed: ${response.error.message}`)
              transport.onmessage = originalOnMessage
              resolve(false)
              return
            }

            log('[Reinit] Initialize successful, sending notifications/initialized...')

            // Send notifications/initialized
            const initializedNotification = {
              jsonrpc: '2.0' as const,
              method: 'notifications/initialized',
            }

            transport.send(initializedNotification).then(() => {
              log('[Reinit] MCP session re-initialized successfully!')
              transport.onmessage = originalOnMessage
              resolve(true)
            }).catch((err) => {
              log('[Reinit] Failed to send initialized notification:', err)
              transport.onmessage = originalOnMessage
              resolve(false)
            })
          }
        } else {
          // Pass through other messages to original handler
          originalOnMessage?.(response)
        }
      }

      // Send the initialize message
      transport.send(initMessage).catch((err) => {
        clearTimeout(timeout)
        if (!resolved) {
          resolved = true
          log('[Reinit] Failed to send initialize:', err)
          transport.onmessage = originalOnMessage
          resolve(false)
        }
      })
    })
  }

  // Helper to send error response for a pending message
  function sendErrorForPendingMessage(pending: { message: Message; timestamp: number }, errorMessage: string) {
    if (pending.message.id) {
      const errorResponse = {
        jsonrpc: '2.0' as const,
        id: pending.message.id,
        error: {
          code: -32603,
          message: errorMessage,
        },
      }
      log(`[Error→Local] Sending error for message ${pending.message.id}: ${errorMessage}`)
      transportToClient.send(errorResponse).catch(onClientError)
    }
  }

  // Helper to flush expired messages with error responses
  function flushExpiredMessages() {
    const now = Date.now()
    const expiredIndices: number[] = []

    pendingMessages.forEach((pending, index) => {
      if (now - pending.timestamp > messageTimeoutMs) {
        if (pending.message.id) {
          queuedMessageIds.delete(pending.message.id)
        }
        sendErrorForPendingMessage(pending, 'Request timed out while waiting for server reconnection')
        expiredIndices.push(index)
      }
    })

    // Remove expired messages (in reverse to maintain indices)
    for (let i = expiredIndices.length - 1; i >= 0; i--) {
      pendingMessages.splice(expiredIndices[i], 1)
    }
  }

  // Helper to send errors for all pending messages
  function flushAllPendingMessagesWithError(errorMessage: string) {
    while (pendingMessages.length > 0) {
      const pending = pendingMessages.shift()!
      if (pending.message.id) {
        queuedMessageIds.delete(pending.message.id)
      }
      sendErrorForPendingMessage(pending, errorMessage)
    }
  }

  // Helper to queue a message for retry (prevents duplicates)
  function queueMessageForRetry(message: Message): boolean {
    if (message.id && queuedMessageIds.has(message.id)) {
      log(`[Queue] Message ${message.id} already queued, skipping duplicate`)
      return false
    }
    if (message.id) {
      queuedMessageIds.add(message.id)
    }
    pendingMessages.push({ message, timestamp: Date.now() })
    return true
  }

  // Helper to track a request and set up timeout
  function trackRequest(message: Message) {
    if (!message.id) return

    const timeout = setTimeout(() => {
      // Request timed out - server might be zombie
      log(`[Timeout] Request ${message.id} (${message.method}) timed out after ${requestTimeoutMs}ms`)
      const pending = pendingRequests.get(message.id)
      pendingRequests.delete(message.id)

      // Increment consecutive timeout counter
      consecutiveTimeouts++
      log(`[Timeout] Consecutive timeouts: ${consecutiveTimeouts}/${maxConsecutiveTimeouts}`)

      // Mark connection as unhealthy and trigger reconnection
      if (connectionHealthy && !isReconnecting) {
        log('[Timeout] Marking connection as unhealthy and triggering reconnection...')
        connectionHealthy = false

        // DON'T send error yet - queue the message for retry after reconnection
        if (pending) {
          log(`[Timeout] Queuing request ${message.id} for retry after reconnection...`)
          queueMessageForRetry(pending.message)
        }

        // Close current transport to trigger reconnection
        currentTransportToServer.close().catch(onServerError)
      } else if (isReconnecting) {
        // Already reconnecting - just queue for retry
        if (pending) {
          log(`[Timeout] Already reconnecting, queuing request ${message.id} for retry...`)
          queueMessageForRetry(pending.message)
        }
      } else {
        // Connection already marked unhealthy but not reconnecting yet - queue for retry
        if (pending) {
          log(`[Timeout] Connection unhealthy, queuing request ${message.id} for retry...`)
          queueMessageForRetry(pending.message)
        }
      }
    }, requestTimeoutMs)

    pendingRequests.set(message.id, { timeout, message })
  }

  // Helper to clear request tracking when response is received
  function clearRequestTracking(messageId: string | number) {
    const pending = pendingRequests.get(messageId)
    if (pending) {
      clearTimeout(pending.timeout)
      pendingRequests.delete(messageId)
      // Reset consecutive timeout counter on successful response
      if (consecutiveTimeouts > 0) {
        log(`[Recovery] Response received, resetting consecutive timeout counter (was ${consecutiveTimeouts})`)
        consecutiveTimeouts = 0
      }
    }
  }

  // Clear all pending request timeouts
  function clearAllRequestTracking() {
    for (const [id, pending] of pendingRequests) {
      clearTimeout(pending.timeout)
    }
    pendingRequests.clear()
  }

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

  function setupServerTransportHandlers(serverTransport: Transport) {
    serverTransport.onmessage = (_message) => {
      // TODO: fix types
      const message = messageTransformer.interceptResponse(_message as any)
      log('[Remote→Local]', message.method || message.id)

      // Clear the timeout for this request if it's a response
      if (message.id !== undefined) {
        clearRequestTracking(message.id)
      }

      debugLog('Remote → Local message', {
        method: message.method,
        id: message.id,
        result: message.result ? 'result-present' : undefined,
        error: message.error,
      })

      transportToClient.send(message).catch(onClientError)
    }

    serverTransport.onclose = async () => {
      if (transportToClientClosed) {
        return
      }

      // Clear all pending request timeouts since we're reconnecting
      clearAllRequestTracking()
      connectionHealthy = false

      // Check if auto-reconnect is enabled
      if (reconnectOptions.enabled && reconnectFn && reconnectAttempts < reconnectOptions.maxAttempts) {
        log(`Remote transport closed. Starting reconnection loop...`)
        debugLog('Remote transport closed, starting reconnection loop', { attempt: reconnectAttempts + 1 })

        isReconnecting = true

        // Reconnection loop with improved handling
        while (reconnectAttempts < reconnectOptions.maxAttempts && !transportToClientClosed) {
          reconnectAttempts++

          // Calculate delay with exponential backoff, capped at maxDelayMs
          const delay = Math.min(reconnectOptions.baseDelayMs * Math.pow(2, reconnectAttempts - 1), maxDelayMs)
          log(`Reconnect attempt ${reconnectAttempts}/${reconnectOptions.maxAttempts} - waiting ${delay}ms...`)

          await new Promise((resolve) => setTimeout(resolve, delay))

          // Flush any expired messages while waiting
          flushExpiredMessages()

          try {
            // Create a promise that rejects after timeout
            const timeoutPromise = new Promise<never>((_, reject) => {
              setTimeout(() => reject(new Error('Connection attempt timed out')), connectionTimeoutMs)
            })

            // Race between connection and timeout
            log('Attempting to connect to remote server...')
            const newTransport = await Promise.race([reconnectFn(), timeoutPromise])

            currentTransportToServer = newTransport
            setupServerTransportHandlers(newTransport)
            newTransport.onerror = onServerError

            log('Transport reconnected successfully!')
            debugLog('Transport reconnected successfully', { attempts: reconnectAttempts })

            // Re-initialize MCP session before sending queued messages
            log('[Reconnect] Re-initializing MCP session...')
            const reinitSuccess = await reinitializeMcpSession(newTransport)

            if (!reinitSuccess) {
              log('[Reconnect] MCP session re-initialization failed, will retry connection...')
              // Close this transport and try again
              newTransport.close().catch(() => {})
              continue // Try next reconnection attempt
            }

            // Reset state
            reconnectAttempts = 0
            isReconnecting = false
            connectionHealthy = true
            consecutiveTimeouts = 0 // Reset timeout counter on successful reconnect

            // Flush pending messages
            log(`Flushing ${pendingMessages.length} queued messages...`)
            while (pendingMessages.length > 0) {
              const pending = pendingMessages.shift()!
              // Remove from tracking set
              if (pending.message.id) {
                queuedMessageIds.delete(pending.message.id)
              }
              // Check if message hasn't expired
              if (Date.now() - pending.timestamp < messageTimeoutMs) {
                log('[Local→Remote] (queued)', pending.message.method || pending.message.id)
                // Track the request for timeout
                trackRequest(pending.message)
                currentTransportToServer.send(pending.message).catch(onServerError)
              } else {
                sendErrorForPendingMessage(pending, 'Request timed out while waiting for server reconnection')
              }
            }

            return // Successfully reconnected, exit the loop
          } catch (error) {
            log(`Reconnection attempt ${reconnectAttempts} failed:`, error)
            debugLog('Reconnection attempt failed', { error, attempts: reconnectAttempts })
            // Continue to next iteration
          }
        }

        // If we get here, all reconnection attempts failed
        log(`Max reconnect attempts (${reconnectOptions.maxAttempts}) reached. Closing connection.`)
        debugLog('Max reconnect attempts reached', { attempts: reconnectAttempts })

        // Send errors for all pending messages
        flushAllPendingMessagesWithError('Server connection lost and reconnection failed')

        transportToServerClosed = true
        isReconnecting = false
        connectionHealthy = false
        transportToClient.close().catch(onClientError)
      } else {
        transportToServerClosed = true
        connectionHealthy = false
        debugLog('Remote transport closed, closing local transport')

        // Send errors for any pending messages
        flushAllPendingMessagesWithError('Server connection closed')

        transportToClient.close().catch(onClientError)
      }
    }

    serverTransport.onerror = onServerError
  }

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
      const { clientInfo } = message.params
      if (clientInfo) clientInfo.name = `${clientInfo.name} (via mcp-remote ${MCP_REMOTE_VERSION})`
      log(JSON.stringify(message, null, 2))

      // Save the initialize message for potential re-initialization after reconnect
      savedInitializeMessage = { ...message }
      log('[Init] Saved initialize message for potential reconnection')

      debugLog('Initialize message with modified client info', { clientInfo })
    }

    // If reconnecting or connection is unhealthy, queue the message
    if (isReconnecting || !connectionHealthy) {
      log('[Local→Remote] (queuing during reconnect)', message.method || message.id)
      queueMessageForRetry(message)

      // Warn if queue is getting large
      if (pendingMessages.length % 10 === 0) {
        log(`Warning: ${pendingMessages.length} messages queued waiting for reconnection`)
      }
      return
    }

    // Track requests that expect a response (have an id)
    trackRequest(message)

    currentTransportToServer.send(message).catch((error) => {
      // Clear the timeout since send failed
      if (message.id !== undefined) {
        clearRequestTracking(message.id)
      }
      // If send fails, the connection might have just died
      // Queue the message and trigger reconnection handling
      log('[Local→Remote] Send failed, queuing message:', error)
      queueMessageForRetry(message)
      connectionHealthy = false
      onServerError(error)
    })
  }

  // Set up handlers for the initial server transport
  setupServerTransportHandlers(transportToServer)

  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return
    }

    transportToClientClosed = true
    debugLog('Local transport closed, closing remote transport')
    currentTransportToServer.close().catch(onServerError)
  }

  transportToClient.onerror = onClientError

  function onClientError(error: Error) {
    log('Error from local client:', error)
    debugLog('Error from local client', { stack: error.stack })
  }

  function onServerError(error: Error) {
    log('Error from remote server:', error)
    debugLog('Error from remote server', { stack: error.stack })
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
        const testClient = new Client({ name: 'mcp-remote-fallback-test', version: '0.0.0' }, { capabilities: {} })
        await testClient.connect(testTransport)
      }
    }
    log(`Connected to remote server using ${transport.constructor.name}`)

    return transport
  } catch (error: any) {
    // Check if it's a protocol error and we should attempt fallback
    if (
      error instanceof Error &&
      shouldAttemptFallback &&
      (error.message.includes('405') ||
        error.message.includes('Method Not Allowed') ||
        error.message.includes('404') ||
        error.message.includes('Not Found'))
    ) {
      log(`Received error: ${error.message}`)

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
        await transport.finishAuth(code)
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
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServerWithLongPoll(options: OAuthCallbackServerOptions) {
  let authCode: string | null = null
  const app = express()

  // Create a promise to track when auth is completed
  let authCompletedResolve: (code: string) => void
  const authCompletedPromise = new Promise<string>((resolve) => {
    authCompletedResolve = resolve
  })

  // Long-polling endpoint
  app.get('/wait-for-auth', (req, res) => {
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

  const server = app.listen(options.port, () => {
    log(`OAuth callback server running at http://127.0.0.1:${options.port}`)
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

  return { server, authCode, waitForAuthCode, authCompletedPromise }
}

/**
 * Sets up an Express server to handle OAuth callbacks
 * @param options The server options
 * @returns An object with the server, authCode, and waitForAuthCode function
 */
export function setupOAuthCallbackServer(options: OAuthCallbackServerOptions) {
  const { server, authCode, waitForAuthCode } = setupOAuthCallbackServerWithLongPoll(options)
  return { server, authCode, waitForAuthCode }
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
    throw new Error('Cannot find localhost callback URI from existing client information')
  }

  return parseInt(localhostRedirectUri.port)
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
  let host = 'localhost' // Default
  const hostIndex = args.indexOf('--host')
  if (hostIndex !== -1 && hostIndex < args.length - 1) {
    host = args[hostIndex + 1]
    log(`Using callback hostname: ${host}`)
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

  // Parse resource to authorize
  let authorizeResource = '' // Default
  const resourceIndex = args.indexOf('--resource')
  if (resourceIndex !== -1 && resourceIndex < args.length - 1) {
    authorizeResource = args[resourceIndex + 1]
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

  // Parse auto-reconnect options
  const autoReconnect = args.includes('--auto-reconnect')
  let maxReconnectAttempts = 20 // Default (enough attempts for gateway restarts)
  const maxReconnectAttemptsIndex = args.indexOf('--max-reconnect-attempts')
  if (maxReconnectAttemptsIndex !== -1 && maxReconnectAttemptsIndex < args.length - 1) {
    const value = parseInt(args[maxReconnectAttemptsIndex + 1], 10)
    if (!isNaN(value) && value > 0) {
      maxReconnectAttempts = value
      log(`Using max reconnect attempts: ${maxReconnectAttempts}`)
    } else {
      log(`Warning: Ignoring invalid --max-reconnect-attempts value: ${args[maxReconnectAttemptsIndex + 1]}. Must be a positive number.`)
    }
  }

  let reconnectDelayMs = 1000 // Default 1 second
  const reconnectDelayIndex = args.indexOf('--reconnect-delay')
  if (reconnectDelayIndex !== -1 && reconnectDelayIndex < args.length - 1) {
    const value = parseInt(args[reconnectDelayIndex + 1], 10)
    if (!isNaN(value) && value > 0) {
      reconnectDelayMs = value
      log(`Using reconnect delay: ${reconnectDelayMs}ms`)
    } else {
      log(`Warning: Ignoring invalid --reconnect-delay value: ${args[reconnectDelayIndex + 1]}. Must be a positive number.`)
    }
  }

  let maxReconnectDelayMs = 15000 // Default 15 seconds max (reasonable for local gateways)
  const maxReconnectDelayIndex = args.indexOf('--max-reconnect-delay')
  if (maxReconnectDelayIndex !== -1 && maxReconnectDelayIndex < args.length - 1) {
    const value = parseInt(args[maxReconnectDelayIndex + 1], 10)
    if (!isNaN(value) && value > 0) {
      maxReconnectDelayMs = value
      log(`Using max reconnect delay: ${maxReconnectDelayMs}ms`)
    } else {
      log(`Warning: Ignoring invalid --max-reconnect-delay value: ${args[maxReconnectDelayIndex + 1]}. Must be a positive number.`)
    }
  }

  let connectionTimeoutMs = 5000 // Default 5 seconds timeout per connection attempt (fast fail for local)
  const connectionTimeoutIndex = args.indexOf('--connection-timeout')
  if (connectionTimeoutIndex !== -1 && connectionTimeoutIndex < args.length - 1) {
    const value = parseInt(args[connectionTimeoutIndex + 1], 10)
    if (!isNaN(value) && value > 0) {
      connectionTimeoutMs = value
      log(`Using connection timeout: ${connectionTimeoutMs}ms`)
    } else {
      log(`Warning: Ignoring invalid --connection-timeout value: ${args[connectionTimeoutIndex + 1]}. Must be a positive number.`)
    }
  }

  const reconnectOptions: ReconnectOptions = {
    enabled: autoReconnect,
    maxAttempts: maxReconnectAttempts,
    baseDelayMs: reconnectDelayMs,
    maxDelayMs: maxReconnectDelayMs,
    connectionTimeoutMs: connectionTimeoutMs,
  }

  if (autoReconnect) {
    log(`Auto-reconnect enabled: max ${maxReconnectAttempts} attempts, base delay ${reconnectDelayMs}ms, max delay ${maxReconnectDelayMs}ms, timeout ${connectionTimeoutMs}ms`)
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
    if (existingClientPort && specifiedPort !== existingClientPort) {
      log(
        `Warning! Specified callback port of ${specifiedPort}, which conflicts with existing client registration port ${existingClientPort}. Deleting existing client data to force reregistration.`,
      )
      await rm(getConfigFilePath(serverUrlHash, 'client_info.json'))
    }
    log(`Using specified callback port: ${specifiedPort}`)
    callbackPort = specifiedPort
  } else if (existingClientPort) {
    log(`Using existing client port: ${existingClientPort}`)
    callbackPort = existingClientPort
  } else {
    log(`Using automatically selected callback port: ${availablePort}`)
    callbackPort = availablePort
  }

  if (Object.keys(headers).length > 0) {
    log(`Using custom headers: ${JSON.stringify(headers)}`)
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
    reconnectOptions,
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
