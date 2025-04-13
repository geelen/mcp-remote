import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthCallbackServerOptions } from './types'
import express from 'express'
import net from 'net'
import crypto from 'crypto'

// Package version from package.json
export const MCP_REMOTE_VERSION = require('../../package.json').version

const pid = process.pid
export function log(str: string, ...rest: unknown[]) {
  // Using stderr so that it doesn't interfere with stdout
  console.error(`[${pid}] ${str}`, ...rest)
}

/**
 * Creates a bidirectional proxy between two transports
 * @param params The transport connections to proxy between
 */
export function mcpProxy({ transportToClient, transportToServer }: { transportToClient: Transport; transportToServer: Transport }) {
  let transportToClientClosed = false
  let transportToServerClosed = false

  transportToClient.onmessage = (message) => {
    // @ts-expect-error TODO
    log('[Local→Remote]', message.method || message.id)
    transportToServer.send(message).catch(onServerError)
  }

  transportToServer.onmessage = (message) => {
    // @ts-expect-error TODO: fix this type
    log('[Remote→Local]', message.method || message.id)
    transportToClient.send(message).catch(onClientError)
  }

  transportToClient.onclose = () => {
    if (transportToServerClosed) {
      return
    }

    transportToClientClosed = true
    transportToServer.close().catch(onServerError)
  }

  transportToServer.onclose = () => {
    if (transportToClientClosed) {
      return
    }
    transportToServerClosed = true
    transportToClient.close().catch(onClientError)
  }

  transportToClient.onerror = onClientError
  transportToServer.onerror = onServerError

  function onClientError(error: Error) {
    log('Error from local client:', error)
  }

  function onServerError(error: Error) {
    log('Error from remote server:', error)
  }
}

/**
 * Creates and connects to a remote SSE server with OAuth authentication
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param headers Additional headers to send with the request
 * @param waitForAuthCode Function to wait for the auth code
 * @param skipBrowserAuth Whether to skip browser auth and use shared auth
 * @returns The connected SSE client transport
 */
export async function connectToRemoteServer(
  serverUrl: string,
  authProvider: OAuthClientProvider,
  headers: Record<string, string>,
  waitForAuthCode: () => Promise<string>,
  skipBrowserAuth: boolean = false,
): Promise<SSEClientTransport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  // Create transport with eventSourceInit to pass Authorization header if present
  const eventSourceInit = {
    fetch: (url: string | URL, init?: RequestInit) => {
      return Promise.resolve(authProvider?.tokens?.()).then((tokens) =>
        fetch(url, {
          ...init,
          headers: {
            ...(init?.headers as Record<string, string> | undefined),
            ...headers,
            ...(tokens?.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
            Accept: "text/event-stream",
          } as Record<string, string>,
        })
      );
    },
  };

  const transport = new SSEClientTransport(url, {
    authProvider,
    requestInit: { headers },
    eventSourceInit,
  })

  try {
    await transport.start()
    log('Connected to remote server')
    return transport
  } catch (error) {
    if (error instanceof UnauthorizedError || (error instanceof Error && error.message.includes('Unauthorized'))) {
      if (skipBrowserAuth) {
        log('Authentication required but skipping browser auth - using shared auth')
      } else {
        log('Authentication required. Waiting for authorization...')
      }

      // Wait for the authorization code from the callback
      const code = await waitForAuthCode()

      try {
        log('Completing authorization...')
        await transport.finishAuth(code)

        // Create a new transport after auth
        const newTransport = new SSEClientTransport(url, { authProvider, requestInit: { headers } })
        await newTransport.start()
        log('Connected to remote server after authentication')
        return newTransport
      } catch (authError) {
        log('Authorization error:', authError)
        throw authError
      }
    } else {
      log('Connection error:', error)
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
    }, 30000)

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

    res.send('Authorization successful! You may close this window and return to the CLI.')

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
 * @param defaultPort Default port for the callback server if specified port is unavailable
 * @param usage Usage message to show on error
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort and headers
 */
export async function parseCommandLineArgs(args: string[], defaultPort: number, usage: string) {
  // Process headers
  const headers: Record<string, string> = {}
  args.forEach((arg, i) => {
    if (arg === '--header' && i < args.length - 1) {
      const value = args[i + 1]
      const match = value.match(/^([A-Za-z0-9_-]+):(.*)$/)
      if (match) {
        headers[match[1]] = match[2]
      } else {
        log(`Warning: ignoring invalid header argument: ${value}`)
      }
      args.splice(i, 2)
    }
  })

  const serverUrl = args[0]
  const specifiedPort = args[1] ? parseInt(args[1]) : undefined

  if (!serverUrl) {
    log(usage)
    process.exit(1)
  }

  const url = new URL(serverUrl)
  const isLocalhost = (url.hostname === 'localhost' || url.hostname === '127.0.0.1') && url.protocol === 'http:'

  if (!(url.protocol == 'https:' || isLocalhost)) {
    log(usage)
    process.exit(1)
  }

  // Use the specified port, or find an available one
  const callbackPort = specifiedPort || (await findAvailablePort(defaultPort))

  if (specifiedPort) {
    log(`Using specified callback port: ${callbackPort}`)
  } else {
    log(`Using automatically selected callback port: ${callbackPort}`)
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

  return { serverUrl, callbackPort, headers }
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
}

/**
 * Generates a hash for the server URL to use in filenames
 * @param serverUrl The server URL to hash
 * @returns The hashed server URL
 */
export function getServerUrlHash(serverUrl: string): string {
  return crypto.createHash('md5').update(serverUrl).digest('hex')
}
