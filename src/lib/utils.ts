import { OAuthClientProvider, UnauthorizedError } from '@modelcontextprotocol/sdk/client/auth.js'
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js'
import { Transport } from '@modelcontextprotocol/sdk/shared/transport.js'
import { OAuthCallbackServerOptions } from './types'
import express from 'express'
import net from 'net'
import crypto from 'crypto'

const iv = crypto.randomBytes(16);
const algorithm = 'aes-256-cbc';

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
 * Encyrypt data
 * @param data The data to be encryppted
 * @param secretKey The secret key that is used, along with an IV, to encrypt data
 * @returns An encrypted string
 */
export function encrypt(data: string, secretKey: string) {

  const key = crypto
  .createHash("sha512")
  .update(secretKey)
  .digest("hex")
  .substring(0, 32);

  const cipher = crypto.createCipheriv(algorithm, Buffer.from(key), iv);
  let encrypted = cipher.update(data, "utf-8", "hex");
  encrypted += cipher.final("hex");

  // Package the IV and encrypted data together so it can be stored in a single
  // column in the database.
  return iv.toString("hex") + encrypted;
}

/**
 * Decrypt data
 * @param data The data to be decrypted
 * @param secretKey The secret key that is used, along with an IV, to decrypt data
 * @returns A decrypted string
 */
export function decrypt(data: string, secretKey: string) {

  const key = crypto
  .createHash("sha512")
  .update(secretKey)
  .digest("hex")
  .substring(0, 32);

  // Unpackage the combined iv + encrypted message. Since we are using a fixed
  // size IV, we can hard code the slice length.
  const inputIV = data.slice(0, 32);
  const encrypted = data.slice(32);
  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(key),
    Buffer.from(inputIV, "hex"),
  );

  let decrypted = decipher.update(encrypted, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
}

/**
 * Creates a headers object
 * @param headers A string that is passed in the arguments, from the AI client config file; the argument is preceded by another argument called --headers
 * @param keysForEncryption The header object keys, whose values require encryption
 * @param secretKey The secret key that is used, along with an IV, to encrypt/decrypt data
 * @returns A headers object
 */
export function parseHeaders(
  headers: string,
  keysForEncryption: string,
  secretKey: string
): any {
  const headersArr = headers.split(',');
  let credentials: any = {};
  if (headersArr.length > 0) {
    headersArr.map((val, idx) => {
      const keyValArr = val.split(':');
      let k = '';
      let v = '';
      keyValArr.map((val, idx) => {
        if (idx === 0) {
          k = val.toLowerCase().trim();
        } else {
          v = val.trim();
        }
      });
      if (k !== '') {
        credentials[k] = v;
      }
    });
    const keysForEncryptionArr = keysForEncryption.split(',');
    for (const property in credentials) {
      const found = keysForEncryptionArr.find(
        (element) => element === property
      );
      if (found && secretKey in credentials) {
        const encrypted = encrypt(credentials[property], credentials[secretKey]);
        const decrypted = decrypt(encrypted, credentials[secretKey]);
        credentials[property] = encrypted;
        // now delete the secret so that it is not sent to the remote MCP server via SSE transport
        delete credentials[secretKey];
      }
    }
  }
  return credentials;
}

/**
 * Creates and connects to a remote SSE server with OAuth authentication
 * @param serverUrl The URL of the remote server
 * @param authProvider The OAuth client provider
 * @param waitForAuthCode Function to wait for the auth code
 * @param skipBrowserAuth Whether to skip browser auth and use shared auth
 * @returns The connected SSE client transport
 */
export async function connectToRemoteServer(
  serverUrl: string,
  authProvider: OAuthClientProvider,
  waitForAuthCode: () => Promise<string>,
  skipBrowserAuth: boolean = false, 
  headers: string = '',
): Promise<SSEClientTransport> {
  log(`[${pid}] Connecting to remote server: ${serverUrl}`)
  const url = new URL(serverUrl)

  const credentials = parseHeaders(headers, 'password', 'secret');

  const requestInit = {
    body: headers,
    headers: credentials
  }
  const transport = new SSEClientTransport(url, { 
    authProvider, 
    requestInit 
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
        const newTransport = new SSEClientTransport(url, { 
          authProvider, 
          requestInit 
        })
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
 * @returns A promise that resolves to an object with parsed serverUrl, callbackPort, and clean flag
 */
export async function parseCommandLineArgs(args: string[], defaultPort: number, usage: string) {
  // Check for --clean flag
  const cleanIndex = args.indexOf('--clean')
  const clean = cleanIndex !== -1

  // Remove the flag from args if it exists
  if (clean) {
    args.splice(cleanIndex, 1)
  }

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

  if (clean) {
    log('Clean mode enabled: config files will be reset before reading')
  }

  // Check for --header flag
  const headerIndex = args.indexOf('--header')
  const header = headerIndex !== -1
  const headerValueIndex = headerIndex + 1
  let headers = ''


  // Remove the flag from args if it exists
  if (header) {
    if (headerValueIndex) {
      headers = args[headerValueIndex]
      args.splice(headerIndex, 2)
    }
  }

  return { serverUrl, callbackPort, clean, headers }
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
