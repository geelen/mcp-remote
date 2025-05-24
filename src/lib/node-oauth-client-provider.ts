import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { getServerUrlHash, log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string
  private softwareId: string
  private softwareVersion: string
  private staticOAuthClientMetadata: StaticOAuthClientMetadata
  private staticOAuthClientInfo: StaticOAuthClientInformationFull

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`;
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
      software_id: this.softwareId,
      software_version: this.softwareVersion,
      ...this.staticOAuthClientMetadata,
    }
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    if (DEBUG) await debugLog(this.serverUrlHash, 'Reading client info')
    if (this.staticOAuthClientInfo) {
      if (DEBUG) await debugLog(this.serverUrlHash, 'Returning static client info')
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(this.serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
    if (DEBUG) await debugLog(this.serverUrlHash, 'Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    if (DEBUG) await debugLog(this.serverUrlHash, 'Saving client info', { client_id: clientInformation.client_id })
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    if (DEBUG) {
      await debugLog(this.serverUrlHash, 'Reading OAuth tokens')
      await debugLog(this.serverUrlHash, 'Token request stack trace:', new Error().stack)
    }

    const tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (DEBUG) {
      if (tokens) {
        const timeLeft = tokens.expires_in || 0

        // Alert if expires_in is invalid
        if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
          await debugLog(this.serverUrlHash, '⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
            expiresIn: tokens.expires_in,
            tokenObject: JSON.stringify(tokens),
            stack: new Error('Invalid expires_in value').stack
          })
        }

        await debugLog(this.serverUrlHash, 'Token result:', {
          found: true,
          hasAccessToken: !!tokens.access_token,
          hasRefreshToken: !!tokens.refresh_token,
          expiresIn: `${timeLeft} seconds`,
          isExpired: timeLeft <= 0,
          expiresInValue: tokens.expires_in
        })
      } else {
        await debugLog(this.serverUrlHash, 'Token result: Not found')
      }
    }

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    if (DEBUG) {
      const timeLeft = tokens.expires_in || 0

      // Alert if expires_in is invalid
      if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
        await debugLog(this.serverUrlHash, '⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack
        })
      }

      await debugLog(this.serverUrlHash, 'Saving tokens', {
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresInValue: tokens.expires_in
      })
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    if (DEBUG) await debugLog(this.serverUrlHash, 'Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(authorizationUrl.toString())
      log('Browser opened automatically.')
      if (DEBUG) await debugLog(this.serverUrlHash, 'Browser opened automatically')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      if (DEBUG) await debugLog(this.serverUrlHash, 'Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (DEBUG) await debugLog(this.serverUrlHash, 'Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    if (DEBUG) await debugLog(this.serverUrlHash, 'Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    if (DEBUG) await debugLog(this.serverUrlHash, 'Code verifier found:', !!verifier)
    return verifier
  }
}
