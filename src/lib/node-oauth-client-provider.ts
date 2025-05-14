import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile } from './mcp-auth-config'
import { getServerUrlHash, log, MCP_REMOTE_VERSION } from './utils'

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
  private clientId: string | undefined
  private clientSecret: string | undefined
  private scope: string | undefined
  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions & { clientId?: string, clientSecret?: string, scope?: string }) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.clientId = options.clientId
    this.clientSecret = options.clientSecret
    this.scope = options.scope
  }

  get redirectUrl(): string {
    return `http://localhost:${this.options.callbackPort}${this.callbackPath}`
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
      scope: this.scope,
    }
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    // log('Reading client info')
    if (this.clientId) {
      return {
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uris: [this.redirectUrl],
      }
    }
    return readJsonFile<OAuthClientInformationFull>(this.serverUrlHash, 'client_info.json', OAuthClientInformationFullSchema)
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    // log('Saving client info')
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    // log('Reading tokens')
    // console.log(new Error().stack)
    return readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    // log('Saving tokens')
    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)
    try {
      await open(authorizationUrl.toString())
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    // log('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    // log('Reading code verifier')
    return await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
  }
}
