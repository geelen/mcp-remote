import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformation,
  OAuthClientInformationFull,
  OAuthClientInformationSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, cleanServerConfig } from './mcp-auth-config'
import { getServerUrlHash, log } from './utils'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 */
export class NodeOAuthClientProvider implements OAuthClientProvider {
  private serverUrlHash: string
  private callbackPath: string
  private clientName: string
  private clientUri: string

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'

    // If clean flag is set, proactively clean all config files for this server
    if (options.clean) {
      cleanServerConfig(this.serverUrlHash).catch((err) => {
        log('Error cleaning server config:', err)
      })
    }
  }

  get redirectUrl(): string {
    return `http://127.0.0.1:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    return {
      redirect_uris: [this.redirectUrl],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      client_name: this.clientName,
      client_uri: this.clientUri,
    }
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformation | undefined> {
    // log('Reading client info')
    return readJsonFile<OAuthClientInformation>(this.serverUrlHash, 'client_info.json', OAuthClientInformationSchema, this.options.clean)
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
    return readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema, this.options.clean)
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
    return await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session', this.options.clean)
  }
}
