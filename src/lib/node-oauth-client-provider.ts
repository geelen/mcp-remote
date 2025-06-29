import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata, AzureAuthOptions, AuthType } from './types'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile } from './mcp-auth-config'
import { StaticOAuthClientInformationFull } from './types'
import { getServerUrlHash, log, debugLog, DEBUG, MCP_REMOTE_VERSION } from './utils'
import { randomUUID } from 'node:crypto'

// Azure Identity imports
import { InteractiveBrowserCredential, AccessToken } from '@azure/identity'

/**
 * Implements the OAuthClientProvider interface for Node.js environments.
 * Handles OAuth flow and token storage for MCP clients.
 * Also supports Azure Identity authentication.
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
  private _state: string
  
  // Azure Identity properties
  private azureCredential?: InteractiveBrowserCredential
  private azureScopes?: string[]
  private azureOptions?: AzureAuthOptions
  private authType: AuthType

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   * @param authType Authentication type (oauth or azure)
   * @param azureOptions Azure configuration options (if using Azure auth)
   */
  constructor(readonly options: OAuthProviderOptions, authType: AuthType = 'oauth', azureOptions?: AzureAuthOptions) {
    this.serverUrlHash = getServerUrlHash(options.serverUrl)
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this._state = randomUUID()
    this.authType = authType
    this.azureOptions = azureOptions

    // Initialize Azure Identity if using Azure auth
    if (this.authType === 'azure' && this.azureOptions) {
      this.initializeAzureCredential()
    }
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
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

  state(): string {
    return this._state
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    if (DEBUG) debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      if (DEBUG) debugLog('Returning static client info')
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )
    if (DEBUG) debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    if (DEBUG) debugLog('Saving client info', { client_id: clientInformation.client_id })
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    if (this.authType === 'azure') {
      return await this.getAzureTokens()
    }

    if (DEBUG) {
      debugLog('Reading OAuth tokens')
      debugLog('Token request stack trace:', new Error().stack)
    }

    const tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

    if (DEBUG) {
      if (tokens) {
        const timeLeft = tokens.expires_in || 0

        // Alert if expires_in is invalid
        if (typeof tokens.expires_in !== 'number' || tokens.expires_in < 0) {
          debugLog('⚠️ WARNING: Invalid expires_in detected while reading tokens ⚠️', {
            expiresIn: tokens.expires_in,
            tokenObject: JSON.stringify(tokens),
            stack: new Error('Invalid expires_in value').stack,
          })
        }

        debugLog('Token result:', {
          found: true,
          hasAccessToken: !!tokens.access_token,
          hasRefreshToken: !!tokens.refresh_token,
          expiresIn: `${timeLeft} seconds`,
          isExpired: timeLeft <= 0,
          expiresInValue: tokens.expires_in,
        })
      } else {
        debugLog('Token result: Not found')
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
        debugLog('⚠️ WARNING: Invalid expires_in detected in tokens ⚠️', {
          expiresIn: tokens.expires_in,
          tokenObject: JSON.stringify(tokens),
          stack: new Error('Invalid expires_in value').stack,
        })
      }

      debugLog('Saving tokens', {
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresInValue: tokens.expires_in,
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

    if (DEBUG) debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await open(authorizationUrl.toString())
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      if (DEBUG) debugLog('Failed to open browser', error)
    }
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (DEBUG) debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, 'code_verifier.txt', codeVerifier)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    if (DEBUG) debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    if (DEBUG) debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    if (DEBUG) debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        if (DEBUG) debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        if (DEBUG) debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        if (DEBUG) debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, 'code_verifier.txt')
        if (DEBUG) debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }

  /**
   * Initializes the Azure credential for authentication
   * @private
   */
  private initializeAzureCredential(): void {
    if (!this.azureOptions) {
      throw new Error('Azure options are required for Azure authentication')
    }

    if (DEBUG) debugLog('Initializing Azure credential', {
      tenantId: this.azureOptions.tenantId,
      clientId: this.azureOptions.clientId,
      scopes: this.azureOptions.scopes
    })

    // Create the Interactive Browser Credential
    this.azureCredential = new InteractiveBrowserCredential({
      clientId: this.azureOptions.clientId,
      tenantId: this.azureOptions.tenantId,
      redirectUri: this.azureOptions.redirectUri || `http://localhost:${this.options.callbackPort}/azure/callback`
    })

    // Store scopes for token requests
    this.azureScopes = this.azureOptions.scopes

    if (DEBUG) debugLog('Azure credential initialized successfully')
  }

  /**
   * Gets Azure tokens using the Azure Identity SDK
   * @returns OAuth-compatible tokens from Azure
   * @private
   */
  private async getAzureTokens(): Promise<OAuthTokens | undefined> {
    if (!this.azureCredential || !this.azureScopes) {
      throw new Error('Azure credential not initialized. Call initializeAzureCredential first.')
    }

    if (DEBUG) debugLog('Getting Azure tokens')

    try {
      // Get token from Azure Identity SDK
      const azureToken: AccessToken = await this.azureCredential.getToken(this.azureScopes)

      if (DEBUG) debugLog('Azure token obtained successfully', {
        expiresOn: azureToken.expiresOnTimestamp,
        timeUntilExpiry: Math.floor((azureToken.expiresOnTimestamp - Date.now()) / 1000)
      })

      // Convert Azure token to OAuth-compatible format
      const oauthTokens: OAuthTokens = {
        access_token: azureToken.token,
        token_type: 'Bearer',
        expires_in: Math.floor((azureToken.expiresOnTimestamp - Date.now()) / 1000),
        // Azure tokens don't have refresh tokens in this flow
        // The Azure Identity SDK handles refresh automatically
      }

      return oauthTokens
    } catch (error) {
      log('Error getting Azure token:', error)
      if (DEBUG) debugLog('Azure token error details', {
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      })
      throw error
    }
  }

  /**
   * Initializes Azure authentication if not already done
   * This method can be called to ensure Azure auth is ready
   */
  public async initializeAzureAuth(): Promise<void> {
    if (this.authType !== 'azure') {
      return
    }

    if (!this.azureCredential) {
      this.initializeAzureCredential()
    }

    // Trigger initial authentication by requesting a token
    // This will open the browser for interactive authentication
    await this.getAzureTokens()
    
    log('Azure authentication completed successfully')
  }
}
