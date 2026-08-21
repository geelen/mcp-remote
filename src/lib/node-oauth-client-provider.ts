import open from 'open'
import { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import type { OAuthProviderOptions, StaticOAuthClientMetadata } from './types'
import { readJsonFile, writeJsonFile, readTextFile, deleteConfigFile } from './mcp-auth-config'
import {
  OAuthAuthorizationPendingError,
  OAuthCallbackStateError,
  OAuthTokenVerificationPendingError,
  StaticOAuthClientInformationFull,
} from './types'
import { log, debugLog, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'
import { StaleClientRegistrationError } from './stale-client-registration-error'

type ClientRegistrationSource = 'cached-dynamic' | 'fresh-dynamic' | 'static' | undefined
type AuthorizationState = 'ready' | 'authorizing' | 'verifying'

type AuthorizationTransaction = {
  version: 1
  state: string
  codeVerifier: string
  createdAt: number
}

const AuthorizationTransactionSchema = {
  async parseAsync(value: unknown): Promise<AuthorizationTransaction | null> {
    if (!value || typeof value !== 'object') {
      return null
    }

    const candidate = value as Record<string, unknown>
    if (
      candidate.version !== 1 ||
      typeof candidate.state !== 'string' ||
      typeof candidate.codeVerifier !== 'string' ||
      typeof candidate.createdAt !== 'number'
    ) {
      return null
    }

    return candidate as AuthorizationTransaction
  },
}

function isStaleClientRegistrationResponse(response: unknown): boolean {
  if (!response || typeof response !== 'object') {
    return false
  }

  const { registration_endpoint: registrationEndpoint, error_description: errorDescription } = response as Record<string, unknown>
  return (
    typeof registrationEndpoint === 'string' &&
    typeof errorDescription === 'string' &&
    /\bclient(?:\s+id)?\b\s+(?:['"][^'"]+['"]\s+)?is\s+not[\s-]+registered\b/i.test(errorDescription)
  )
}

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
  private authorizeResource: string | undefined
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private clientRegistrationSource: ClientRegistrationSource
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  private authorizationState: AuthorizationState
  private callbackState: string | undefined
  private authorizationPrepared = false
  private sharedAuthorization = false
  private authorizationExchangeState = new AsyncLocalStorage<string>()

  /**
   * Creates a new NodeOAuthClientProvider
   * @param options Configuration options for the provider
   */
  constructor(readonly options: OAuthProviderOptions) {
    this.serverUrlHash = options.serverUrlHash
    this.callbackPath = options.callbackPath || '/oauth/callback'
    this.clientName = options.clientName || 'MCP CLI Client'
    this.clientUri = options.clientUri || 'https://github.com/modelcontextprotocol/mcp-cli'
    this.softwareId = options.softwareId || '2e6dc280-f3c3-4e01-99a7-8181dbd1d23d'
    this.softwareVersion = options.softwareVersion || MCP_REMOTE_VERSION
    this.staticOAuthClientMetadata = options.staticOAuthClientMetadata
    this.staticOAuthClientInfo = options.staticOAuthClientInfo
    this.authorizeResource = options.authorizeResource
    this._state = randomUUID()
    this._clientInfo = undefined
    this.clientRegistrationSource = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope
    this.authorizationState = 'ready'
    this.callbackState = undefined
  }

  /**
   * Marks a successfully processed MCP response as proof that the most
   * recently exchanged token is accepted by the remote resource server.
   */
  async markRemoteAuthorizationVerified(): Promise<void> {
    if (this.authorizationState !== 'verifying') {
      return
    }

    await Promise.all([
      deleteConfigFile(this.serverUrlHash, 'authorization.json'),
      deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
    ])
    this.resetAuthorizationState()
  }

  get redirectUrl(): string {
    return `http://${this.options.host}:${this.options.callbackPort}${this.callbackPath}`
  }

  get clientMetadata() {
    const effectiveScope = this.getEffectiveScope()
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
      scope: effectiveScope,
    }
  }

  state(): string {
    return this._state
  }

  /**
   * Gets the authorization server metadata, fetching it if not already available
   * @returns The authorization server metadata, or undefined if unavailable
   */
  async getAuthorizationServerMetadata(): Promise<AuthorizationServerMetadata | undefined> {
    // Already have metadata? Return it
    debugLog(`authorizationServerMetadata: ${JSON.stringify(this.authorizationServerMetadata)}`)
    if (this.authorizationServerMetadata) {
      return this.authorizationServerMetadata
    }

    // Fetch metadata and cache in memory for this session
    try {
      this.authorizationServerMetadata = await fetchAuthorizationServerMetadata(this.options.serverUrl)
      if (this.authorizationServerMetadata?.scopes_supported) {
        debugLog('Authorization server supports scopes', {
          scopes_supported: this.authorizationServerMetadata.scopes_supported,
        })
      }
      return this.authorizationServerMetadata
    } catch (error) {
      debugLog('Failed to fetch authorization server metadata', error)
      return undefined
    }
  }

  private getEffectiveScope(): string {
    // Priority 1: User-provided scope from staticOAuthClientMetadata (highest priority)
    if (this.staticOAuthClientMetadata?.scope && this.staticOAuthClientMetadata.scope.trim().length > 0) {
      debugLog('Using scope from staticOAuthClientMetadata', { scope: this.staticOAuthClientMetadata.scope })
      return this.staticOAuthClientMetadata.scope
    }

    // Priority 2: Scope from WWW-Authenticate header (per MCP spec)
    if (this.wwwAuthenticateScope && this.wwwAuthenticateScope.trim().length > 0) {
      debugLog('Using scope from WWW-Authenticate header', { scope: this.wwwAuthenticateScope })
      return this.wwwAuthenticateScope
    }

    // Priority 3: Scopes from Protected Resource Metadata (RFC 9728)
    if (this.protectedResourceMetadata?.scopes_supported?.length) {
      const scope = this.protectedResourceMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: this.protectedResourceMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if available
    if (this.authorizationServerMetadata?.scopes_supported?.length) {
      const scope = this.authorizationServerMetadata.scopes_supported.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: this.authorizationServerMetadata.scopes_supported,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default
    debugLog('Using fallback default scope')
    return 'openid email profile'
  }

  /**
   * Gets the client information if it exists
   * @returns The client information or undefined
   */
  async clientInformation(): Promise<OAuthClientInformationFull | undefined> {
    debugLog('Reading client info')
    if (this.staticOAuthClientInfo) {
      debugLog('Returning static client info')
      this._clientInfo = this.staticOAuthClientInfo
      this.clientRegistrationSource = 'static'
      return this.staticOAuthClientInfo
    }
    const clientInfo = await readJsonFile<OAuthClientInformationFull>(
      this.serverUrlHash,
      'client_info.json',
      OAuthClientInformationFullSchema,
    )

    if (clientInfo) {
      this._clientInfo = clientInfo
      if (this.clientRegistrationSource !== 'fresh-dynamic') {
        this.clientRegistrationSource = 'cached-dynamic'
      }
    }

    debugLog('Client info result:', clientInfo ? 'Found' : 'Not found')
    return clientInfo
  }

  /**
   * Saves client information
   * @param clientInformation The client information to save
   */
  async saveClientInformation(clientInformation: OAuthClientInformationFull): Promise<void> {
    debugLog('Saving client info', { client_id: clientInformation.client_id })
    this._clientInfo = clientInformation
    this.clientRegistrationSource = 'fresh-dynamic'
    await writeJsonFile(this.serverUrlHash, 'client_info.json', clientInformation)
  }

  /**
   * Gets the OAuth tokens if they exist
   * @returns The OAuth tokens or undefined
   */
  async tokens(): Promise<OAuthTokens | undefined> {
    debugLog('Reading OAuth tokens')
    debugLog('Token request stack trace:', new Error().stack)

    const tokens = await readJsonFile<OAuthTokens>(this.serverUrlHash, 'tokens.json', OAuthTokensSchema)

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

    return tokens
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const exchangeState = this.authorizationExchangeState.getStore()
    if (exchangeState && exchangeState !== this.callbackState) {
      debugLog('Ignoring tokens from a retired OAuth authorization exchange')
      return
    }
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

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokens)
    this.authorizationState = 'verifying'
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.authorizationState === 'verifying') {
      throw new OAuthTokenVerificationPendingError()
    }

    if (this.authorizationState === 'authorizing') {
      const transaction = await this.readAuthorizationTransaction()
      if (!transaction || transaction.state !== authorizationUrl.searchParams.get('state')) {
        throw new OAuthAuthorizationPendingError()
      }
    } else {
      await this.prepareAuthorization()
      if (this.sharedAuthorization) {
        return
      }
      this.authorizationState = 'authorizing'
    }

    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    if (this.authorizeResource) {
      authorizationUrl.searchParams.set('resource', this.authorizeResource)
    }

    const effectiveScope = this.getEffectiveScope()
    authorizationUrl.searchParams.set('scope', effectiveScope)
    debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    try {
      await this.preflightDynamicClientRegistration(authorizationUrl)
    } catch (error) {
      this.authorizationState = 'ready'
      throw error
    }

    try {
      await open(sanitizeUrl(authorizationUrl.toString()))
      log('Browser opened automatically.')
    } catch (error) {
      log('Could not open browser automatically. Please copy and paste the URL above into your browser.')
      debugLog('Failed to open browser', error)
    }
  }

  private async preflightDynamicClientRegistration(authorizationUrl: URL): Promise<void> {
    if (this.clientRegistrationSource !== 'cached-dynamic' && this.clientRegistrationSource !== 'fresh-dynamic') {
      return
    }

    let response: Response
    try {
      response = await fetch(authorizationUrl.toString(), {
        redirect: 'manual',
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5_000),
      })
    } catch (error) {
      debugLog('Authorization preflight failed; continuing to browser authorization', error)
      return
    }

    if (response.status !== 400 && response.status !== 401) {
      return
    }

    let errorResponse: unknown
    try {
      errorResponse = await response.json()
    } catch (error) {
      debugLog('Authorization preflight returned invalid JSON; continuing to browser authorization', error)
      return
    }

    if (!isStaleClientRegistrationResponse(errorResponse)) {
      return
    }

    await this.invalidateCredentials('all')
    throw new StaleClientRegistrationError()
  }

  /**
   * Saves the PKCE code verifier
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    if (this.authorizationState === 'authorizing') {
      throw new OAuthAuthorizationPendingError()
    }

    if (this.authorizationState === 'verifying') {
      throw new OAuthTokenVerificationPendingError()
    }

    await this.prepareAuthorization()
    if (this.sharedAuthorization) {
      return
    }

    const transaction: AuthorizationTransaction = {
      version: 1,
      state: this._state,
      codeVerifier,
      createdAt: Date.now(),
    }

    debugLog('Saving state-bound PKCE authorization transaction')
    this.authorizationState = 'authorizing'
    this.callbackState = undefined
    try {
      await writeJsonFile(this.serverUrlHash, 'authorization.json', transaction)
    } catch (error) {
      this.resetAuthorizationState()
      throw error
    }
  }

  /**
   * Binds a browser callback to the verifier produced for that exact state.
   * A stale callback must never exchange a code with a newer verifier.
   */
  async acceptAuthorizationCallback(state: string): Promise<void> {
    const transaction = await this.readAuthorizationTransaction()
    if (!transaction || transaction.state !== state) {
      throw new OAuthCallbackStateError()
    }

    if (this.isTransactionExpired(transaction)) {
      await this.invalidateCredentials('verifier')
      throw new OAuthCallbackStateError()
    }

    this.callbackState = state
  }

  /**
   * Retires an authorization that cannot be completed, while preserving a
   * current transaction when an old browser callback arrives out of order.
   */
  async handleAuthorizationFailure(error: unknown): Promise<void> {
    if (error instanceof OAuthCallbackStateError || (error instanceof Error && error.name === 'OAuthCallbackStateError')) {
      return
    }

    if (this.sharedAuthorization) {
      this.resetAuthorizationState()
      return
    }

    await this.invalidateCredentials('tokens')
  }

  /** Runs one code exchange in a state-bound async context. */
  async runAuthorizationExchange<T>(state: string, exchange: () => Promise<T>): Promise<T> {
    return await this.authorizationExchangeState.run(state, exchange)
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    const transaction = await this.readAuthorizationTransaction()
    if (transaction) {
      if (this.callbackState !== transaction.state) {
        throw new OAuthCallbackStateError()
      }
      debugLog('Reading verifier for state-bound PKCE authorization transaction')
      return transaction.codeVerifier
    }

    debugLog('Reading legacy code verifier')
    const verifier = await readTextFile(this.serverUrlHash, 'code_verifier.txt', 'No code verifier saved for session')
    debugLog('Code verifier found:', !!verifier)
    return verifier
  }

  /**
   * Invalidates the specified credentials
   * @param scope The scope of credentials to invalidate
   */
  async invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier'): Promise<void> {
    debugLog(`Invalidating credentials: ${scope}`)

    switch (scope) {
      case 'all':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'client_info.json'),
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'authorization.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        this.resetAuthorizationState()
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'tokens.json'),
          deleteConfigFile(this.serverUrlHash, 'authorization.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this.resetAuthorizationState()
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await Promise.all([
          deleteConfigFile(this.serverUrlHash, 'authorization.json'),
          deleteConfigFile(this.serverUrlHash, 'code_verifier.txt'),
        ])
        this.resetAuthorizationState()
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }

  private async prepareAuthorization(): Promise<void> {
    if (this.authorizationPrepared) {
      return
    }

    try {
      const preparation = await this.options.prepareAuthorization?.()
      this.sharedAuthorization = preparation?.skipBrowserAuth === true
      this.authorizationPrepared = true
    } catch (error) {
      this.resetAuthorizationState()
      throw error
    }
  }

  private async readAuthorizationTransaction(): Promise<AuthorizationTransaction | undefined> {
    return await readJsonFile<AuthorizationTransaction>(this.serverUrlHash, 'authorization.json', AuthorizationTransactionSchema)
  }

  private isTransactionExpired(transaction: AuthorizationTransaction): boolean {
    const authTimeoutMs = this.options.authTimeoutMs ?? 30_000
    return transaction.createdAt + authTimeoutMs < Date.now()
  }

  private resetAuthorizationState(): void {
    this.authorizationState = 'ready'
    this.callbackState = undefined
    this.authorizationPrepared = false
    this.sharedAuthorization = false
    this._state = randomUUID()
  }
}
