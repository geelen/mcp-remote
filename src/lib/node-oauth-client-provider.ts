import { z } from 'zod'
import { OAuthClientProvider, refreshAuthorization, selectResourceURL } from '@modelcontextprotocol/sdk/client/auth.js'
import {
  OAuthClientInformationFull,
  OAuthClientInformationFullSchema,
  OAuthTokens,
  OAuthTokensSchema,
} from '@modelcontextprotocol/sdk/shared/auth.js'
import { type OAuthProviderOptions, type StaticOAuthClientInformationFull, type StaticOAuthClientMetadata } from './types'
import { InvalidClientError, UnauthorizedClientError } from '@modelcontextprotocol/sdk/server/auth/errors.js'
import { readJsonFile, writeJsonFile, readTextFile, writeTextFile, deleteConfigFile, deleteStaleConfigFiles } from './mcp-auth-config'
import { openBrowser } from './open-browser'
import { log, debugLog, buildRedirectUrl, MCP_REMOTE_VERSION } from './utils'
import { sanitizeUrl } from 'strict-url-sanitise'
import { randomUUID } from 'node:crypto'
import { fetchAuthorizationServerMetadata, type AuthorizationServerMetadata } from './authorization-server-metadata'
import { getAuthorizationServerUrl, type ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * The OAuth token response only carries the relative `expires_in`, which is
 * useless once persisted to disk. We extend the SDK token schema with an
 * absolute `expires_at` timestamp so later reads can detect imminent expiry
 * and refresh proactively. The base schema uses `.strip()`, which would
 * otherwise drop `expires_at` on read, so we parse and serialize tokens with
 * this extended schema instead.
 */
export const OAuthTokensWithExpiresAtSchema = OAuthTokensSchema.extend({
  expires_at: z.coerce.number().optional(),
  /** The scope this client asked for when the token was obtained. See {@link scopeRequestChanged}. */
  requested_scope: z.string().optional(),
})
type OAuthTokensWithExpiresAt = z.infer<typeof OAuthTokensWithExpiresAtSchema>

/** The shape of the state we issue, and the only shape accepted into a config filename. */
const ISSUED_STATE = /^[A-Za-z0-9-]{1,64}$/

const CODE_VERIFIER_PREFIX = 'code_verifier_'

/**
 * How many access tokens may be issued inside {@link TOKEN_STORM_WINDOW_MS} before this client
 * stops going back for more.
 *
 * Set well above any legitimate cadence. A token lives minutes at least, and the handful of
 * refreshes a burst of concurrent requests can trigger is nowhere near this. Reaching it means
 * something is exchanging tokens in a loop rather than because one expired.
 */
const TOKEN_STORM_LIMIT = 20
const TOKEN_STORM_WINDOW_MS = 30_000

/** How long a flow may still be in progress, and its verifier still needed. */
const ABANDONED_FLOW_AGE_MS = 10 * 60 * 1000

type ClientRegistrationSource = 'cached-dynamic' | 'fresh-dynamic' | 'static' | undefined

function staleClientRegistrationError(value: unknown): InvalidClientError | UnauthorizedClientError | undefined {
  if (!value || typeof value !== 'object') {
    return undefined
  }

  const response = value as Record<string, unknown>
  const message =
    typeof response.error_description === 'string' ? response.error_description : 'Cached OAuth client registration is no longer valid'
  if (response.error === 'invalid_client') {
    return new InvalidClientError(message)
  }
  if (response.error === 'unauthorized_client') {
    return new UnauthorizedClientError(message)
  }
  return undefined
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
  private authorizeParams: Record<string, string>
  private skipResourceParameter: boolean
  /**
   * Overrides how the SDK picks the RFC 8707 `resource` indicator. Only defined when we have
   * an opinion; otherwise the SDK derives it from Protected Resource Metadata as usual.
   */
  validateResourceURL?: (defaultResource: URL, discoveredResource?: string) => Promise<URL | undefined>
  private _state: string
  private _clientInfo: OAuthClientInformationFull | undefined
  private clientRegistrationSource: ClientRegistrationSource
  private incomingState: string | undefined
  private authorizationServerMetadata: AuthorizationServerMetadata | undefined
  private protectedResourceMetadata: ProtectedResourceMetadata | undefined
  private wwwAuthenticateScope: string | undefined
  /** When tokens were last written, for spotting an exchange loop. See {@link TOKEN_STORM_LIMIT}. */
  private recentTokenWrites: number[] = []
  /** In-flight proactive refresh, so concurrent requests share one refresh_token use */
  private refreshInFlight: Promise<OAuthTokensWithExpiresAt | undefined> | null = null

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
    const trimmedAuthorizeResource = options.authorizeResource?.trim()
    this.authorizeResource = trimmedAuthorizeResource ? trimmedAuthorizeResource : undefined
    this.skipResourceParameter = options.skipResourceParameter ?? false
    this.authorizeParams = options.authorizeParams ?? {}
    this._state = randomUUID()
    this._clientInfo = undefined
    this.clientRegistrationSource = undefined
    this.authorizationServerMetadata = options.authorizationServerMetadata
    this.protectedResourceMetadata = options.protectedResourceMetadata
    this.wwwAuthenticateScope = options.wwwAuthenticateScope

    // The SDK feeds one `resource` value into the authorization, token and refresh requests
    // (selectResourceURL -> startAuthorization / fetchToken / refreshAuthorization). Deciding
    // it here keeps those three in agreement, which RFC 8707 §2.2 requires - previously the
    // authorize URL was rewritten after the fact, so it could disagree with the token request.
    if (this.skipResourceParameter) {
      this.validateResourceURL = async () => {
        debugLog('Resource parameter disabled; omitting it from authorization and token requests')
        return undefined
      }
    } else if (this.authorizeResource) {
      const resourceUrl = new URL(this.authorizeResource)
      this.validateResourceURL = async () => resourceUrl
    }
    // Otherwise left undefined so the SDK applies its default resource selection.
  }

  setCallbackPort(port: number): void {
    this.options.callbackPort = port
  }

  get redirectUrl(): string {
    return buildRedirectUrl(this.options.host, this.options.callbackPort, this.callbackPath)
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
      ...(effectiveScope ? { scope: effectiveScope } : {}),
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
    const resourceScopes = this.protectedResourceMetadata?.scopes_supported
    if (resourceScopes !== undefined) {
      if (resourceScopes.length === 0) {
        debugLog('Protected resource advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = resourceScopes.join(' ')
      debugLog('Using scopes from Protected Resource Metadata', {
        scopes_supported: resourceScopes,
        scope,
      })
      return scope
    }

    // Priority 4: Scope from client registration response
    if (this._clientInfo?.scope && this._clientInfo.scope.trim().length > 0) {
      debugLog('Using scope from client registration response', { scope: this._clientInfo.scope })
      return this._clientInfo.scope
    }

    // Priority 5: Use authorization server's supported scopes if advertised
    const authScopes = this.authorizationServerMetadata?.scopes_supported
    if (authScopes !== undefined) {
      if (authScopes.length === 0) {
        debugLog('Authorization server advertises no scopes (scopes_supported: []), omitting scope')
        return ''
      }
      const scope = authScopes.join(' ')
      debugLog('Using scopes from Authorization Server Metadata', {
        scopes_supported: authScopes,
        scope,
      })
      return scope
    }

    // Priority 6: Fallback to hardcoded default when metadata is unknown or omits scopes_supported
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

    const tokens = await readJsonFile<OAuthTokensWithExpiresAt>(this.serverUrlHash, 'tokens.json', OAuthTokensWithExpiresAtSchema)

    if (tokens && this.scopeRequestChanged(tokens)) {
      log('The scopes this client asks for have changed since it signed in; signing in again')
      debugLog('Discarding a token obtained for a different scope request', {
        obtainedFor: tokens.requested_scope,
        nowRequesting: this.getEffectiveScope(),
      })
      await this.invalidateCredentials('tokens')
      return undefined
    }

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

      // Use the persisted absolute expiry timestamp to detect imminent expiry,
      // refreshing ~60s early to avoid sending a token that is about to 401.
      const isExpired = tokens.expires_at ? Date.now() >= tokens.expires_at - 60_000 : false

      debugLog('Token result:', {
        found: true,
        hasAccessToken: !!tokens.access_token,
        hasRefreshToken: !!tokens.refresh_token,
        expiresIn: `${timeLeft} seconds`,
        expiresAt: tokens.expires_at ? new Date(tokens.expires_at).toISOString() : 'unknown',
        isExpired,
      })

      // Renew before the token is sent rather than after the server rejects it.
      // Waiting for a 401 assumes the server answers expiry with exactly 401 -
      // one that replies 400 or 403 instead never reaches the SDK's refresh path
      // and the connection just fails (see issue #273).
      if (isExpired && tokens.refresh_token) {
        const refreshed = await this.refreshTokens(tokens.refresh_token)
        if (refreshed) {
          return refreshed
        }
        // Refresh failed: hand back what we have and let the SDK's own 401
        // handling take it from here, exactly as it did before.
        log('Proactive token refresh failed, falling back to the stored token')
      }
    } else {
      debugLog('Token result: Not found')
    }

    return tokens
  }

  /**
   * Whether this run is asking for something different from what the stored token was obtained for.
   *
   * Compares request against request, deliberately, not against what the server granted. An
   * authorization server may grant *less* than it was asked for (RFC 6749 3.3), and treating that
   * as a reason to sign in again is a loop with nothing to break it: the next sign-in returns the
   * same narrower grant, which is rejected the same way. Comparing the two requests only fires
   * when the configuration actually changed - a scope added to `--static-oauth-client-metadata`,
   * say - and then only once, because the new token records the new request.
   *
   * A token stored before this was recorded has no request to compare, and is left alone.
   *
   * @param tokens The tokens read from disk
   * @returns True if a fresh authorization is needed to cover what is being asked for now
   */
  private scopeRequestChanged(tokens: OAuthTokensWithExpiresAt): boolean {
    if (tokens.requested_scope === undefined) return false
    return tokens.requested_scope !== this.getEffectiveScope()
  }

  /**
   * Exchanges a refresh token for a new access token, reusing the same authorization
   * server, client credentials and RFC 8707 resource indicator the SDK would have
   * picked, so the refresh request agrees with the authorization that produced it.
   *
   * Concurrent callers share one attempt: `tokens()` runs on every outgoing request,
   * and with refresh token rotation a second, parallel use of the same token can
   * invalidate the whole chain rather than merely wasting a round trip.
   *
   * @param refreshToken The refresh token to redeem
   * @returns The refreshed tokens, or undefined if the refresh could not be completed
   */
  private async refreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    if (!this.refreshInFlight) {
      this.refreshInFlight = this.doRefreshTokens(refreshToken).finally(() => {
        this.refreshInFlight = null
      })
    }
    return this.refreshInFlight
  }

  private async doRefreshTokens(refreshToken: string): Promise<OAuthTokensWithExpiresAt | undefined> {
    try {
      const clientInformation = await this.clientInformation()
      if (!clientInformation) {
        debugLog('No client information available, cannot refresh proactively')
        return undefined
      }

      const metadata = await this.getAuthorizationServerMetadata()
      const authorizationServerUrl =
        (this.protectedResourceMetadata ? getAuthorizationServerUrl(this.protectedResourceMetadata) : undefined) ??
        new URL('/', this.options.serverUrl).toString()
      const resource = await selectResourceURL(new URL(this.options.serverUrl), this, this.protectedResourceMetadata)

      debugLog('Refreshing access token before it expires', { authorizationServerUrl, resource: resource?.toString() })

      // The SDK types metadata as the full OIDC discovery document, while ours is
      // the RFC 8414 subset. Only these two fields reach the token request
      // (executeTokenRequest), so narrow to them rather than cast the whole object.
      const tokenRequestMetadata = metadata
        ? ({
            token_endpoint: metadata.token_endpoint,
            token_endpoint_auth_methods_supported: metadata.token_endpoint_auth_methods_supported,
          } as Parameters<typeof refreshAuthorization>[1]['metadata'])
        : undefined

      const refreshed = await refreshAuthorization(authorizationServerUrl, {
        metadata: tokenRequestMetadata,
        clientInformation,
        refreshToken,
        resource,
      })

      // Goes through saveTokens so the new expiry is persisted the same way
      await this.saveTokens(refreshed)
      log('Refreshed the access token before it expired')

      return OAuthTokensWithExpiresAtSchema.parse({
        ...refreshed,
        expires_at: refreshed.expires_in ? Date.now() + refreshed.expires_in * 1000 : undefined,
      })
    } catch (error) {
      debugLog('Proactive token refresh failed', error)
      return undefined
    }
  }

  /**
   * Saves OAuth tokens
   * @param tokens The tokens to save
   */
  /**
   * Stops this client taking part in a token exchange loop.
   *
   * An authorization server that keeps honouring a refresh token, for a resource server that keeps
   * rejecting the access tokens it returns, is a loop with nothing to end it: every rejection looks
   * to the SDK like a token worth refreshing. The SDK breaks that cycle for the request path, but
   * not for the standalone SSE stream, whose 401 handler re-enters authorization and reopens the
   * stream with no circuit breaker and no backoff - measured at several hundred exchanges a second,
   * indefinitely, which is what gets people rate-limited by their own identity provider.
   *
   * Every one of those exchanges ends here, so this is the one place the loop can be seen from and
   * the one place it can be stopped. Throwing fails the authorization that asked for the write,
   * which is what unwinds the stream's retry.
   *
   * The window is a sliding one, so a client that stops hammering is trusted again shortly after.
   */
  private inTokenStorm(): boolean {
    const now = Date.now()
    this.recentTokenWrites = this.recentTokenWrites.filter((at) => now - at < TOKEN_STORM_WINDOW_MS)
    return this.recentTokenWrites.length >= TOKEN_STORM_LIMIT
  }

  /** The error both halves of the brake raise, so the cause reads the same wherever it surfaces. */
  private tokenStormError(): Error {
    const seconds = TOKEN_STORM_WINDOW_MS / 1000
    log(
      `Stopping: ${TOKEN_STORM_LIMIT} access tokens were issued in the last ${seconds}s and the MCP server ` +
        `rejected them all. Asking for another would only repeat the exchange.`,
    )
    debugLog('Token exchange loop detected', { writes: this.recentTokenWrites.length, windowMs: TOKEN_STORM_WINDOW_MS })
    return new Error(
      `Stopped after ${TOKEN_STORM_LIMIT} token exchanges in ${seconds}s. The tokens being issued are not accepted ` +
        `by the MCP server - check that its audience and scopes match, or sign in again.`,
    )
  }

  private guardAgainstTokenStorm(): void {
    if (this.inTokenStorm()) throw this.tokenStormError()
    this.recentTokenWrites.push(Date.now())
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    this.guardAgainstTokenStorm()

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

    // Persist an absolute expiry timestamp alongside the token so that future
    // reads can detect imminent expiry and refresh proactively (the spec only
    // provides the relative `expires_in`, which is meaningless once stored).
    const tokensToSave: OAuthTokensWithExpiresAt = {
      ...tokens,
      expires_at: tokens.expires_in ? Date.now() + tokens.expires_in * 1000 : undefined,
      requested_scope: this.getEffectiveScope(),
    }

    await writeJsonFile(this.serverUrlHash, 'tokens.json', tokensToSave)

    // The flow is over, and its verifier is named after a state nothing will use again
    await deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState))
    await deleteStaleConfigFiles(this.serverUrlHash, CODE_VERIFIER_PREFIX, ABANDONED_FLOW_AGE_MS)
  }

  /**
   * Redirects the user to the authorization URL
   * @param authorizationUrl The URL to redirect to
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    // A refused refresh sends the SDK down the full authorization path, so without this the brake
    // would turn an exchange loop into a browser-tab loop - the same storm, more visible.
    if (this.inTokenStorm()) throw this.tokenStormError()

    // Optionally fetch metadata for debugging/informational purposes (non-blocking)
    this.getAuthorizationServerMetadata().catch(() => {
      // Ignore errors, metadata is optional
    })

    this.applyScope(authorizationUrl)
    this.applyAuthorizeParams(authorizationUrl)

    log(`\nPlease authorize this client by visiting:\n${authorizationUrl.toString()}\n`)

    debugLog('Redirecting to authorization URL', authorizationUrl.toString())

    await this.preflightCachedDynamicClientRegistration(authorizationUrl)

    if (await openBrowser(sanitizeUrl(authorizationUrl.toString()))) {
      log('Browser opened automatically.')
    } else {
      log('Could not open a browser automatically. Please copy and paste the URL above into your browser.')
    }
  }

  private async preflightCachedDynamicClientRegistration(authorizationUrl: URL): Promise<void> {
    if (this.clientRegistrationSource !== 'cached-dynamic') {
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

    const registrationError = staleClientRegistrationError(errorResponse)
    if (!registrationError) {
      return
    }

    throw registrationError
  }

  /**
   * Decides which scope the authorization request asks for.
   *
   * The SDK has already put one on the URL, picked - in its order - from a scope it parsed out of a
   * live `WWW-Authenticate` challenge, the protected resource's `scopes_supported`, or the `scope`
   * in our own client metadata. The last two originate here, and this client's priority order for
   * them is not the SDK's, so they are replaced with what `getEffectiveScope` decided.
   *
   * A challenge scope does not originate here, and replacing it defeated the one thing it is for: a
   * 403 `insufficient_scope` names the scopes the call actually needed, the SDK re-runs
   * authorization asking for them, and overwriting them here re-requested exactly the scope that
   * had just been refused - so it was refused again and the SDK gave up with "Server returned 403
   * after trying upscoping" (see https://github.com/geelen/mcp-remote/issues/134).
   *
   * A scope the user pinned with `--static-oauth-client-metadata` still wins over both. They set it
   * because the scopes the server advertises do not work for them, and a challenge is the server
   * advertising them again.
   *
   * @param authorizationUrl The authorization URL to set the scope on, modified in place
   */
  /**
   * Adds the caller's own parameters to the authorization URL.
   *
   * Applied after everything this client decides for itself, so an explicitly requested value wins
   * - the flag exists precisely for servers whose requirements this client does not model. The
   * parameters the flow derives per request are refused at parse time instead.
   *
   * @param authorizationUrl The authorization URL to add parameters to, modified in place
   */
  private applyAuthorizeParams(authorizationUrl: URL): void {
    for (const [key, value] of Object.entries(this.authorizeParams)) {
      authorizationUrl.searchParams.set(key, value)
    }

    if (Object.keys(this.authorizeParams).length > 0) {
      debugLog('Added extra parameters to authorization URL', { keys: Object.keys(this.authorizeParams) })
    }
  }

  private applyScope(authorizationUrl: URL): void {
    const effectiveScope = this.getEffectiveScope()
    const requestedScope = authorizationUrl.searchParams.get('scope')
    const pinnedByUser = !!this.staticOAuthClientMetadata?.scope?.trim()
    const couldBeOurs = [effectiveScope, this.protectedResourceMetadata?.scopes_supported?.join(' ')]

    if (!pinnedByUser && requestedScope && !couldBeOurs.includes(requestedScope)) {
      log(`Authorizing with the scope the server asked for: ${requestedScope}`)
      debugLog('Keeping a scope this client did not supply', { scope: requestedScope, effectiveScope })
      return
    }

    if (effectiveScope) {
      authorizationUrl.searchParams.set('scope', effectiveScope)
      debugLog('Added scope parameter to authorization URL', { scopes: effectiveScope })
    } else {
      debugLog('Omitting scope parameter from authorization URL (no effective scope)')
    }
  }

  /**
   * Saves the PKCE code verifier
   *
   * The filename is scoped to this flow's authorization state rather than to the process, so a
   * code can still be redeemed by an instance that took the callback port over from the one that
   * started the flow. See https://github.com/geelen/mcp-remote/issues/235.
   * @param codeVerifier The code verifier to save
   */
  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    debugLog('Saving code verifier')
    await writeTextFile(this.serverUrlHash, this.codeVerifierFile(this._state), codeVerifier)
  }

  /**
   * Records the state a code came back with, so the flow that produced it decides which verifier
   * redeems it
   * @param state The state from the callback
   */
  useAuthorizationState(state: string): void {
    if (!ISSUED_STATE.test(state)) {
      log('Ignoring an authorization state this client could not have issued')
      debugLog('Rejected authorization state', { state })
      return
    }
    this.incomingState = state
  }

  /** The flow this instance is redeeming for: another instance's when a code names it. */
  private get flowState(): string {
    return this.incomingState ?? this._state
  }

  private codeVerifierFile(state: string): string {
    return `${CODE_VERIFIER_PREFIX}${state}.txt`
  }

  /**
   * Gets the PKCE code verifier
   * @returns The code verifier
   */
  async codeVerifier(): Promise<string> {
    debugLog('Reading code verifier')
    const verifier = await readTextFile(this.serverUrlHash, this.codeVerifierFile(this.flowState), 'No code verifier saved for session')
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
          deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState)),
        ])
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        debugLog('All credentials invalidated')
        break

      case 'client':
        await deleteConfigFile(this.serverUrlHash, 'client_info.json')
        this._clientInfo = undefined
        this.clientRegistrationSource = undefined
        debugLog('Client information invalidated')
        break

      case 'tokens':
        await deleteConfigFile(this.serverUrlHash, 'tokens.json')
        debugLog('OAuth tokens invalidated')
        break

      case 'verifier':
        await deleteConfigFile(this.serverUrlHash, this.codeVerifierFile(this.flowState))
        debugLog('Code verifier invalidated')
        break

      default:
        throw new Error(`Unknown credential scope: ${scope}`)
    }
  }
}
