import { EventEmitter } from 'events'
import { OAuthClientInformationFull, OAuthClientMetadata } from '@modelcontextprotocol/sdk/shared/auth.js'
import type { AuthorizationServerMetadata } from './authorization-server-metadata'
import type { ProtectedResourceMetadata } from './protected-resource-metadata'

/**
 * Raised when an OAuth flow is already awaiting a browser callback. Callers
 * should retry after the flow completes instead of initiating another flow.
 */
export class OAuthAuthorizationPendingError extends Error {
  constructor() {
    super('OAuth authorization is already pending; retry after it completes')
    this.name = 'OAuthAuthorizationPendingError'
  }
}

/**
 * Raised when a freshly exchanged token has not yet been accepted by the MCP
 * server. A second browser flow cannot make that token valid.
 */
export class OAuthTokenVerificationPendingError extends Error {
  constructor() {
    super('OAuth token is awaiting remote verification; retry the MCP request')
    this.name = 'OAuthTokenVerificationPendingError'
  }
}

/**
 * Options for creating an OAuth client provider
 */
export interface OAuthProviderOptions {
  /** Server URL to connect to */
  serverUrl: string
  /** Port for the OAuth callback server */
  callbackPort: number
  /** Desired hostname for the OAuth callback server */
  host: string
  /** Path for the OAuth callback endpoint */
  callbackPath?: string
  /** Directory to store OAuth credentials */
  configDir?: string
  /** Client name to use for OAuth registration */
  clientName?: string
  /** Client URI to use for OAuth registration */
  clientUri?: string
  /** Software ID to use for OAuth registration */
  softwareId?: string
  /** Software version to use for OAuth registration */
  softwareVersion?: string
  /** Static OAuth client metadata to override default OAuth client metadata */
  staticOAuthClientMetadata?: StaticOAuthClientMetadata
  /** Static OAuth client information to use instead of OAuth registration */
  staticOAuthClientInfo?: StaticOAuthClientInformationFull
  /** Resource parameter to send to the authorization server */
  authorizeResource?: string
  /** Pre-calculated server URL hash for cache isolation */
  serverUrlHash: string
  /** Authorization server metadata (optional, fetched if not provided) */
  authorizationServerMetadata?: AuthorizationServerMetadata
  /** Protected resource metadata (optional, discovered from 401 response) */
  protectedResourceMetadata?: ProtectedResourceMetadata
  /** Scope extracted from WWW-Authenticate header */
  wwwAuthenticateScope?: string
  /**
   * Prepares the local OAuth callback coordination before a browser is opened.
   * A secondary process can report that a primary process completed the flow,
   * in which case this provider must not start another browser authorization.
   */
  prepareAuthorization?: () => Promise<{ skipBrowserAuth: boolean }>
}

/**
 * OAuth callback server setup options
 */
export interface OAuthCallbackServerOptions {
  /** Port for the callback server */
  port: number
  /** Path for the callback endpoint */
  path: string
  /** Event emitter to signal when auth code is received */
  events: EventEmitter
  /** Timeout in milliseconds for waiting for the OAuth callback and long polls */
  authTimeoutMs?: number
}

// optional tatic OAuth client information
export type StaticOAuthClientMetadata = OAuthClientMetadata | null | undefined
export type StaticOAuthClientInformationFull = OAuthClientInformationFull | null | undefined
