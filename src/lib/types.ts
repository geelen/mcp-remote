import { EventEmitter } from 'events'
import { OAuthClientInformationFull, OAuthClientMetadata } from '@modelcontextprotocol/sdk/shared/auth.js'

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
}

// optional tatic OAuth client information
export type StaticOAuthClientMetadata = OAuthClientMetadata | null | undefined
export type StaticOAuthClientInformationFull = OAuthClientInformationFull | null | undefined
