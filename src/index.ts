export { NodeOAuthClientProvider } from './lib/node-oauth-client-provider'
export { createLazyAuthCoordinator, coordinateAuth, isLockValid, isPidRunning, waitForAuthentication } from './lib/coordination'
export type { AuthCoordinator } from './lib/coordination'
export {
  connectToRemoteServer,
  createMessageTransformer,
  debugLog,
  discoverOAuthServerInfo,
  findAvailablePort,
  getServerUrlHash,
  log,
  mcpProxy,
  REASON_AUTH_NEEDED,
  REASON_TRANSPORT_FALLBACK,
  setupOAuthCallbackServer,
  setupOAuthCallbackServerWithLongPoll,
  shouldIncludeTool,
} from './lib/utils'
export type { AuthInitializer, OAuthServerDiscoveryResult, TransportStrategy } from './lib/utils'
export type {
  OAuthCallbackServerOptions,
  OAuthProviderOptions,
  StaticOAuthClientInformationFull,
  StaticOAuthClientMetadata,
} from './lib/types'
