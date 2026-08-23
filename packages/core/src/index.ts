export { createP2PNode, P2PNode, Peer } from './node.js';
export type {
  ConnectOptions,
  P2PNodeLimits,
  P2PNodeOptions,
  PeerContext,
  PeerDiagnostics,
  PeerFiles,
  PeerIdentity,
  PeerLocator,
  PrincipalMatcher,
  ProtocolIdentity,
  SecurityAuditEvent
} from './node.js';
export { P2PError, asP2PError } from './errors.js';
export type { P2PErrorCode } from './errors.js';
export { fileDestination, fileSource } from './files/fs.js';
export type { FileDestinationOptions } from './files/fs.js';
export { ShareRegistry } from './files/share.js';
export type { ShareRegistryOptions } from './files/share.js';
export type { FileTransferDiagnostics } from './files/manager.js';
export type { FileTransferLimits } from './files/validation.js';
export { Transfer } from './files/transfer.js';
export type {
  DownloadFileOptions,
  FileDestination,
  FileManifest,
  FileOffer,
  FilePrincipalIdentity,
  FileSource,
  IncomingFileHandler,
  PeerSharePolicy,
  SendFileOptions,
  SharePolicy,
  SharedFileHandle,
  TransferProgress,
  TransferResult
} from './files/types.js';
export { irohLink, p2pRpcContext } from './rpc/link.js';
export type { IrohLinkOptions, P2PRpcOperationContext } from './rpc/link.js';
export { normalizeRpcHeaders } from './rpc/headers.js';
export type { RpcHeaderInput, RpcHeaderLimits, RpcHeaders } from './rpc/headers.js';
export { createSharedSecretSecurity, dangerouslyAllowInsecureSessions } from './security/shared-secret.js';
export type { SharedSecretSecurityOptions } from './security/shared-secret.js';
export { createOidcSessionSecurity } from './security/oidc.js';
export type { OidcIssuerConfiguration, OidcSessionSecurityOptions } from './security/oidc.js';
export type {
  AuthenticatedSession,
  AuthorizationAction,
  AuthorizationContext,
  AuthorizationResult,
  CredentialRequestContext,
  SessionAuthenticationContext,
  SessionCredential,
  SessionPrincipal,
  SessionSecurity
} from './security/types.js';
export type {
  IrohDiscoveryConfiguration,
  IrohEndpointOptions,
  IrohRelayConfiguration
} from './transport/iroh.js';
export type {
  ConnectionPath,
  ConnectionStats,
  EndpointDiagnostics,
  EndpointDiscoveryEvent,
  EndpointDiscoveryOptions,
  StreamLifecycleStats
} from './transport/types.js';
