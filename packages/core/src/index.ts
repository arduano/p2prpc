export { createP2PNode } from './node.js';
export type {
  ConnectOptions,
  P2PNode,
  P2PNodeLimits,
  P2PNodeOptions,
  P2PRequestContext,
  P2PRequestFiles,
  Peer,
  PeerContext,
  PeerDiagnostics,
  PeerFileShareOptions,
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
export type { FileTransferDiagnostics } from './files/manager.js';
export type { ShareRegistryDiagnostics } from './files/share.js';
export type { FileTransferLimits } from './files/validation.js';
export type {
  DownloadFileOptions,
  FileDestination,
  FileDestinationFinalizeContext,
  FileManifest,
  FileMetadataSchema,
  FileMetadataSchemaResult,
  FileOffer,
  FilePrincipalIdentity,
  FileSource,
  FileTransfer,
  IncomingFileDecision,
  IncomingFileHandler,
  PeerSharePolicy,
  PreparedFileSource,
  SendFileOptions,
  SharedFileHandle,
  TransferProgress,
  TransferResult
} from './files/types.js';

export { p2pRpcContext } from './rpc/link.js';
export type { P2PRpcOperationContext } from './rpc/link.js';
export type { RpcHeaderInput, RpcHeaders } from './rpc/headers.js';

export { createSharedSecretSecurity } from './security/shared-secret.js';
export type { SharedSecretSecurityOptions } from './security/shared-secret.js';
export { createOidcSessionSecurity, irohPeerIdJwkThumbprint } from './security/oidc.js';
export type {
  OidcAlgorithm,
  OidcClaimValue,
  OidcIssuerConfiguration,
  OidcSessionSecurityOptions,
  OidcStaticJwk,
  OidcStaticJwks,
  OidcVerificationKey,
  OidcVerifiedClaims
} from './security/oidc.js';
export type {
  AuthenticatedSession,
  AuthorizationAction,
  AuthorizationContext,
  AuthorizationResult,
  CredentialRequestContext,
  PeerBoundSessionSecurity,
  SessionAuthenticationContext,
  SessionCredentialContext,
  SessionPrincipal,
  SessionRole
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
