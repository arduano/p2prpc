/** Browser-safe typed RPC and binary files through an authenticated Gateway. */
export { connectBridge } from './bridge/client.js';
export type { ConnectBridgeOptions, BrowserBridgePeer } from './bridge/client.js';
export type { BridgeContext, BridgePeerDiagnostics, BridgePeerLimits } from './bridge/contracts.js';
export { blobSource, memoryDestination } from './files/browser.js';
export type { MemoryFileDestination } from './files/browser.js';
export type {
  FileSource, FileDestination, FileManifest, FileMetadataSchema, FileOffer,
  FileTransfer, IncomingFileHandler, SharedFileHandle, TransferProgress,
  TransferResult, PeerFiles, PeerFileShareOptions
} from './files/types.js';
export { p2pRpcContext } from './rpc/portable-link.js';
export type { P2PRpcOperationContext } from './rpc/portable-link.js';
export type { RpcHeaderInput, RpcHeaders } from './rpc/portable-headers.js';
export { P2PError } from './errors.js';
export type { P2PErrorCode } from './errors.js';
export type {
  SessionPrincipal, AuthorizationContext, AuthorizationAction, AuthorizationResult
} from './security/types.js';
