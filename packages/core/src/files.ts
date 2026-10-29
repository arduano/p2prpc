/** Portable file contracts and Blob/memory IO, independent of RPC and native IO. */
export { blobSource, memoryDestination } from './files/browser.js';
export type { MemoryFileDestination } from './files/browser.js';
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
  PeerFiles,
  PeerFileShareOptions,
  PeerSharePolicy,
  PreparedFileSource,
  SendFileOptions,
  SharedFileHandle,
  TransferProgress,
  TransferResult
} from './files/types.js';
