import type { SessionPrincipal } from '../security/types.js';

/** Identity fields used to bind a file capability without retaining claims or scopes. */
export type FilePrincipalIdentity = Pick<
  SessionPrincipal,
  'id' | 'subject' | 'issuer' | 'clientId' | 'tenantId'
>;

export interface FileManifest<TMetadata = unknown> {
  readonly transferId: string;
  readonly name: string;
  readonly size: number;
  readonly digest: string;
  readonly chunkSize: number;
  readonly chunkCount: number;
  readonly metadata?: TMetadata;
}

export interface FileSource<TMetadata = unknown> {
  readonly name: string;
  readonly size: number;
  readonly metadata?: TMetadata;
  /** Custom sources must settle promptly when signal aborts. */
  readChunk(index: number, chunkSize: number, signal?: AbortSignal): Promise<Uint8Array>;
}

export interface FileDestination<TMetadata = unknown> {
  /**
   * Custom destinations must cooperatively settle on abort. In particular,
   * finalize must check signal immediately before publishing durable output.
   */
  prepare(manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<ReadonlySet<number>>;
  writeChunk(manifest: FileManifest<TMetadata>, index: number, data: Uint8Array, signal?: AbortSignal): Promise<void>;
  /**
   * Verify the complete staged content against manifest.digest immediately
   * before atomically publishing it. Per-chunk transport checks are not a
   * substitute for this storage-side final verification.
   */
  finalize(manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<void>;
  abort(manifest: FileManifest<TMetadata>, options: { discard: boolean }, signal?: AbortSignal): Promise<void>;
}

export interface FileOffer<TMetadata = unknown> {
  readonly peerId: string;
  /** Trusted application principal from the mutually authenticated session. */
  readonly principal: SessionPrincipal;
  readonly sessionId: string;
  /** Aborts if the authenticated connection/session expires or the offer decision times out. */
  readonly signal: AbortSignal;
  readonly manifest: FileManifest<TMetadata>;
  accept(destination: FileDestination<TMetadata>): void;
  reject(reason?: string): void;
}

export type IncomingFileHandler<TMetadata = unknown> = (offer: FileOffer<TMetadata>) => Promise<void> | void;

export interface TransferProgress {
  readonly transferId: string;
  readonly direction: 'send' | 'receive';
  readonly transferredBytes: number;
  readonly totalBytes: number;
  readonly completedChunks: number;
  readonly totalChunks: number;
}

export interface TransferResult<TMetadata = unknown> {
  readonly manifest: FileManifest<TMetadata>;
  readonly resumed: boolean;
  readonly durationMs: number;
}

export interface SharedFileHandle {
  readonly token: string;
  readonly expiresAt?: number;
}

export interface PeerSharePolicy {
  /**
   * Expiry for starting or reconnecting an operation. An operation already
   * authorized may finish; call revoke() to abort it immediately.
   * Defaults to five minutes and may not exceed registry policy.
   */
  readonly expiresAt?: number;
  /** Optional exact binding to canonical authenticated principal identity tuples. */
  readonly allowedPrincipals?: readonly FilePrincipalIdentity[];
  /**
   * Optional additional binding to OAuth/OIDC subjects or service accounts.
   * @deprecated Subject values are issuer-scoped. Prefer allowedPrincipals.
   */
  readonly allowedSubjects?: readonly string[];
  /** Defaults to one distinct download operation. */
  readonly maxDownloads?: number;
}

export type SharePolicy = PeerSharePolicy & (
  | {
      /** One or more authenticated Iroh endpoint IDs allowed to redeem the capability. */
      readonly allowedPeerIds: readonly string[];
      readonly allowBearer?: never;
    }
  | {
      /** Explicitly create a bearer capability usable by any authenticated and authorized peer. */
      readonly allowBearer: true;
      readonly allowedPeerIds?: readonly string[];
    }
);

export interface SendFileOptions {
  readonly signal?: AbortSignal;
  readonly lanes?: number;
  readonly chunkSize?: number;
  readonly transferId?: string;
  readonly onProgress?: (progress: TransferProgress) => void;
}

export type DownloadFileOptions = SendFileOptions;
