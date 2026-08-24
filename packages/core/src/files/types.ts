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
  /**
   * Advanced lifecycle used to retain validated resources through hashing and
   * transmission. The manager always calls close(), including on cancellation.
   */
  prepare?(signal?: AbortSignal): Promise<PreparedFileSource<TMetadata>>;
  /** Custom sources must settle promptly when signal aborts. */
  readChunk(index: number, chunkSize: number, signal?: AbortSignal): Promise<Uint8Array>;
}

export interface PreparedFileSource<TMetadata = unknown> {
  readonly name: string;
  readonly size: number;
  readonly metadata?: TMetadata;
  readChunk(index: number, chunkSize: number, signal?: AbortSignal): Promise<Uint8Array>;
  close(): Promise<void>;
}

/** Structural subset of Standard Schema v1 used for runtime file metadata validation. */
export interface FileMetadataSchema<TMetadata> {
  readonly '~standard': {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (
      value: unknown
    ) => FileMetadataSchemaResult<TMetadata> | Promise<FileMetadataSchemaResult<TMetadata>>;
  };
}

export type FileMetadataSchemaResult<TMetadata> =
  | { readonly value: TMetadata; readonly issues?: undefined }
  | { readonly issues: readonly unknown[]; readonly value?: undefined };

/**
 * Explicit irreversible-boundary signal for a destination commit.
 *
 * `markCommitted()` must be called exactly once, immediately after durable
 * output becomes externally visible and before any fallible post-commit
 * cleanup. The transfer manager uses that synchronous signal to ensure a
 * later cleanup failure can never cause rollback, a contradictory Reject, or
 * an unsafe automatic retry of an already-published file.
 */
export interface FileDestinationFinalizeContext {
  readonly signal?: AbortSignal;
  readonly markCommitted: () => void;
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
   * before atomically publishing it, then call `context.markCommitted()` at
   * the exact publication boundary. Per-chunk transport checks are not a
   * substitute for this storage-side final verification. Rejecting before
   * `markCommitted()` asserts that publication did not happen; rejecting
   * afterward reports only post-commit cleanup uncertainty.
   */
  finalize(manifest: FileManifest<TMetadata>, context: FileDestinationFinalizeContext): Promise<void>;
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
}

export type IncomingFileDecision<TMetadata = unknown> =
  | { readonly accept: FileDestination<TMetadata>; readonly reject?: never }
  | { readonly reject: true | string; readonly accept?: never };

export type IncomingFileHandler<TMetadata = unknown> = (
  offer: FileOffer<TMetadata>
) => Promise<IncomingFileDecision<TMetadata>> | IncomingFileDecision<TMetadata>;

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

export interface FileTransfer<TMetadata = unknown> {
  readonly manifest: FileManifest<TMetadata>;
  readonly result: Promise<TransferResult<TMetadata>>;
  cancel(reason?: unknown): void;
  /** Each iterator is an independent, bounded, conflated subscription. */
  progress(): AsyncIterable<TransferProgress>;
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
  /** Defaults to one distinct download operation. */
  readonly maxDownloads?: number;
}

/** Advanced registry policy; root peer APIs derive these bindings automatically. */
export interface PrincipalBoundSharePolicy extends PeerSharePolicy {
  readonly allowedPrincipals?: readonly (FilePrincipalIdentity | SessionPrincipal)[];
}

export type SharePolicy = PrincipalBoundSharePolicy & (
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

interface FileTransferOptions {
  readonly signal?: AbortSignal;
  readonly lanes?: number;
  readonly chunkSize?: number;
  readonly onProgress?: (progress: TransferProgress) => void;
}

export interface SendFileOptions extends FileTransferOptions {
  /** Stable push operation ID; reuse only to reconcile the exact same manifest. */
  readonly transferId?: string;
}

export interface DownloadFileOptions extends FileTransferOptions {
  /** Stable capability-redemption operation ID used across reconnect/retry. */
  readonly operationId?: string;
}
