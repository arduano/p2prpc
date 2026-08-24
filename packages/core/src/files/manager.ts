import { createHash, randomBytes, type Hash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { P2PError, asP2PError } from '../errors.js';
import {
  DEFAULT_FRAME_LIMITS,
  PROTOCOL_VERSION,
  StreamKind,
  TransferFrameKind,
  readFrame,
  writeFrame,
  writeStreamKind,
  type Frame,
  type FrameLimits
} from '../protocol.js';
import type { QuicBiStream, QuicConnection, QuicRecvStream, QuicSendStream } from '../transport/types.js';
import type { SessionPrincipal } from '../security/types.js';
import { sanitizeBoundedDisplayText } from '../text.js';
import { chunkDigest, createManifest } from './fs.js';
import { capabilityId, type ShareRegistry, type ShareReservation } from './share.js';
import { Transfer } from './transfer.js';
import type {
  DownloadFileOptions,
  FileDestination,
  FileDestinationFinalizeContext,
  FileManifest,
  FileMetadataSchema,
  FileOffer,
  FileSource,
  IncomingFileHandler,
  PreparedFileSource,
  SendFileOptions,
  TransferProgress,
  TransferResult
} from './types.js';
import {
  assertOnlyKeys,
  expectedChunkSize,
  isRecord,
  manifestWireValue,
  resolveFileTransferLimits,
  validateChunkSize,
  validateDigest,
  validateManifest,
  validateTransferId,
  type FileTransferLimits
} from './validation.js';

interface IncomingSession<TMetadata> {
  readonly manifest: FileManifest<TMetadata>;
  readonly destination: FileDestination<TMetadata>;
  readonly missing: ChunkBitmap;
  readonly inFlight: Set<number>;
  readonly claimedLanes: Set<number>;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly allowedLanes: number;
  readonly totalMissing: number;
  readonly resumed: boolean;
  readonly transfer: Transfer<TMetadata> | undefined;
  readonly context: FileTransferConnectionContext;
  readonly connectionAttempt: FileConnectionAttempt;
  readonly controller: AbortController;
  readonly signal: AbortSignal;
  readonly receivers: Set<QuicRecvStream>;
  readonly done: Promise<void>;
  announcedChunks: number;
  transferredBytes: number;
  /** Refresh the session-level no-progress deadline. */
  touch(): void;
  /** Stop only the idle watchdog after the irreversible commit boundary. */
  stopIdle(): void;
  /** Register a lane handler so destination teardown cannot race its callbacks. */
  beginLane(): () => void;
  /** Resolves only after every registered lane handler has settled. */
  lanesDrained(): Promise<void>;
  resolve(): void;
  reject(error: unknown): void;
  dispose(): void;
}

interface TransferAccept {
  readonly transferId: string;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly missingRanges: Array<readonly [start: number, endExclusive: number]>;
  readonly missingCount: number;
  readonly lanes: number;
}

interface TransferPull {
  readonly token: string;
  readonly requestId: string;
  readonly options?: { readonly chunkSize?: number; readonly lanes?: number };
}

interface LaneHeader {
  readonly transferId: string;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly laneId: number;
  readonly count: number;
}

interface ChunkHeader {
  readonly index: number;
  readonly size: number;
  readonly digest: string;
}

interface CompletionFrame {
  readonly transferId: string;
  readonly attemptId: string;
}

interface CompletionAcknowledgement extends CompletionFrame {
  /** Fresh receiver challenge proving that the sender observed this acknowledgement. */
  readonly receiptToken: string;
}

interface OperationRecord {
  readonly principalBinding: string;
  readonly fingerprint: string;
  state: 'active' | 'committed';
  expiresAt: number;
}

interface ReplayTombstone {
  readonly principalBinding: string;
  readonly fingerprint: string;
  readonly state: 'acknowledged' | 'rejected';
  readonly expiresAt: number;
}

interface OperationAdmission {
  readonly record: OperationRecord | ReplayTombstone;
  readonly fresh: boolean;
}

interface ReceiverOperationScope {
  readonly operations: Map<string, OperationRecord>;
  readonly replayTombstones: Map<string, ReplayTombstone>;
}

interface ReceiverPrincipalUsage {
  hard: number;
  tombstones: number;
}

interface TombstoneLocation {
  readonly peerId: string;
  readonly key: string;
  readonly scope: ReceiverOperationScope;
  readonly record: ReplayTombstone;
}

interface ReceiverExpiry {
  readonly peerId: string;
  readonly key: string;
  readonly expiresAt: number;
  readonly record: OperationRecord | ReplayTombstone;
}

interface ReceiverOperationLedgerDiagnostics {
  readonly activeOperations: number;
  readonly ambiguousOperations: number;
  readonly replayTombstones: number;
  readonly operationRecords: number;
}

export interface ReceiverOperationLedgerOptions {
  /** Maximum active or acknowledgement-ambiguous operations per peer. */
  readonly maxOperationRecords: number;
  /** Maximum evictable acknowledged/rejected tombstones per peer. */
  readonly maxReplayTombstones: number;
  /** Maximum active/ambiguous operations across the node. */
  readonly maxGlobalOperationRecords?: number;
  /** Maximum replay tombstones across the node. */
  readonly maxGlobalReplayTombstones?: number;
  /** Maximum active/ambiguous operations for one canonical principal. */
  readonly maxPrincipalOperationRecords?: number;
  /** Maximum replay tombstones for one canonical principal. */
  readonly maxPrincipalReplayTombstones?: number;
  readonly operationRecordTtlMs: number;
}

/**
 * Node-lifetime receiver commit/replay state.
 *
 * The exact key is peer endpoint + canonical principal + transfer ID. Active
 * and committed records are never capacity-evicted; only terminal tombstones
 * may be displaced. This object contains no connection/session resources, so
 * replacement TransferManagers can safely share it.
 */
export class ReceiverOperationLedger {
  readonly maxOperationRecords: number;
  readonly maxReplayTombstones: number;
  readonly operationRecordTtlMs: number;
  readonly maxGlobalOperationRecords: number;
  readonly maxGlobalReplayTombstones: number;
  readonly maxPrincipalOperationRecords: number;
  readonly maxPrincipalReplayTombstones: number;
  private readonly scopes = new Map<string, ReceiverOperationScope>();
  private readonly principalUsage = new Map<string, ReceiverPrincipalUsage>();
  private readonly globalTombstoneOrder = new Map<ReplayTombstone, TombstoneLocation>();
  private readonly principalTombstoneOrder = new Map<string, Map<ReplayTombstone, TombstoneLocation>>();
  private totalOperationRecords = 0;
  private totalReplayTombstones = 0;
  /** Indexed min-heap of expiring entries. Active operations never enter it. */
  private readonly expiryHeap: ReceiverExpiry[] = [];
  private expiryIndexes = new WeakMap<OperationRecord | ReplayTombstone, number>();
  private closed = false;

  constructor(options: ReceiverOperationLedgerOptions) {
    this.maxOperationRecords = options.maxOperationRecords;
    this.maxReplayTombstones = options.maxReplayTombstones;
    this.operationRecordTtlMs = options.operationRecordTtlMs;
    this.maxGlobalOperationRecords = options.maxGlobalOperationRecords ?? this.maxOperationRecords;
    this.maxGlobalReplayTombstones = options.maxGlobalReplayTombstones ?? this.maxReplayTombstones;
    this.maxPrincipalOperationRecords = options.maxPrincipalOperationRecords ?? this.maxOperationRecords;
    this.maxPrincipalReplayTombstones = options.maxPrincipalReplayTombstones ?? this.maxReplayTombstones;
    if (
      !Number.isSafeInteger(this.maxOperationRecords) ||
      this.maxOperationRecords < 1 ||
      this.maxOperationRecords > 100_000
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file operation-record limit');
    }
    if (
      !Number.isSafeInteger(this.maxReplayTombstones) ||
      this.maxReplayTombstones < 1 ||
      this.maxReplayTombstones > 100_000
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file replay-tombstone limit');
    }
    for (const [value, label] of [
      [this.maxGlobalOperationRecords, 'global file operation-record limit'],
      [this.maxGlobalReplayTombstones, 'global file replay-tombstone limit'],
      [this.maxPrincipalOperationRecords, 'principal file operation-record limit'],
      [this.maxPrincipalReplayTombstones, 'principal file replay-tombstone limit']
    ] as const) {
      if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
        throw new P2PError('RESOURCE_LIMIT', `Invalid ${label}`);
      }
    }
    if (
      this.maxOperationRecords > this.maxPrincipalOperationRecords ||
      this.maxPrincipalOperationRecords > this.maxGlobalOperationRecords
    ) {
      throw new P2PError(
        'RESOURCE_LIMIT',
        'File operation-record limits must be ordered per-peer <= per-principal <= global'
      );
    }
    if (
      this.maxReplayTombstones > this.maxPrincipalReplayTombstones ||
      this.maxPrincipalReplayTombstones > this.maxGlobalReplayTombstones
    ) {
      throw new P2PError(
        'RESOURCE_LIMIT',
        'File replay-tombstone limits must be ordered per-peer <= per-principal <= global'
      );
    }
    if (
      !Number.isSafeInteger(this.operationRecordTtlMs) ||
      this.operationRecordTtlMs < 1_000 ||
      this.operationRecordTtlMs > 24 * 60 * 60_000
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file operation-record lifetime');
    }
  }

  diagnostics(peerId: string): ReceiverOperationLedgerDiagnostics {
    this.pruneExpired();
    const scope = this.scopes.get(peerId);
    let activeOperations = 0;
    let ambiguousOperations = 0;
    for (const record of scope?.operations.values() ?? []) {
      if (record.state === 'active') activeOperations += 1;
      else ambiguousOperations += 1;
    }
    return {
      activeOperations,
      ambiguousOperations,
      replayTombstones: scope?.replayTombstones.size ?? 0,
      operationRecords: scope?.operations.size ?? 0
    };
  }

  admit<TMetadata>(
    peerId: string,
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal
  ): OperationAdmission {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Receiver operation ledger is closed');
    this.pruneExpired();
    const existingScope = this.scopes.get(peerId);
    const key = receiverOperationKey(principal, manifest.transferId);
    const record = existingScope?.operations.get(key) ?? existingScope?.replayTombstones.get(key);
    const fingerprint = manifestFingerprint(manifest);
    const binding = receiverPrincipalBinding(principal);
    if (record && (record.principalBinding !== binding || record.fingerprint !== fingerprint)) {
      throw new P2PError('INTEGRITY_FAILED', 'Transfer ID was reused for a different authenticated operation');
    }
    if (record) return { record, fresh: false };
    if ((existingScope?.operations.size ?? 0) >= this.maxOperationRecords) {
      throw new P2PError('RESOURCE_LIMIT', 'File operation reconciliation registry is full');
    }
    const existingUsage = this.principalUsage.get(binding);
    if (
      this.totalOperationRecords >= this.maxGlobalOperationRecords ||
      (existingUsage?.hard ?? 0) >= this.maxPrincipalOperationRecords
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'File operation reconciliation registry is full');
    }
    const usage = existingUsage ?? this.usage(binding);
    const admitted: OperationRecord = {
      principalBinding: binding,
      fingerprint,
      state: 'active',
      expiresAt: Number.MAX_SAFE_INTEGER
    };
    const scope = existingScope ?? this.scope(peerId);
    scope.operations.set(key, admitted);
    this.totalOperationRecords += 1;
    usage.hard += 1;
    this.touch(peerId, scope);
    return { record: admitted, fresh: true };
  }

  finishFailed<TMetadata>(
    peerId: string,
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord,
    cause: unknown
  ): void {
    const scope = this.existingScope(peerId);
    const key = receiverOperationKey(principal, manifest.transferId);
    const code = asP2PError(cause).code;
    if (['DISCONNECTED', 'TIMEOUT', 'CANCELLED', 'RESOURCE_LIMIT', 'UNAUTHORIZED', 'NOT_FOUND'].includes(code)) {
      if (scope?.operations.get(key) === operation && operation.state === 'active') {
        this.deleteOperation(scope, key, operation);
        this.removeEmptyScope(peerId, scope);
      }
      return;
    }
    this.reject(peerId, manifest, principal, operation);
  }

  prepareCommit<TMetadata>(
    peerId: string,
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): () => void {
    const scope = this.requiredScope(peerId);
    const key = receiverOperationKey(principal, manifest.transferId);
    this.assertHandle(manifest, principal, operation);
    if (scope.operations.get(key) !== operation || operation.state !== 'active') {
      throw new P2PError('INTERNAL', 'File operation changed before durable commit');
    }
    return () => {
      operation.state = 'committed';
      operation.expiresAt = Date.now() + this.operationRecordTtlMs;
      this.enqueueExpiry(peerId, key, operation);
      this.touch(peerId, scope);
    };
  }

  acknowledge<TMetadata>(
    peerId: string,
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): void {
    const scope = this.requiredScope(peerId);
    const key = receiverOperationKey(principal, manifest.transferId);
    this.assertHandle(manifest, principal, operation);
    const current = scope.operations.get(key);
    if (current !== operation) {
      const tombstone = scope.replayTombstones.get(key);
      if (
        tombstone?.state === 'acknowledged' &&
        tombstone.principalBinding === operation.principalBinding &&
        tombstone.fingerprint === operation.fingerprint
      ) return;
      throw new P2PError('INTERNAL', 'File operation changed before acknowledgement receipt');
    }
    if (operation.state !== 'committed') {
      throw new P2PError('INTERNAL', 'Uncommitted file operation was receipted');
    }
    this.deleteOperation(scope, key, operation);
    this.installReplayTombstone(peerId, scope, key, operation, 'acknowledged');
  }

  reject<TMetadata>(
    peerId: string,
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): void {
    const scope = this.existingScope(peerId);
    if (!scope) return;
    const key = receiverOperationKey(principal, manifest.transferId);
    this.assertHandle(manifest, principal, operation);
    if (scope.operations.get(key) !== operation) return;
    this.deleteOperation(scope, key, operation);
    this.installReplayTombstone(peerId, scope, key, operation, 'rejected');
  }

  private scope(peerId: string): ReceiverOperationScope {
    const current = this.scopes.get(peerId);
    if (current) return current;
    const created: ReceiverOperationScope = {
      operations: new Map(),
      replayTombstones: new Map()
    };
    this.scopes.set(peerId, created);
    return created;
  }

  private existingScope(peerId: string): ReceiverOperationScope | undefined {
    this.pruneExpired();
    return this.scopes.get(peerId);
  }

  private requiredScope(peerId: string): ReceiverOperationScope {
    const scope = this.existingScope(peerId);
    if (!scope) throw new P2PError('INTERNAL', 'Receiver operation scope is no longer owned');
    return scope;
  }

  private installReplayTombstone(
    peerId: string,
    scope: ReceiverOperationScope,
    key: string,
    operation: OperationRecord,
    state: ReplayTombstone['state']
  ): void {
    const binding = operation.principalBinding;
    const existing = scope.replayTombstones.get(key);
    if (existing) this.deleteTombstone(scope, key, existing);
    if (scope.replayTombstones.size >= this.maxReplayTombstones) {
      const oldest = scope.replayTombstones.keys().next().value as string | undefined;
      if (oldest !== undefined) {
        const tombstone = scope.replayTombstones.get(oldest);
        if (tombstone) this.deleteTombstone(scope, oldest, tombstone);
      }
    }
    this.evictTombstonesForCapacity(binding);
    const currentScope = this.scopes.get(peerId);
    if (currentScope === undefined) this.scopes.set(peerId, scope);
    else if (currentScope !== scope) {
      throw new P2PError('INTERNAL', 'Receiver operation scope ownership changed');
    }
    const usage = this.usage(binding);
    const tombstone: ReplayTombstone = {
      principalBinding: operation.principalBinding,
      fingerprint: operation.fingerprint,
      state,
      expiresAt: Date.now() + this.operationRecordTtlMs
    };
    scope.replayTombstones.set(key, tombstone);
    const location = { peerId, key, scope, record: tombstone };
    this.globalTombstoneOrder.set(tombstone, location);
    let principalOrder = this.principalTombstoneOrder.get(binding);
    if (!principalOrder) {
      principalOrder = new Map();
      this.principalTombstoneOrder.set(binding, principalOrder);
    }
    principalOrder.set(tombstone, location);
    this.totalReplayTombstones += 1;
    usage.tombstones += 1;
    this.enqueueExpiry(peerId, key, tombstone);
    this.touch(peerId, scope);
  }

  private assertHandle<TMetadata>(
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): void {
    if (
      operation.principalBinding !== receiverPrincipalBinding(principal) ||
      operation.fingerprint !== manifestFingerprint(manifest)
    ) {
      throw new P2PError('INTEGRITY_FAILED', 'File operation handle does not match its authenticated manifest');
    }
  }

  private pruneExpired(): void {
    const now = Date.now();
    while (this.expiryHeap.length > 0) {
      const expiry = this.expiryHeap[0]!;
      if (expiry.expiresAt > now) break;
      this.removeExpiry(expiry.record);
      const scope = this.scopes.get(expiry.peerId);
      if (!scope) continue;
      if (scope.operations.get(expiry.key) === expiry.record && expiry.record.state === 'committed') {
        this.deleteOperation(scope, expiry.key, expiry.record);
      } else if (scope.replayTombstones.get(expiry.key) === expiry.record) {
        this.deleteTombstone(scope, expiry.key, expiry.record);
      }
      this.removeEmptyScope(expiry.peerId, scope);
    }
  }

  private enqueueExpiry(
    peerId: string,
    key: string,
    record: OperationRecord | ReplayTombstone
  ): void {
    this.removeExpiry(record);
    const entry = { peerId, key, expiresAt: record.expiresAt, record };
    this.expiryHeap.push(entry);
    let index = this.expiryHeap.length - 1;
    this.expiryIndexes.set(record, index);
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (this.expiryHeap[parent]!.expiresAt <= entry.expiresAt) break;
      this.swapExpiry(index, parent);
      index = parent;
    }
  }

  private removeExpiry(record: OperationRecord | ReplayTombstone): void {
    const index = this.expiryIndexes.get(record);
    if (index === undefined) return;
    this.expiryIndexes.delete(record);
    const last = this.expiryHeap.pop()!;
    if (index >= this.expiryHeap.length) return;
    this.expiryHeap[index] = last;
    this.expiryIndexes.set(last.record, index);
    const parent = index === 0 ? -1 : Math.floor((index - 1) / 2);
    if (parent >= 0 && this.expiryHeap[parent]!.expiresAt > last.expiresAt) {
      let current = index;
      while (current > 0) {
        const nextParent = Math.floor((current - 1) / 2);
        if (this.expiryHeap[nextParent]!.expiresAt <= this.expiryHeap[current]!.expiresAt) break;
        this.swapExpiry(current, nextParent);
        current = nextParent;
      }
      return;
    }
    let current = index;
    while (true) {
      const left = current * 2 + 1;
      const right = left + 1;
      let smallest = current;
      if (left < this.expiryHeap.length && this.expiryHeap[left]!.expiresAt < this.expiryHeap[smallest]!.expiresAt) {
        smallest = left;
      }
      if (right < this.expiryHeap.length && this.expiryHeap[right]!.expiresAt < this.expiryHeap[smallest]!.expiresAt) {
        smallest = right;
      }
      if (smallest === current) return;
      this.swapExpiry(current, smallest);
      current = smallest;
    }
  }

  private swapExpiry(left: number, right: number): void {
    const leftEntry = this.expiryHeap[left]!;
    const rightEntry = this.expiryHeap[right]!;
    this.expiryHeap[left] = rightEntry;
    this.expiryHeap[right] = leftEntry;
    this.expiryIndexes.set(leftEntry.record, right);
    this.expiryIndexes.set(rightEntry.record, left);
  }

  private usage(binding: string): ReceiverPrincipalUsage {
    let usage = this.principalUsage.get(binding);
    if (!usage) {
      usage = { hard: 0, tombstones: 0 };
      this.principalUsage.set(binding, usage);
    }
    return usage;
  }

  private deleteOperation(scope: ReceiverOperationScope, key: string, record: OperationRecord): void {
    if (scope.operations.get(key) !== record) return;
    scope.operations.delete(key);
    this.removeExpiry(record);
    this.totalOperationRecords -= 1;
    const usage = this.usage(record.principalBinding);
    usage.hard -= 1;
    this.removeEmptyUsage(record.principalBinding, usage);
  }

  private deleteTombstone(scope: ReceiverOperationScope, key: string, record: ReplayTombstone): void {
    if (scope.replayTombstones.get(key) !== record) return;
    scope.replayTombstones.delete(key);
    this.removeExpiry(record);
    this.globalTombstoneOrder.delete(record);
    const principalOrder = this.principalTombstoneOrder.get(record.principalBinding);
    principalOrder?.delete(record);
    if (principalOrder?.size === 0) this.principalTombstoneOrder.delete(record.principalBinding);
    this.totalReplayTombstones -= 1;
    const usage = this.usage(record.principalBinding);
    usage.tombstones -= 1;
    this.removeEmptyUsage(record.principalBinding, usage);
  }

  private removeEmptyUsage(binding: string, usage: ReceiverPrincipalUsage): void {
    if (usage.hard === 0 && usage.tombstones === 0) this.principalUsage.delete(binding);
  }

  private evictTombstonesForCapacity(binding: string): void {
    while (this.usage(binding).tombstones >= this.maxPrincipalReplayTombstones) {
      const oldest = this.principalTombstoneOrder.get(binding)?.values().next().value as
        | TombstoneLocation
        | undefined;
      if (!oldest) break;
      this.deleteTombstone(oldest.scope, oldest.key, oldest.record);
      this.removeEmptyScope(oldest.peerId, oldest.scope);
    }
    while (this.totalReplayTombstones >= this.maxGlobalReplayTombstones) {
      const oldest = this.globalTombstoneOrder.values().next().value as TombstoneLocation | undefined;
      if (!oldest) break;
      this.deleteTombstone(oldest.scope, oldest.key, oldest.record);
      this.removeEmptyScope(oldest.peerId, oldest.scope);
    }
  }

  private touch(peerId: string, scope: ReceiverOperationScope): void {
    if (this.scopes.get(peerId) !== scope) {
      throw new P2PError('INTERNAL', 'Receiver operation scope ownership changed');
    }
    this.scopes.delete(peerId);
    this.scopes.set(peerId, scope);
  }

  private removeEmptyScope(peerId: string, scope: ReceiverOperationScope): void {
    if (scope.operations.size === 0 && scope.replayTombstones.size === 0 && this.scopes.get(peerId) === scope) {
      this.scopes.delete(peerId);
    }
  }

  /** Reject new operations while allowing already-owned transitions to settle. */
  close(): void {
    this.closed = true;
  }

  /** Release retained replay state after all node-owned operations have settled. */
  clear(): void {
    this.closed = true;
    this.scopes.clear();
    this.principalUsage.clear();
    this.globalTombstoneOrder.clear();
    this.principalTombstoneOrder.clear();
    this.expiryHeap.length = 0;
    this.expiryIndexes = new WeakMap();
    this.totalOperationRecords = 0;
    this.totalReplayTombstones = 0;
  }
}

/** Maximum transient transport read/write segment outside the owned chunk buffer. */
export const FILE_DATA_SEGMENT_BYTES = 64 * 1024;

export interface TransferManagerOptions<TMetadata = unknown> {
  readonly peerId: string;
  readonly connection: () => Promise<FileTransferConnectionContext>;
  readonly incoming?: IncomingFileHandler<TMetadata>;
  readonly shares: ShareRegistry<TMetadata>;
  /** Required to accept or send defined file metadata. */
  readonly metadataSchema?: FileMetadataSchema<TMetadata>;
  /** Required application authorization after strict parsing and before any file or capability access. */
  readonly authorize: (
    action: FileTransferAuthorization<TMetadata>,
    security: FileTransferSecurityContext,
    signal: AbortSignal
  ) => Promise<void> | void;
  /**
   * Central direction-separated admission. P2PNode supplies its global,
   * peer, and principal scheduler; standalone managers use local limits.
   */
  readonly acquireTransfer?: (
    direction: FileTransferDirection,
    signal: AbortSignal
  ) => Promise<() => void>;
  readonly limits?: Partial<FileTransferLimits>;
  readonly frameLimits?: FrameLimits;
  readonly idleTimeoutMs?: number;
  /** Bounded receiver-side idempotency window. Defaults to 1,024 operations per peer. */
  readonly maxOperationRecords?: number;
  /** Recent acknowledged/rejected replay tombstones. Defaults to 1,024 per peer. */
  readonly maxReplayTombstones?: number;
  /** Duration of receiver-side commit/rejection reconciliation. Defaults to 15 minutes. */
  readonly operationRecordTtlMs?: number;
  /** Node-lifetime receiver replay ledger shared by replacement peer runtimes. */
  readonly receiverOperations?: ReceiverOperationLedger;
  readonly onProgress?: (progress: TransferProgress) => void;
}

export type FileTransferDirection = 'outbound' | 'inbound';

export type FileTransferAuthorization<TMetadata = unknown> =
  | { readonly kind: 'file.push'; readonly manifest: FileManifest<TMetadata> }
  | { readonly kind: 'file.pull'; readonly capabilityId: string };

export interface FileTransferSecurityContext {
  readonly principal: SessionPrincipal;
  readonly sessionId: string;
}

/** Exact authenticated physical connection on which file streams are valid. */
export interface FileTransferConnectionContext {
  readonly connection: QuicConnection;
  readonly security: FileTransferSecurityContext;
  /** Aborts on connection close/replacement, session expiry, or node shutdown. */
  readonly signal: AbortSignal;
  /** Node-owned fail-closed hook; standalone managers may rely on close(). */
  readonly quarantine?: (reason: string) => void;
}

/**
 * Registers native work which must remain covered by the caller's stream
 * admission lease after a file-control handler has returned.
 */
type FileWorkTracker = (work: Promise<unknown>) => void;

type SenderRole = 'push' | 'capability-pull';

type AttemptOutcome<T> =
  | { readonly kind: 'success'; readonly value: T }
  | { readonly kind: 'retryable-transport-loss'; readonly error: P2PError }
  | { readonly kind: 'terminal-failure'; readonly error: P2PError };

type ControlOutcome = AttemptOutcome<void>;

export interface FileTransferDiagnostics {
  readonly activeTransfers: number;
  readonly queuedTransfers: number;
  readonly activeOutboundTransfers: number;
  readonly activeInboundTransfers: number;
  readonly queuedOutboundTransfers: number;
  readonly queuedInboundTransfers: number;
  readonly incomingSessions: number;
  readonly reservedSessions: number;
  readonly activeLanes: number;
  /** Active receiver operations which have not reached durable commit. */
  readonly activeOperations: number;
  /** Durable commits whose acknowledgement has not yet been receipted. */
  readonly ambiguousOperations: number;
  /** Bounded, evictable recent-operation replay tombstones. */
  readonly replayTombstones: number;
  readonly operationRecords: number;
  readonly maxOperationRecords: number;
  readonly maxReplayTombstones: number;
}

export class TransferManager<TMetadata = unknown> {
  private readonly sessions = new Map<string, IncomingSession<TMetadata>>();
  private readonly reservedSessionIds = new Set<string>();
  private readonly lifetimeController = new AbortController();
  private readonly limits: FileTransferLimits;
  private readonly idleTimeoutMs: number;
  private readonly maxOperationRecords: number;
  private readonly maxReplayTombstones: number;
  private readonly operationRecordTtlMs: number;
  private readonly receiverOperations: ReceiverOperationLedger;
  private readonly activeTransfers: Record<FileTransferDirection, number> = { outbound: 0, inbound: 0 };
  private readonly queuedTransfers: Record<FileTransferDirection, number> = { outbound: 0, inbound: 0 };
  private readonly localTransferSlots: Record<FileTransferDirection, {
    active: number;
    readonly waiters: Array<() => void>;
  }> = {
    outbound: { active: 0, waiters: [] },
    inbound: { active: 0, waiters: [] }
  };

  constructor(private readonly options: TransferManagerOptions<TMetadata>) {
    this.limits = resolveFileTransferLimits(options.limits);
    this.idleTimeoutMs = options.idleTimeoutMs ?? 30_000;
    this.maxOperationRecords = options.maxOperationRecords ?? 1_024;
    this.maxReplayTombstones = options.maxReplayTombstones ?? 1_024;
    this.operationRecordTtlMs = options.operationRecordTtlMs ?? 15 * 60_000;
    if (!Number.isSafeInteger(this.idleTimeoutMs) || this.idleTimeoutMs < 1_000 || this.idleTimeoutMs > 10 * 60_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file stream idle timeout');
    }
    if (options.metadataSchema !== undefined && !isFileMetadataSchema(options.metadataSchema)) {
      throw new P2PError('INVALID_FRAME', 'File metadata schema must implement Standard Schema v1');
    }
    if (!Number.isSafeInteger(this.maxOperationRecords) || this.maxOperationRecords < 1 || this.maxOperationRecords > 100_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file operation-record limit');
    }
    if (!Number.isSafeInteger(this.maxReplayTombstones) || this.maxReplayTombstones < 1 || this.maxReplayTombstones > 100_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file replay-tombstone limit');
    }
    if (
      !Number.isSafeInteger(this.operationRecordTtlMs) ||
      this.operationRecordTtlMs < 1_000 ||
      this.operationRecordTtlMs > 24 * 60 * 60_000
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file operation-record lifetime');
    }
    this.receiverOperations = options.receiverOperations ?? new ReceiverOperationLedger({
      maxOperationRecords: this.maxOperationRecords,
      maxReplayTombstones: this.maxReplayTombstones,
      operationRecordTtlMs: this.operationRecordTtlMs
    });
    if (
      this.receiverOperations.maxOperationRecords !== this.maxOperationRecords ||
      this.receiverOperations.maxReplayTombstones !== this.maxReplayTombstones ||
      this.receiverOperations.operationRecordTtlMs !== this.operationRecordTtlMs
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Receiver operation ledger limits do not match the file manager');
    }
  }

  diagnostics(): FileTransferDiagnostics {
    let activeLanes = 0;
    for (const session of this.sessions.values()) activeLanes += session.receivers.size;
    const activeOutboundTransfers = this.activeTransfers.outbound;
    const activeInboundTransfers = this.activeTransfers.inbound;
    const queuedOutboundTransfers = this.queuedTransfers.outbound;
    const queuedInboundTransfers = this.queuedTransfers.inbound;
    const operationDiagnostics = this.receiverOperations.diagnostics(this.options.peerId);
    return Object.freeze({
      activeTransfers: activeOutboundTransfers + activeInboundTransfers,
      queuedTransfers: queuedOutboundTransfers + queuedInboundTransfers,
      activeOutboundTransfers,
      activeInboundTransfers,
      queuedOutboundTransfers,
      queuedInboundTransfers,
      incomingSessions: this.sessions.size,
      reservedSessions: this.reservedSessionIds.size,
      activeLanes,
      activeOperations: operationDiagnostics.activeOperations,
      ambiguousOperations: operationDiagnostics.ambiguousOperations,
      replayTombstones: operationDiagnostics.replayTombstones,
      operationRecords: operationDiagnostics.operationRecords,
      maxOperationRecords: this.maxOperationRecords,
      maxReplayTombstones: this.maxReplayTombstones
    });
  }

  /** Permanently abort active, queued, and retrying work for this peer runtime. */
  close(reason: unknown = new P2PError('DISCONNECTED', 'Peer file manager closed')): void {
    if (!this.lifetimeController.signal.aborted) this.lifetimeController.abort(reason);
  }

  async sendFile(source: FileSource<TMetadata>, options: SendFileOptions = {}): Promise<Transfer<TMetadata>> {
    const linked = combinedController([
      this.lifetimeController.signal,
      ...(options.signal ? [options.signal] : [])
    ]);
    const controller = linked.controller;
    let release: (() => void) | undefined;
    let prepared: PreparedFileSource<TMetadata> | undefined;
    let chunkSize: number;
    let manifest: FileManifest<TMetadata>;
    try {
      throwIfCancelled(controller.signal);
      release = await this.acquireTransferSlot('outbound', controller.signal);
      chunkSize = validateChunkSize(options.chunkSize ?? this.limits.chunkSize, this.limits.maxChunkSize);
      prepared = await this.localOperation(
        (operationSignal) => prepareFileSource(source, operationSignal),
        controller.signal,
        'File source preparation timed out'
      );
      const manifestSource = prepared.metadata === undefined
        ? prepared
        : sourceWithMetadata(prepared, await this.validateMetadataValue(prepared.metadata, controller.signal));
      manifest = await createManifest(manifestSource, {
        chunkSize,
        ...(options.transferId ? { transferId: options.transferId } : {}),
        limits: this.limits,
        signal: controller.signal,
        readTimeoutMs: this.idleTimeoutMs
      });
    } catch (cause) {
      try {
        if (prepared) await closePreparedFileSource(prepared);
      } catch (cleanupCause) {
        throw preparedSourceCleanupFailed(cause, cleanupCause);
      } finally {
        release?.();
        linked.dispose();
      }
      throw cause;
    }
    const transferRef: { current?: Transfer<TMetadata> } = {};
    const transfer = new Transfer(manifest, controller, async () => {
      // Transfer starts its executor in the constructor. Yield once so the
      // circular progress reference is assigned before the first attempt can
      // emit an event.
      await Promise.resolve();
      try {
        return await settlePreparedFileSource(
          prepared!,
          () => this.retryFiles(
            controller.signal,
            (attempt) => this.sendAttempt(prepared!, manifest, options, transferRef.current, attempt)
          )
        );
      } finally {
        release!();
        linked.dispose();
      }
    });
    transferRef.current = transfer;
    if (options.onProgress) transfer.onProgress(options.onProgress);
    return transfer;
  }

  async download(
    token: string,
    destination: FileDestination<TMetadata>,
    options: DownloadFileOptions = {}
  ): Promise<Transfer<TMetadata>> {
    const linked = combinedController([
      this.lifetimeController.signal,
      ...(options.signal ? [options.signal] : [])
    ]);
    const controller = linked.controller;
    let release: (() => void) | undefined;
    const requestId = options.operationId ?? randomTransferId();
    let initial: {
      stream: QuicBiStream;
      manifest: FileManifest<TMetadata>;
      context: FileTransferConnectionContext;
    };
    try {
      throwIfCancelled(controller.signal);
      release = await this.acquireTransferSlot('outbound', controller.signal);
      initial = await this.retryFiles(
        controller.signal,
        (attempt) => this.openPull(token, requestId, options, attempt)
      );
    } catch (cause) {
      release?.();
      linked.dispose();
      throw cause;
    }
    const manifest = initial.manifest;
    let first: QuicBiStream | undefined = initial.stream;
    let firstContext: FileTransferConnectionContext | undefined = initial.context;
    const transferRef: { current?: Transfer<TMetadata> } = {};
    const transfer = new Transfer(manifest, controller, async () => {
      // See sendFile(): receiveAttempt must capture the Transfer itself, not
      // the still-empty constructor-time reference.
      await Promise.resolve();
      try {
        return await this.retryFiles(controller.signal, async (attempt) => {
          const openedOutcome = first
            ? successOutcome({ stream: first, manifest, context: firstContext! })
            : await this.openPull(token, requestId, options, attempt);
          first = undefined;
          firstContext = undefined;
          if (openedOutcome.kind !== 'success') return openedOutcome;
          const opened = openedOutcome.value;
          attempt.bindConnectionSignal(opened.context.signal);
          try {
            assertSameManifest(manifest, opened.manifest);
          } catch (cause) {
            const drained = await this.abortBiStream(opened.stream, opened.context.connection);
            return terminalOutcome(drained ? cause : cleanupFailed(cause));
          }
          return this.receiveAttempt(
            opened.stream,
            manifest,
            destination,
            transferRef.current,
            opened.context,
            attempt
          );
        });
      } finally {
        release!();
        linked.dispose();
      }
    });
    transferRef.current = transfer;
    if (options.onProgress) transfer.onProgress(options.onProgress);
    return transfer;
  }

  async handleControl(
    stream: QuicBiStream,
    context: FileTransferConnectionContext,
    trackWork: FileWorkTracker = ignoreFileWork
  ): Promise<void> {
    const attempt = new FileConnectionAttempt(this.lifetimeController.signal);
    attempt.bindConnectionSignal(context.signal);
    let release: (() => void) | undefined;
    let sharedPull: SharedPullAttempt<TMetadata> | undefined;
    let outcome: ControlOutcome = successOutcome(undefined);
    try {
      release = await this.acquireTransferSlot('inbound', attempt.controller.signal);
      await this.networkOperation(
        () => stream.send.setPriority(50),
        attempt.controller.signal,
        'File control priority timed out',
        attempt
      );
      const first = await this.readControlFrame(stream.recv, attempt.controller.signal, attempt);
      if (first.kind === TransferFrameKind.Offer) {
        const manifest = await this.validateManifestMetadata(
          validateManifest<TMetadata>(first.value, this.limits),
          attempt.controller.signal
        );
        await this.localOperation(
          (signal) => Promise.resolve(this.options.authorize(
            { kind: 'file.push', manifest },
            context.security,
            signal
          )),
          attempt.controller.signal,
          'File authorization timed out'
        );
        const admission = this.operationRecord(manifest, context.security.principal);
        if (!admission.fresh && admission.record.state === 'committed') {
          await this.reconcileCommittedPush(
            stream,
            manifest,
            admission.record,
            context,
            attempt.controller.signal,
            trackWork
          );
        } else {
          if (!admission.fresh && admission.record.state === 'active') {
            throw new P2PError('REJECTED', 'This file operation is already active');
          }
          if (!admission.fresh) {
            throw new P2PError('REJECTED', 'This file operation was already terminal');
          }
          const operation = admission.record as OperationRecord;
          try {
            const destination = await this.offerDestination(manifest, context.security, attempt.controller.signal);
            const received = await this.receiveAttempt(
              stream,
              manifest,
              destination,
              undefined,
              context,
              attempt,
              operation,
              trackWork
            );
            if (received.kind !== 'success') {
              this.finishFailedOperation(manifest, context.security.principal, operation, received.error);
              outcome = received;
            }
          } catch (cause) {
            this.finishFailedOperation(manifest, context.security.principal, operation, cause);
            throw cause;
          }
        }
      } else if (first.kind === TransferFrameKind.Pull) {
        const pull = validatePull(first.value, this.limits);
        await this.localOperation(
          (signal) => Promise.resolve(this.options.authorize(
            { kind: 'file.pull', capabilityId: capabilityId(pull.token) },
            context.security,
            signal
          )),
          attempt.controller.signal,
          'File authorization timed out'
        );
        const chunkSize = validateChunkSize(
          pull.options?.chunkSize ?? this.limits.chunkSize,
          this.limits.maxChunkSize
        );
        const lanes = validateLaneCount(pull.options?.lanes ?? this.limits.lanes, this.limits);
        const reservation = this.options.shares.reserve(pull.token, {
          peerId: this.options.peerId,
          principalId: context.security.principal.id,
          subject: context.security.principal.subject,
          ...(context.security.principal.issuer !== undefined
            ? { issuer: context.security.principal.issuer }
            : {}),
          ...(context.security.principal.clientId !== undefined
            ? { clientId: context.security.principal.clientId }
            : {}),
          ...(context.security.principal.tenantId !== undefined
            ? { tenantId: context.security.principal.tenantId }
            : {}),
          fingerprint: `v${PROTOCOL_VERSION}:${chunkSize}:${lanes}`,
          operationId: pull.requestId
        });
        sharedPull = new SharedPullAttempt(reservation, attempt.controller.signal);
        const reservationSignal = sharedPull.signal;
        const preparedReservationSource = await this.localOperation(
          (operationSignal) => prepareFileSource(reservation.source, operationSignal),
          reservationSignal,
          'File source preparation timed out'
        );
        sharedPull.adoptPrepared(preparedReservationSource);
        const reservationSource = preparedReservationSource.metadata === undefined
          ? preparedReservationSource
          : sourceWithMetadata(
            preparedReservationSource,
            await this.validateMetadataValue(preparedReservationSource.metadata, reservationSignal)
          );
        const manifest = await createManifest(reservationSource, {
          chunkSize,
          transferId: pull.requestId,
          limits: this.limits,
          signal: reservationSignal,
          readTimeoutMs: this.idleTimeoutMs
        });
        await this.writeControlFrame(
          stream.send,
          TransferFrameKind.Offer,
          manifestWireValue(manifest),
          reservationSignal,
          attempt
        );
        const sent = await this.senderFlow(
          stream,
          reservationSource,
          manifest,
          lanes,
          undefined,
          context,
          attempt,
          reservationSignal,
          'capability-pull',
          trackWork
        );
        if (sent.kind !== 'success') outcome = sent;
      } else {
        throw new P2PError('INVALID_FRAME', 'Unexpected transfer control frame');
      }
    } catch (cause) {
      outcome = await this.settleControlFailure(stream, context.connection, cause, attempt);
    }
    try {
      const failure = sharedPull
        ? await sharedPull.settle(outcome)
        : outcome.kind === 'success'
          ? undefined
          : outcome.error;
      if (failure !== undefined) throw failure;
    } finally {
      release?.();
      sharedPull?.dispose();
      attempt.dispose();
    }
  }

  private async settleControlFailure(
    stream: QuicBiStream,
    connection: QuicConnection,
    cause: unknown,
    attempt: FileConnectionAttempt
  ): Promise<ControlOutcome> {
    try {
      const error = asP2PError(cause);
      if (attempt.isTransportLoss(cause)) {
        const drained = await this.abortBiStream(stream, connection);
        return drained
          ? { kind: 'retryable-transport-loss', error }
          : { kind: 'terminal-failure', error: cleanupFailed(error) };
      }
      const drained = await this.rejectControlStream(stream, error, connection);
      return {
        kind: 'terminal-failure',
        error: drained ? error : cleanupFailed(error)
      };
    } catch (settlementCause) {
      return {
        kind: 'terminal-failure',
        error: new P2PError('INTERNAL', 'File control failure settlement failed', {
          cause: { operation: cause, settlement: settlementCause }
        })
      };
    }
  }

  async handleData(recv: QuicRecvStream, context: FileTransferConnectionContext): Promise<void> {
    let session: IncomingSession<TMetadata> | undefined;
    let claimed = false;
    let releaseLane: (() => void) | undefined;
    try {
      const first = await this.readControlFrame(recv, context.signal);
      if (first.kind !== TransferFrameKind.Accept) throw new P2PError('INVALID_FRAME', 'Missing lane header');
      const header = validateLaneHeader(first.value, this.limits);
      const candidate = this.sessions.get(header.transferId);
      if (
        !candidate ||
        candidate.context !== context ||
        candidate.attemptId !== header.attemptId ||
        candidate.laneToken !== header.laneToken
      ) {
        throw new P2PError('NOT_FOUND', 'Transfer lane is stale or inactive');
      }
      if (header.laneId >= candidate.allowedLanes || candidate.claimedLanes.has(header.laneId)) {
        throw new P2PError('INVALID_FRAME', 'Transfer lane is duplicate or outside the negotiated range');
      }
      if (candidate.announcedChunks + header.count > candidate.totalMissing) {
        throw new P2PError('RESOURCE_LIMIT', 'Transfer lanes announced too many chunks');
      }
      throwIfCancelled(candidate.signal);
      candidate.claimedLanes.add(header.laneId);
      candidate.announcedChunks += header.count;
      candidate.receivers.add(recv);
      releaseLane = candidate.beginLane();
      session = candidate;
      claimed = true;
      session.touch();

      for (let position = 0; position < header.count; position += 1) {
        const frame = await this.readControlFrame(recv, session.signal, session.connectionAttempt);
        session.touch();
        if (frame.kind !== TransferFrameKind.ChunkHeader) throw new P2PError('INVALID_FRAME', 'Missing chunk header');
        const chunk = validateChunkHeader(frame.value, session.manifest);
        if (!session.missing.has(chunk.index) || session.inFlight.has(chunk.index)) {
          throw new P2PError('INVALID_FRAME', `Unexpected or duplicate chunk ${chunk.index}`);
        }
        session.inFlight.add(chunk.index);
        try {
          const data = await this.readChunkBody(
            recv,
            chunk.size,
            session.signal,
            session.connectionAttempt,
            session.touch
          );
          session.touch();
          if (chunkDigest(data) !== chunk.digest) throw new P2PError('INTEGRITY_FAILED', `Chunk ${chunk.index} failed verification`);
          await this.localOperation(
            (operationSignal) => session!.destination.writeChunk(
              session!.manifest,
              chunk.index,
              data,
              operationSignal
            ),
            session.signal,
            'File destination write timed out'
          );
          session.touch();
          session.missing.delete(chunk.index);
        } finally {
          session.inFlight.delete(chunk.index);
        }
        session.transferredBytes += chunk.size;
        this.emitProgress(session.manifest, {
          completedChunks: session.manifest.chunkCount - session.missing.size,
          transferredBytes: session.transferredBytes
        }, 'receive', session.transfer);
      }
      await this.expectRecvEnd(recv, session.signal, session.connectionAttempt);
      session.touch();
    } catch (cause) {
      const error = asP2PError(cause);
      if (claimed && session) {
        // This handler owns cleanup for its receive half. Remove it before
        // aborting the attempt so the control-flow cleanup cannot stop the
        // same lane concurrently.
        session.receivers.delete(recv);
        session.reject(error);
      }
      const drained = await this.abortRecvStream(recv, context.connection);
      if (!drained) throw cleanupFailed(error);
      throw error;
    } finally {
      session?.receivers.delete(recv);
      releaseLane?.();
    }
  }

  private async sendAttempt(
    source: FileSource<TMetadata>,
    manifest: FileManifest<TMetadata>,
    options: SendFileOptions,
    transfer: Transfer<TMetadata> | undefined,
    attempt: FileConnectionAttempt
  ): Promise<AttemptOutcome<TransferResult<TMetadata>>> {
    let context: FileTransferConnectionContext | undefined;
    let stream: QuicBiStream | undefined;
    try {
      context = await this.getConnection(attempt);
      const opened = await this.openBiStream(context.connection, attempt.controller.signal, attempt);
      stream = opened;
      await this.networkOperation(
        () => opened.send.setPriority(50),
        attempt.controller.signal,
        'File control priority timed out',
        attempt
      );
      await this.writeKind(opened.send, StreamKind.TransferControl, attempt.controller.signal, attempt);
      await this.writeControlFrame(
        opened.send,
        TransferFrameKind.Offer,
        manifestWireValue(manifest),
        attempt.controller.signal,
        attempt
      );
      return await this.senderFlow(
        opened,
        source,
        manifest,
        options.lanes,
        transfer,
        context,
        attempt,
        attempt.controller.signal,
        'push'
      );
    } catch (cause) {
      if (!stream || !context) return attemptOutcome(attempt, cause, true);
      const drained = await this.abortBiStream(stream, context.connection);
      return attemptOutcome(attempt, drained ? cause : cleanupFailed(cause), drained);
    }
  }

  private async senderFlow(
    stream: QuicBiStream,
    source: FileSource<TMetadata>,
    manifest: FileManifest<TMetadata>,
    requestedLanes: number | undefined,
    transfer: Transfer<TMetadata> | undefined,
    context: FileTransferConnectionContext,
    connectionAttempt: FileConnectionAttempt,
    signal: AbortSignal,
    role: SenderRole,
    trackWork: FileWorkTracker = ignoreFileWork
  ): Promise<AttemptOutcome<TransferResult<TMetadata>>> {
    const startedAt = Date.now();
    const attempt = childController(signal);
    const activeSends = new Set<QuicSendStream>();
    const laneTasks: Array<Promise<void>> = [];
    let remoteCommitPossible = false;
    try {
      const response = await this.readControlFrame(
        stream.recv,
        attempt.controller.signal,
        connectionAttempt
      );
      if (response.kind === TransferFrameKind.Reject) throw remoteRejection(response.value);
      if (response.kind !== TransferFrameKind.Accept) throw new P2PError('INVALID_FRAME', 'Transfer was not accepted');
      const accept = validateAccept(response.value, manifest, this.limits);
      const missing = validateMissingRanges(accept.missingRanges, manifest.chunkCount, accept.missingCount);
      const preferredLanes = requestedLanes === undefined
        ? accept.lanes
        : Math.min(validateLaneCount(requestedLanes, this.limits), accept.lanes);
      const lanes = clampLanes(preferredLanes, this.limits.maxLanes, Math.max(1, missing.count));
      let sentChunks = manifest.chunkCount - missing.count;
      let sentBytes = manifest.size - missing.byteLength(manifest);
      if (sentChunks > 0) {
        this.emitProgress(manifest, {
          completedChunks: sentChunks,
          transferredBytes: sentBytes
        }, 'send', transfer);
      }
      // The receiver may reject an accepted transfer later (for example, a
      // destination write can fail). Listen while lanes are active so its
      // explicit terminal frame wins over secondary STOP_SENDING write errors.
      // A transfer may legitimately run much longer than one idle interval.
      // Keep the control read cancellable, but start an idle deadline only if
      // a failed lane makes us wait for the receiver's terminal decision.
      const terminalOutcome = this.readControlFrameUntilCancelled(
        stream.recv,
        attempt.controller.signal,
        connectionAttempt
      ).then(
        (frame) => ({ kind: 'frame' as const, frame }),
        (error: unknown) => ({ kind: 'error' as const, error })
      );

      for (let laneId = 0; laneId < lanes; laneId += 1) {
        const laneStart = Math.floor(missing.count * laneId / lanes);
        const laneEnd = Math.floor(missing.count * (laneId + 1) / lanes);
        const laneCount = laneEnd - laneStart;
        if (laneCount === 0) continue;
        laneTasks.push((async () => {
          const send = await this.openUniStream(
            context.connection,
            attempt.controller.signal,
            connectionAttempt
          );
          activeSends.add(send);
          let finished = false;
          let laneFailure: unknown;
          try {
            await this.networkOperation(
              () => send.setPriority(-10),
              attempt.controller.signal,
              'File lane priority timed out',
              connectionAttempt
            );
            await this.writeKind(
              send,
              StreamKind.TransferData,
              attempt.controller.signal,
              connectionAttempt
            );
            await this.writeControlFrame(send, TransferFrameKind.Accept, {
              transferId: manifest.transferId,
              attemptId: accept.attemptId,
              laneToken: accept.laneToken,
              laneId,
              count: laneCount
            } satisfies LaneHeader, attempt.controller.signal, connectionAttempt);
            for (const index of missing.slice(laneStart, laneCount)) {
              const data = await this.localOperation(
                (operationSignal) => source.readChunk(index, manifest.chunkSize, operationSignal),
                attempt.controller.signal,
                'File source read timed out'
              );
              const expected = expectedChunkSize(manifest, index);
              if (data.byteLength !== expected) {
                throw new P2PError('INTEGRITY_FAILED', `Source returned an invalid chunk ${index}`);
              }
              await this.writeControlFrame(send, TransferFrameKind.ChunkHeader, {
                index,
                size: expected,
                digest: chunkDigest(data)
              } satisfies ChunkHeader, attempt.controller.signal, connectionAttempt);
              await this.writeChunkBody(
                send,
                data,
                attempt.controller.signal,
                connectionAttempt
              );
              sentChunks += 1;
              sentBytes += expected;
              this.emitProgress(manifest, {
                completedChunks: sentChunks,
                transferredBytes: sentBytes
              }, 'send', transfer);
            }
            await this.finishSendStream(send, attempt.controller.signal, connectionAttempt);
            finished = true;
          } catch (cause) {
            laneFailure = cause;
          } finally {
            try {
              // Every lane owns terminal cleanup for the stream it opened.
              // This closes the race where the outer abort path snapshots the
              // set just before a concurrently opening lane registers itself.
              if (!finished && !await this.abortSendStream(send, context.connection)) {
                laneFailure = cleanupFailed(laneFailure);
              }
            } finally {
              activeSends.delete(send);
            }
          }
          if (laneFailure !== undefined) throw laneFailure;
        })());
      }
      const lanesOutcome = Promise.all(laneTasks).then(
        () => ({ kind: 'lanes' as const }),
        (error: unknown) => ({ kind: 'lane-error' as const, error })
      );
      const firstFinished = await Promise.race([lanesOutcome, terminalOutcome]);
      if (firstFinished.kind === 'frame') {
        if (firstFinished.frame.kind === TransferFrameKind.Reject) {
          throw remoteRejection(firstFinished.frame.value);
        }
        throw new P2PError('INVALID_FRAME', 'Receiver completed before all file lanes settled');
      }
      if (firstFinished.kind === 'error') throw firstFinished.error;
      if (firstFinished.kind === 'lane-error') {
        // The receiver writes and finishes Reject before stopping its lane
        // readers, but QUIC streams are independently scheduled. Apply the
        // configured idle deadline now and wait for the authoritative control
        // outcome instead of guessing after a shorter grace period and
        // accidentally retrying side-effecting destination work.
        const peerTerminal = await withDeadline(
          terminalOutcome,
          this.idleTimeoutMs,
          'Peer transfer terminal frame timed out'
        ).catch(() => undefined);
        if (peerTerminal?.kind === 'frame' && peerTerminal.frame.kind === TransferFrameKind.Reject) {
          throw remoteRejection(peerTerminal.frame.value);
        }
        if (peerTerminal?.kind === 'frame') {
          throw new P2PError('INVALID_FRAME', 'Receiver completed after a failed file lane');
        }
        throw firstFinished.error;
      }

      const completion: CompletionFrame = { transferId: manifest.transferId, attemptId: accept.attemptId };
      // From the first byte of this terminal request onward, the receiver may
      // durably publish before a disconnect becomes observable locally.
      remoteCommitPossible = true;
      await this.writeControlFrame(
        stream.send,
        TransferFrameKind.Complete,
        completion,
        attempt.controller.signal,
        connectionAttempt
      );
      const terminal = await withDeadline(
        terminalOutcome,
        this.idleTimeoutMs,
        'Peer transfer acknowledgement timed out'
      );
      if (terminal.kind === 'error') throw terminal.error;
      const complete = terminal.frame;
      if (complete.kind === TransferFrameKind.Reject) {
        throw remoteRejection(complete.value);
      }
      if (complete.kind !== TransferFrameKind.Complete) {
        throw new P2PError('INTEGRITY_FAILED', 'Receiver did not verify this transfer attempt');
      }
      const acknowledgement = validateCompletionAcknowledgement(complete.value, completion);
      await this.finishAcknowledgedSender(
        stream,
        acknowledgement,
        context,
        attempt.controller.signal,
        trackWork
      );
      return successOutcome({
        manifest,
        resumed: missing.count < manifest.chunkCount,
        durationMs: Date.now() - startedAt
      });
    } catch (cause) {
      const terminalError = asP2PError(cause);
      const failure = remoteCommitPossible && role === 'push' && terminalError.code !== 'REJECTED'
        ? new P2PError(
          'OUTCOME_UNKNOWN',
          'The receiver may have committed the file, but its acknowledgement was not received',
          { cause }
        )
        : cause;
      attempt.controller.abort(failure);
      const [lanesSettled, sendsDrained, controlDrained] = await Promise.all([
        this.settleTasks(laneTasks, context.connection),
        this.abortSendStreams(activeSends, context.connection),
        this.abortBiStream(stream, context.connection)
      ]);
      const drained = lanesSettled && sendsDrained && controlDrained;
      return attemptOutcome(
        connectionAttempt,
        drained ? failure : cleanupFailed(failure),
        drained
      );
    } finally {
      attempt.dispose();
    }
  }

  private async receiveAttempt(
    stream: QuicBiStream,
    manifest: FileManifest<TMetadata>,
    destination: FileDestination<TMetadata>,
    transfer: Transfer<TMetadata> | undefined,
    context: FileTransferConnectionContext,
    attempt: FileConnectionAttempt,
    pushOperation?: OperationRecord,
    trackWork: FileWorkTracker = ignoreFileWork
  ): Promise<AttemptOutcome<TransferResult<TMetadata>>> {
    const startedAt = Date.now();
    let ownsReservation = false;
    let destinationPrepared = false;
    let destinationPublished = false;
    let commitBoundaryFailure: unknown;
    let session: IncomingSession<TMetadata> | undefined;
    try {
      throwIfCancelled(attempt.controller.signal);
      if (this.sessions.has(manifest.transferId) || this.reservedSessionIds.has(manifest.transferId)) {
        throw new P2PError('REJECTED', 'A transfer with this ID is already active');
      }
      this.reservedSessionIds.add(manifest.transferId);
      ownsReservation = true;
      const completed = await this.localOperation(
        (operationSignal) => destination.prepare(manifest, operationSignal),
        attempt.controller.signal,
        'File destination preparation timed out'
      );
      destinationPrepared = true;
      if (!completed || !Number.isSafeInteger(completed.size) || completed.size < 0 || completed.size > manifest.chunkCount) {
        throw new P2PError('INVALID_FRAME', 'Destination returned too many completed chunks');
      }
      const missing = ChunkBitmap.full(manifest.chunkCount);
      let completedCount = 0;
      let completedBytes = 0;
      for (const index of completed) {
        completedCount += 1;
        if (completedCount > manifest.chunkCount) {
          throw new P2PError('INVALID_FRAME', 'Destination returned too many completed chunks');
        }
        if (!Number.isSafeInteger(index) || index < 0 || index >= manifest.chunkCount) {
          throw new P2PError('INVALID_FRAME', 'Destination returned an invalid completed chunk');
        }
        if (!missing.delete(index)) throw new P2PError('INVALID_FRAME', 'Destination returned a duplicate completed chunk');
        completedBytes += expectedChunkSize(manifest, index);
      }
      if (completedCount !== completed.size) throw new P2PError('INVALID_FRAME', 'Destination completed chunk count is inconsistent');
      const allowedLanes = clampLanes(this.limits.lanes, this.limits.maxLanes, Math.max(1, missing.size));
      session = createSession(
        manifest,
        destination,
        missing,
        completed.size > 0,
        completedBytes,
        allowedLanes,
        transfer,
        context,
        attempt,
        attempt.controller.signal,
        this.idleTimeoutMs
      );
      if (this.sessions.has(manifest.transferId)) throw new P2PError('REJECTED', 'A transfer with this ID is already active');
      this.sessions.set(manifest.transferId, session);
      this.reservedSessionIds.delete(manifest.transferId);
      ownsReservation = false;
      const missingRanges = missing.ranges(this.limits.maxMissingRanges);
      const acceptance: TransferAccept = {
        transferId: manifest.transferId,
        attemptId: session.attemptId,
        laneToken: session.laneToken,
        missingRanges,
        missingCount: missing.size,
        lanes: allowedLanes
      };
      await this.writeControlFrame(
        stream.send,
        TransferFrameKind.Accept,
        acceptance,
        session.signal,
        attempt
      );
      if (completedCount > 0) {
        this.emitProgress(manifest, {
          completedChunks: completedCount,
          transferredBytes: completedBytes
        }, 'receive', transfer);
      }
      session.touch();
      if (missing.size === 0) session.resolve();
      // Read concurrently so malformed/remote terminal frames fail promptly,
      // but do not put a fixed wall-clock deadline on control silence while
      // healthy data lanes keep refreshing the session idle watchdog.
      const completionPromise = this.readControlFrameUntilCancelled(
        stream.recv,
        session.signal,
        attempt
      );
      const firstFinished = await Promise.race([
        completionPromise.then((completion) => ({ kind: 'completion' as const, completion })),
        session.done.then(() => ({ kind: 'data' as const }))
      ]);
      const completion = firstFinished.kind === 'completion'
        ? firstFinished.completion
        : await completionPromise;
      session.touch();
      if (completion.kind !== TransferFrameKind.Complete || !matchesCompletion(completion.value, acceptance)) {
        throw new P2PError('INVALID_FRAME', 'Sender completed a different transfer attempt');
      }
      // QUIC does not order independent data lanes against this control stream,
      // so a valid completion frame may arrive while lane bytes are in flight.
      await session.done;
      session.touch();
      if (session.missing.size !== 0) throw new P2PError('INVALID_FRAME', 'Sender completed before all chunks arrived');
      // A lane is complete only after its final chunk and clean FIN have both
      // been consumed. Do not finalize durable state or acknowledge the
      // transfer while a lane handler still owns a receive stream.
      await session.lanesDrained();
      session.touch();
      const receiptToken = randomBytes(32).toString('base64url');
      const commitOperation = pushOperation
        ? this.prepareCommitOperation(manifest, context.security.principal, pushOperation)
        : undefined;
      const markCommitted = (): void => {
        if (destinationPublished) {
          commitBoundaryFailure ??= new P2PError(
            'INTERNAL',
            'File destination marked publication more than once'
          );
          return;
        }
        // Set this first: even an impossible bookkeeping failure after the
        // destination's irreversible publication must take the known-commit
        // path and may never invoke rollback or emit Reject.
        destinationPublished = true;
        session!.stopIdle();
        try {
          commitOperation?.();
        } catch (cause) {
          commitBoundaryFailure = cause;
        }
      };
      await this.localOperation(
        (operationSignal) => destination.finalize(manifest, Object.freeze({
          signal: operationSignal,
          markCommitted
        }) satisfies FileDestinationFinalizeContext),
        session.signal,
        'File destination finalization timed out'
      );
      if (!destinationPublished) {
        throw new P2PError(
          'INTERNAL',
          'File destination finalized without marking durable publication'
        );
      }
      if (commitBoundaryFailure !== undefined) throw commitBoundaryFailure;
      // Atomic destination publication is the local outcome. The challenge /
      // receipt exchange tells us whether its compact reconciliation record is
      // still correctness-critical or may become an evictable replay tombstone.
      await this.acknowledgeReceiverCommit(
        stream,
        { transferId: manifest.transferId, attemptId: session.attemptId },
        context,
        session.signal,
        receiptToken,
        pushOperation
          ? () => this.acknowledgeOperation(manifest, context.security.principal, pushOperation)
          : undefined,
        trackWork
      );
      this.emitProgress(manifest, {
        completedChunks: manifest.chunkCount,
        transferredBytes: manifest.size
      }, 'receive', transfer);
      return successOutcome({ manifest, resumed: session.resumed, durationMs: Date.now() - startedAt });
    } catch (cause) {
      const error = asP2PError(cause);
      if (destinationPublished) {
        // Publication is the irreversible local commit boundary. No exception
        // after finalize() may reject, abort, roll back, or make the receiving
        // application observe failure. Preserve the exact operation handle for
        // reconciliation and quarantine the incomplete stream instead.
        await this.abortBiStream(stream, context.connection, trackWork);
        this.quarantineContext(context);
        this.emitProgress(manifest, {
          completedChunks: manifest.chunkCount,
          transferredBytes: manifest.size
        }, 'receive', transfer);
        return successOutcome({
          manifest,
          resumed: session?.resumed ?? false,
          durationMs: Date.now() - startedAt
        });
      }
      if (ownsReservation) this.reservedSessionIds.delete(manifest.transferId);
      if (session && this.sessions.get(manifest.transferId) === session) this.sessions.delete(manifest.transferId);
      // Tell the sender why this attempt is terminal while the control send
      // half is still usable. Stopping data lanes first can make their writers
      // fail with DISCONNECTED, which looks retryable and can eventually poison
      // an otherwise healthy long-lived session.
      const controlDrained = await this.rejectControlStream(stream, error, context.connection);
      session?.controller.abort(error);
      session?.reject(error);
      const receiversDrained = session
        ? await this.abortRecvStreams(session.receivers, context.connection)
        : true;
      // writeChunk() is a side-effecting custom-adapter callback. It may still
      // be cooperatively settling after its lane stream is stopped, so wait for
      // every claimed lane handler before invoking destination.abort() or
      // allowing a retry to prepare the same destination.
      if (session) await session.lanesDrained();
      let destinationCleanupError: unknown;
      if (destinationPrepared) {
        try {
          await this.localOperation(
            (operationSignal) => destination.abort(
              manifest,
              { discard: error.code === 'INTEGRITY_FAILED' || error.code === 'INVALID_FRAME' },
              operationSignal
            ),
            undefined,
            'File destination cleanup timed out'
          );
        } catch (cause) {
          destinationCleanupError = cause;
        }
      }
      if (!receiversDrained || !controlDrained) {
        return terminalOutcome(cleanupFailed(error));
      }
      // A custom destination owns side-effecting state outside this library.
      // Retrying it after rollback rejected or timed out could mix two attempts
      // in the same staging area. Make that uncertainty explicit and terminal.
      if (destinationCleanupError !== undefined) {
        return terminalOutcome(destinationCleanupFailed(error, destinationCleanupError));
      }
      return attemptOutcome(attempt, error, true);
    } finally {
      if (ownsReservation) this.reservedSessionIds.delete(manifest.transferId);
      if (session && this.sessions.get(manifest.transferId) === session) this.sessions.delete(manifest.transferId);
      session?.dispose();
    }
  }

  private async offerDestination(
    manifest: FileManifest<TMetadata>,
    security: FileTransferSecurityContext,
    signal: AbortSignal
  ): Promise<FileDestination<TMetadata>> {
    if (!this.options.incoming) throw new P2PError('REJECTED', 'Peer does not accept incoming files');
    const decision = await this.localOperation((operationSignal) => {
      const offer: FileOffer<TMetadata> = Object.freeze({
        peerId: this.options.peerId,
        principal: security.principal,
        sessionId: security.sessionId,
        signal: operationSignal,
        manifest
      });
      return Promise.resolve(this.options.incoming!(offer));
    }, signal, 'Incoming file decision timed out');
    if (!isRecord(decision)) throw new P2PError('INTERNAL', 'Incoming file handler returned an invalid decision');
    assertOnlyKeys(decision, ['accept', 'reject'], 'Incoming file decision');
    if ((decision.reject === true || typeof decision.reject === 'string') && decision.accept === undefined) {
      throw new P2PError(
        'REJECTED',
        safeRejectionReason(decision.reject === true ? undefined : decision.reject, 'File offer rejected')
      );
    }
    if (
      decision.accept === undefined ||
      decision.reject !== undefined ||
      !isFileDestination(decision.accept)
    ) {
      throw new P2PError('INTERNAL', 'Incoming file handler returned an invalid decision');
    }
    return decision.accept as FileDestination<TMetadata>;
  }

  private async reconcileCommittedPush(
    stream: QuicBiStream,
    manifest: FileManifest<TMetadata>,
    operation: OperationRecord,
    context: FileTransferConnectionContext,
    signal: AbortSignal,
    trackWork: FileWorkTracker
  ): Promise<void> {
    try {
      const acceptance: TransferAccept = {
        transferId: manifest.transferId,
        attemptId: randomOpaqueId(),
        laneToken: randomBytes(32).toString('base64url'),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      };
      await this.writeControlFrame(stream.send, TransferFrameKind.Accept, acceptance, signal);
      const completion = await this.readControlFrame(stream.recv, signal);
      if (completion.kind !== TransferFrameKind.Complete || !matchesCompletion(completion.value, acceptance)) {
        throw new P2PError('INVALID_FRAME', 'Sender reconciled a different committed transfer attempt');
      }
      await this.acknowledgeReceiverCommit(
        stream,
        { transferId: manifest.transferId, attemptId: acceptance.attemptId },
        context,
        signal,
        randomBytes(32).toString('base64url'),
        () => this.acknowledgeOperation(manifest, context.security.principal, operation),
        trackWork
      );
    } catch {
      // The durable commit predates this reconciliation stream. A malformed
      // retry, EOF, timeout, or cancellation cannot change that known local
      // outcome and must never produce a misleading Reject. Keep the committed
      // record for a later valid retry and quarantine this incomplete stream.
      await this.abortBiStream(stream, context.connection, trackWork);
      this.quarantineContext(context);
    }
  }

  /** Complete a known-successful sender stream without changing its outcome. */
  private async finishAcknowledgedSender(
    stream: QuicBiStream,
    acknowledgement: CompletionAcknowledgement,
    context: FileTransferConnectionContext,
    signal: AbortSignal,
    trackWork: FileWorkTracker
  ): Promise<void> {
    try {
      await this.writeControlFrame(stream.send, TransferFrameKind.Receipt, acknowledgement, signal);
      await this.finishSendStream(stream.send, signal);
      await this.expectRecvEnd(stream.recv, signal);
    } catch {
      // The receiver has already attested durable commit. Quarantine an
      // incomplete terminal exchange, but never turn known success into an
      // OUTCOME_UNKNOWN result or retry it.
      await this.abortBiStream(stream, context.connection, trackWork);
      this.quarantineContext(context);
    }
  }

  /**
   * Challenge the sender after durable commit. Only an echo of this fresh
   * token proves that the acknowledgement reached the sender application.
   */
  private async acknowledgeReceiverCommit(
    stream: QuicBiStream,
    completion: CompletionFrame,
    context: FileTransferConnectionContext,
    signal: AbortSignal,
    receiptToken: string,
    onReceipt?: () => void,
    trackWork: FileWorkTracker = ignoreFileWork
  ): Promise<void> {
    const acknowledgement: CompletionAcknowledgement = {
      ...completion,
      receiptToken
    };
    try {
      await this.writeControlFrame(stream.send, TransferFrameKind.Complete, acknowledgement, signal);
      const receipt = await this.readControlFrame(stream.recv, signal);
      if (receipt.kind !== TransferFrameKind.Receipt || !matchesCompletionAcknowledgement(receipt.value, acknowledgement)) {
        throw new P2PError('INVALID_FRAME', 'Sender did not receipt this transfer acknowledgement');
      }
      // Receipt proves the sender observed success; retain only a bounded,
      // evictable recent-replay tombstone from this point onward.
      onReceipt?.();
      await this.expectRecvEnd(stream.recv, signal);
      await this.finishSendStream(stream.send, signal);
    } catch {
      // Finalization already published the destination. Preserve any committed
      // reconciliation record, quarantine the incomplete protocol stream, and
      // report the known local success to the receiving application.
      await this.abortBiStream(stream, context.connection, trackWork);
      this.quarantineContext(context);
    }
  }

  private operationRecord(
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal
  ): OperationAdmission {
    return this.receiverOperations.admit(this.options.peerId, manifest, principal);
  }

  private finishFailedOperation(
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord,
    cause: unknown
  ): void {
    this.receiverOperations.finishFailed(this.options.peerId, manifest, principal, operation, cause);
  }

  private prepareCommitOperation(
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): () => void {
    return this.receiverOperations.prepareCommit(this.options.peerId, manifest, principal, operation);
  }

  private acknowledgeOperation(
    manifest: FileManifest<TMetadata>,
    principal: SessionPrincipal,
    operation: OperationRecord
  ): void {
    this.receiverOperations.acknowledge(this.options.peerId, manifest, principal, operation);
  }

  private async openPull(
    token: string,
    requestId: string,
    options: DownloadFileOptions,
    attempt: FileConnectionAttempt
  ): Promise<AttemptOutcome<{
    stream: QuicBiStream;
    manifest: FileManifest<TMetadata>;
    context: FileTransferConnectionContext;
  }>> {
    throwIfCancelled(attempt.controller.signal);
    validateTransferId(requestId, this.limits);
    validateChunkSize(options.chunkSize ?? this.limits.chunkSize, this.limits.maxChunkSize);
    validateLaneCount(options.lanes ?? this.limits.lanes, this.limits);
    let context: FileTransferConnectionContext | undefined;
    let stream: QuicBiStream | undefined;
    try {
      context = await this.getConnection(attempt);
      const opened = await this.openBiStream(context.connection, attempt.controller.signal, attempt);
      stream = opened;
      await this.networkOperation(
        () => opened.send.setPriority(50),
        attempt.controller.signal,
        'File control priority timed out',
        attempt
      );
      await this.writeKind(opened.send, StreamKind.TransferControl, attempt.controller.signal, attempt);
      await this.writeControlFrame(opened.send, TransferFrameKind.Pull, {
        token,
        requestId,
        options: { chunkSize: options.chunkSize ?? this.limits.chunkSize, lanes: options.lanes ?? this.limits.lanes }
      } satisfies TransferPull, attempt.controller.signal, attempt);
      const offer = await this.readControlFrame(opened.recv, attempt.controller.signal, attempt);
      if (offer.kind === TransferFrameKind.Reject) throw remoteRejection(offer.value);
      if (offer.kind !== TransferFrameKind.Offer) throw new P2PError('INVALID_FRAME', 'Pull did not receive a file offer');
      const manifest = await this.validateManifestMetadata(
        validateManifest<TMetadata>(offer.value, this.limits),
        attempt.controller.signal
      );
      return successOutcome({ stream: opened, manifest, context });
    } catch (cause) {
      if (!stream || !context) return attemptOutcome(attempt, cause, true);
      const drained = await this.abortBiStream(stream, context.connection);
      return attemptOutcome(attempt, drained ? cause : cleanupFailed(cause), drained);
    }
  }

  private async retryFiles<TResult>(
    signal: AbortSignal,
    operation: (attempt: FileConnectionAttempt) => Promise<AttemptOutcome<TResult>>
  ): Promise<TResult> {
    let retryCount = 0;
    while (true) {
      throwIfCancelled(signal);
      const attempt = new FileConnectionAttempt(signal);
      let outcome: AttemptOutcome<TResult>;
      try {
        outcome = await operation(attempt);
      } catch (cause) {
        // Attempt implementations must explicitly return retryability only
        // after settling every resource they own. An escaped exception has no
        // such proof and therefore fails closed.
        outcome = terminalOutcome(cause);
      } finally {
        attempt.dispose();
      }
      if (outcome.kind === 'success') return outcome.value;
      if (outcome.kind !== 'retryable-transport-loss' || retryCount >= 5) throw outcome.error;
      try {
        await delay(Math.min(500 * 2 ** retryCount, 8_000), undefined, { signal });
      } catch (delayCause) {
        if (signal.aborted) throw signalError(signal);
        throw delayCause;
      }
      retryCount += 1;
    }
  }

  private async validateManifestMetadata(
    manifest: FileManifest<TMetadata>,
    signal: AbortSignal
  ): Promise<FileManifest<TMetadata>> {
    if (manifest.metadata === undefined) return manifest;
    const metadata = await this.validateMetadataValue(manifest.metadata, signal);
    return validateManifest<TMetadata>({
      transferId: manifest.transferId,
      name: manifest.name,
      size: manifest.size,
      digest: manifest.digest,
      chunkSize: manifest.chunkSize,
      chunkCount: manifest.chunkCount,
      metadata
    }, this.limits);
  }

  private async validateMetadataValue(value: unknown, signal: AbortSignal): Promise<TMetadata> {
    const schema = this.options.metadataSchema;
    if (!schema) throw new P2PError('INVALID_FRAME', 'File metadata is not enabled for this node');
    const result = await this.localOperation(
      () => Promise.resolve(schema['~standard'].validate(value)),
      signal,
      'File metadata validation timed out'
    );
    if (
      !result ||
      typeof result !== 'object' ||
      !('value' in result) ||
      ('issues' in result && result.issues !== undefined)
    ) {
      throw new P2PError('INVALID_FRAME', 'File metadata failed runtime schema validation');
    }
    return result.value;
  }

  private emitProgress(
    manifest: FileManifest<TMetadata>,
    completed: { readonly completedChunks: number; readonly transferredBytes: number },
    direction: 'send' | 'receive',
    transfer: Transfer<TMetadata> | undefined
  ): void {
    const progress: TransferProgress = Object.freeze({
      transferId: manifest.transferId,
      direction,
      transferredBytes: completed.transferredBytes,
      totalBytes: manifest.size,
      completedChunks: completed.completedChunks,
      totalChunks: manifest.chunkCount
    });
    transfer?.emit(progress);
    try {
      const delivered = this.options.onProgress?.(progress);
      void Promise.resolve(delivered).catch(() => undefined);
    } catch {
      // Observability callbacks cannot influence transfer correctness.
    }
  }

  private frameLimits(): FrameLimits {
    return this.options.frameLimits ?? DEFAULT_FRAME_LIMITS;
  }

  private readControlFrame<T = unknown>(
    recv: QuicRecvStream,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<Frame<T>> {
    return this.networkOperation(
      () => readFrame<T>(recv, this.frameLimits()),
      signal,
      'File control frame timed out',
      attempt
    );
  }

  private readControlFrameUntilCancelled<T = unknown>(
    recv: QuicRecvStream,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<Frame<T>> {
    return cancellableOperation(
      () => readFrame<T>(recv, this.frameLimits()),
      signal,
      'DISCONNECTED',
      true,
      attempt
    );
  }

  private async getConnection(attempt: FileConnectionAttempt): Promise<FileTransferConnectionContext> {
    const context = await this.networkOperation(
      this.options.connection,
      attempt.controller.signal,
      'File connection timed out',
      attempt
    );
    if (
      !context ||
      typeof context !== 'object' ||
      !context.connection ||
      !context.security ||
      !(context.signal instanceof AbortSignal)
    ) {
      throw new P2PError('INTERNAL', 'File connection provider returned an invalid authenticated context');
    }
    attempt.bindConnectionSignal(context.signal);
    throwIfCancelled(attempt.controller.signal);
    return context;
  }

  private async openBiStream(
    connection: QuicConnection,
    signal: AbortSignal,
    attempt: FileConnectionAttempt
  ): Promise<QuicBiStream> {
    const opening = linkedController(signal);
    let pendingSettled = false;
    const pending = Promise.resolve().then(() => connection.openBi({
      fileControl: 'outbound',
      signal: opening.controller.signal
    })).then(
      (stream) => {
        pendingSettled = true;
        return stream;
      },
      (cause: unknown) => {
        pendingSettled = true;
        throw cause;
      }
    );
    try {
      return await this.networkOperation(() => pending, signal, 'Opening file control stream timed out', attempt);
    } catch (cause) {
      if (!opening.controller.signal.aborted) opening.controller.abort(cause);
      if (!pendingSettled) this.quarantineConnection(connection);
      void pending.then((stream) => this.abortBiStream(stream, connection), () => undefined);
      throw cause;
    } finally {
      opening.dispose();
    }
  }

  private async openUniStream(
    connection: QuicConnection,
    signal: AbortSignal,
    attempt: FileConnectionAttempt
  ): Promise<QuicSendStream> {
    const opening = linkedController(signal);
    let pendingSettled = false;
    const pending = Promise.resolve().then(() => connection.openUni({
      fileData: 'outbound',
      signal: opening.controller.signal
    })).then(
      (stream) => {
        pendingSettled = true;
        return stream;
      },
      (cause: unknown) => {
        pendingSettled = true;
        throw cause;
      }
    );
    try {
      return await this.networkOperation(() => pending, signal, 'Opening file data stream timed out', attempt);
    } catch (cause) {
      if (!opening.controller.signal.aborted) opening.controller.abort(cause);
      if (!pendingSettled) this.quarantineConnection(connection);
      void pending.then((send) => this.abortSendStream(send, connection), () => undefined);
      throw cause;
    } finally {
      opening.dispose();
    }
  }

  private writeKind(
    send: QuicSendStream,
    kind: StreamKind,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<void> {
    return this.networkOperation(
      () => writeStreamKind(send, kind),
      signal,
      'Writing file stream header timed out',
      attempt
    );
  }

  private writeControlFrame(
    send: QuicSendStream,
    kind: TransferFrameKind,
    value: unknown,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<void> {
    return this.networkOperation(
      () => writeFrame(send, kind, value, this.frameLimits()),
      signal,
      'Writing file control frame timed out',
      attempt
    );
  }

  private finishSendStream(
    send: QuicSendStream,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<void> {
    return this.networkOperation(() => send.finish(), signal, 'Finishing file stream timed out', attempt);
  }

  private expectRecvEnd(
    recv: QuicRecvStream,
    signal?: AbortSignal,
    attempt?: FileConnectionAttempt
  ): Promise<void> {
    return this.networkOperation(() => recv.expectEnd(), signal, 'Finishing file stream timed out', attempt);
  }

  private async writeChunkBody(
    send: QuicSendStream,
    data: Uint8Array,
    signal: AbortSignal,
    attempt: FileConnectionAttempt
  ): Promise<void> {
    for (let offset = 0; offset < data.byteLength; offset += FILE_DATA_SEGMENT_BYTES) {
      const segment = data.subarray(offset, Math.min(data.byteLength, offset + FILE_DATA_SEGMENT_BYTES));
      await this.networkOperation(() => send.writeAll(segment), signal, 'File chunk write timed out', attempt);
    }
  }

  private async readChunkBody(
    recv: QuicRecvStream,
    size: number,
    signal: AbortSignal,
    attempt: FileConnectionAttempt,
    onProgress?: () => void
  ): Promise<Uint8Array> {
    const data = new Uint8Array(size);
    for (let offset = 0; offset < size; offset += FILE_DATA_SEGMENT_BYTES) {
      const length = Math.min(FILE_DATA_SEGMENT_BYTES, size - offset);
      data.set(
        await this.networkOperation(() => recv.readExact(length), signal, 'File chunk body timed out', attempt),
        offset
      );
      onProgress?.();
    }
    return data;
  }

  private networkOperation<TResult>(
    operation: () => Promise<TResult>,
    signal: AbortSignal | undefined,
    message: string,
    attempt?: FileConnectionAttempt
  ): Promise<TResult> {
    return boundedOperation(operation, this.idleTimeoutMs, message, signal, 'DISCONNECTED', true, attempt);
  }

  private localOperation<TResult>(
    operation: (signal: AbortSignal) => Promise<TResult>,
    signal: AbortSignal | undefined,
    message: string
  ): Promise<TResult> {
    return cooperativeOperation(operation, this.idleTimeoutMs, message, signal);
  }

  private async settleTasks(
    tasks: readonly Promise<unknown>[],
    connection: QuicConnection
  ): Promise<boolean> {
    if (tasks.length === 0) return true;
    const settled = await this.cleanupOperation(() => Promise.allSettled(tasks).then(() => undefined));
    return this.confirmStreamCleanup(settled, connection);
  }

  private async abortSendStream(
    send: QuicSendStream,
    connection: QuicConnection
  ): Promise<boolean> {
    const reset = await this.cleanupOperation(() => send.reset(3n));
    return this.confirmStreamCleanup(reset, connection);
  }

  private async abortRecvStream(
    recv: QuicRecvStream,
    connection: QuicConnection
  ): Promise<boolean> {
    const stopped = await this.cleanupOperation(() => recv.stop(3n));
    return this.confirmStreamCleanup(stopped, connection);
  }

  private async abortBiStream(
    stream: QuicBiStream,
    connection: QuicConnection,
    trackWork?: FileWorkTracker
  ): Promise<boolean> {
    // Subscribe before reset/stop can synchronously close or invalidate a
    // native adapter handle. Register the proof only if terminal cleanup is
    // unconfirmed, so the ordinary success path releases immediately.
    const physicalClosure = trackWork ? physicalClosureProof(connection) : undefined;
    const results = await Promise.all([
      this.cleanupOperation(() => stream.send.reset(3n)),
      this.cleanupOperation(() => stream.recv.stop(3n))
    ]);
    const confirmed = this.confirmStreamCleanup(results.every(Boolean), connection);
    if (!confirmed && trackWork) trackWork(physicalClosure!);
    return confirmed;
  }

  private async abortSendStreams(
    streams: ReadonlySet<QuicSendStream>,
    connection: QuicConnection
  ): Promise<boolean> {
    const results = await Promise.all(
      [...streams].map((stream) => this.cleanupOperation(() => stream.reset(3n)))
    );
    return this.confirmStreamCleanup(results.every(Boolean), connection);
  }

  private async abortRecvStreams(
    streams: ReadonlySet<QuicRecvStream>,
    connection: QuicConnection
  ): Promise<boolean> {
    const results = await Promise.all(
      [...streams].map((stream) => this.cleanupOperation(() => stream.stop(3n)))
    );
    return this.confirmStreamCleanup(results.every(Boolean), connection);
  }

  private async rejectControlStream(
    stream: QuicBiStream,
    cause: unknown,
    connection: QuicConnection
  ): Promise<boolean> {
    let wrote = false;
    const writeSettled = await this.cleanupOperation(async () => {
      await writeFrame(stream.send, TransferFrameKind.Reject, publicRejection(cause), this.frameLimits());
      await stream.send.finish();
      wrote = true;
    });
    const recvStopped = await this.cleanupOperation(() => stream.recv.stop(3n));
    if (writeSettled && wrote) {
      return this.confirmStreamCleanup(recvStopped, connection);
    }
    const sendReset = await this.cleanupOperation(() => stream.send.reset(3n));
    return this.confirmStreamCleanup(sendReset && recvStopped, connection);
  }

  private async cleanupOperation(operation: () => Promise<unknown>): Promise<boolean> {
    try {
      await withDeadline(
        Promise.resolve().then(operation),
        Math.min(this.idleTimeoutMs, 1_000),
        'File stream cleanup timed out'
      );
      return true;
    } catch {
      return false;
    }
  }

  private confirmStreamCleanup(confirmed: boolean, connection: QuicConnection): boolean {
    if (!confirmed) this.quarantineConnection(connection);
    return confirmed;
  }

  private quarantineConnection(connection: QuicConnection): void {
    try {
      connection.close(4n, new TextEncoder().encode('File stream cleanup failed'));
    } catch {
      // The caller still receives cleanupFailed(); a throwing transport close
      // cannot turn an unconfirmed stream into an apparently successful one.
    }
  }

  private quarantineContext(context: FileTransferConnectionContext): void {
    if (!context.quarantine) {
      this.quarantineConnection(context.connection);
      return;
    }
    try {
      context.quarantine('File stream cleanup failed');
    } catch {
      // The fulfilled-only connection barrier still owns native resources.
      // Quarantine callbacks are fail-closed policy notifications and cannot
      // change a known transfer outcome.
    }
  }

  private async acquireTransferSlot(
    direction: FileTransferDirection,
    signal: AbortSignal
  ): Promise<() => void> {
    throwIfCancelled(signal);
    this.queuedTransfers[direction] += 1;
    let releaseAdmission: (() => void) | undefined;
    try {
      releaseAdmission = this.options.acquireTransfer
        ? await this.options.acquireTransfer(direction, signal)
        : await this.acquireLocalTransferSlot(direction, signal);
    } finally {
      this.queuedTransfers[direction] -= 1;
    }
    this.activeTransfers[direction] += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.activeTransfers[direction] -= 1;
      releaseAdmission!();
    };
  }

  private async acquireLocalTransferSlot(
    direction: FileTransferDirection,
    signal: AbortSignal
  ): Promise<() => void> {
    const slots = this.localTransferSlots[direction];
    throwIfCancelled(signal);
    if (slots.active < this.limits.maxTransfers) {
      slots.active += 1;
    } else {
      if (slots.waiters.length >= this.limits.maxQueuedTransfers) {
        throw new P2PError('RESOURCE_LIMIT', 'File transfer queue is full');
      }
      await new Promise<void>((resolve, reject) => {
        const waiter = (): void => {
          detachAbort();
          resolve();
        };
        const detachAbort = onAbort(signal, () => {
          const index = slots.waiters.indexOf(waiter);
          if (index >= 0) slots.waiters.splice(index, 1);
          reject(signalError(signal));
        });
        slots.waiters.push(waiter);
      });
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const waiter = slots.waiters.shift();
      if (waiter) waiter();
      else slots.active -= 1;
    };
  }
}

function createSession<TMetadata>(
  manifest: FileManifest<TMetadata>,
  destination: FileDestination<TMetadata>,
  missing: ChunkBitmap,
  resumed: boolean,
  transferredBytes: number,
  allowedLanes: number,
  transfer: Transfer<TMetadata> | undefined,
  context: FileTransferConnectionContext,
  connectionAttempt: FileConnectionAttempt,
  signal: AbortSignal,
  idleTimeoutMs: number
): IncomingSession<TMetadata> {
  const linked = childController(signal);
  let resolvePromise!: () => void;
  let rejectPromise!: (error: unknown) => void;
  let settled = false;
  let activeLanes = 0;
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  const laneDrainWaiters = new Set<() => void>();
  const done = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  // Lane failures can arrive before the control flow awaits `done`; attach a
  // handler immediately while preserving the original rejection for awaiters.
  void done.catch(() => undefined);
  const detachAbort = onAbort(linked.controller.signal, () => {
    if (!settled) {
      settled = true;
      rejectPromise(signalError(linked.controller.signal));
    }
  });
  const stopIdle = (): void => {
    if (idleTimer) clearTimeout(idleTimer);
    idleTimer = undefined;
  };
  const touch = (): void => {
    if (linked.controller.signal.aborted) return;
    stopIdle();
    idleTimer = setTimeout(() => linked.controller.abort(
      new P2PError('TIMEOUT', 'File transfer made no progress before its idle deadline')
    ), idleTimeoutMs);
    idleTimer.unref?.();
  };
  touch();
  return {
    manifest,
    destination,
    missing,
    inFlight: new Set(),
    claimedLanes: new Set(),
    attemptId: randomOpaqueId(),
    laneToken: randomBytes(32).toString('base64url'),
    allowedLanes,
    totalMissing: missing.size,
    resumed,
    transfer,
    context,
    connectionAttempt,
    controller: linked.controller,
    signal: linked.controller.signal,
    receivers: new Set(),
    done,
    announcedChunks: 0,
    transferredBytes,
    touch,
    stopIdle,
    beginLane() {
      activeLanes += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        activeLanes -= 1;
        if (activeLanes === 0) {
          if (missing.size === 0) this.resolve();
          for (const resolve of laneDrainWaiters) resolve();
          laneDrainWaiters.clear();
        }
      };
    },
    lanesDrained() {
      if (activeLanes === 0) return Promise.resolve();
      return new Promise<void>((resolve) => laneDrainWaiters.add(resolve));
    },
    resolve() {
      if (!settled) {
        settled = true;
        resolvePromise();
      }
    },
    reject(error) {
      if (!settled) {
        settled = true;
        rejectPromise(error);
      }
    },
    dispose() {
      stopIdle();
      detachAbort();
      linked.dispose();
    }
  };
}

function linkedController(signal?: AbortSignal): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const dispose = onAbort(signal, () => controller.abort(signal?.reason));
  return { controller, dispose };
}

function childController(signal: AbortSignal): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const dispose = onAbort(signal, () => controller.abort(signal.reason));
  return { controller, dispose };
}

function combinedController(signals: readonly AbortSignal[]): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const disposers = signals.map((signal) => onAbort(signal, () => controller.abort(signal.reason)));
  return {
    controller,
    dispose() {
      for (const dispose of disposers) dispose();
    }
  };
}

/**
 * Attempt-local retry provenance.
 *
 * Callback-visible abort reasons are ordinary P2PErrors. Retry authority is
 * held only in this private instance, so retaining and rethrowing an earlier
 * attempt's error cannot authorize a later attempt or replay stale drain
 * evidence.
 */
class FileConnectionAttempt {
  readonly controller = new AbortController();
  private readonly transportLosses = new WeakSet<P2PError>();
  private readonly operationDispose: () => void;
  private connectionDispose: (() => void) | undefined;
  private connectionSignal: AbortSignal | undefined;

  constructor(operationSignal: AbortSignal) {
    this.operationDispose = onAbort(operationSignal, () => {
      this.controller.abort(publicAbortError(operationSignal.reason));
    });
  }

  bindConnectionSignal(signal: AbortSignal): void {
    if (this.connectionSignal === signal) return;
    if (this.connectionSignal !== undefined) {
      throw new P2PError('INTERNAL', 'File attempt was bound to more than one authenticated connection');
    }
    this.connectionSignal = signal;
    this.connectionDispose = onAbort(signal, () => {
      const reason = signal.reason;
      if (reason instanceof P2PError && reason.code === 'DISCONNECTED') {
        this.controller.abort(this.recordTransportLoss(reason));
        return;
      }
      // An untyped abort cannot distinguish transport loss from application
      // cancellation, session policy, or adapter failure. It carries no retry
      // authority.
      this.controller.abort(publicAbortError(reason));
    });
  }

  recordTransportLoss(cause: P2PError): P2PError {
    if (this.transportLosses.has(cause)) return cause;
    const error = new P2PError('DISCONNECTED', cause.message, { cause });
    this.transportLosses.add(error);
    return error;
  }

  isTransportLoss(cause: unknown): boolean {
    return cause instanceof P2PError && this.transportLosses.has(cause);
  }

  dispose(): void {
    this.operationDispose();
    this.connectionDispose?.();
  }
}

function publicAbortError(reason: unknown): P2PError {
  return reason instanceof P2PError
    ? new P2PError(reason.code, reason.message, { cause: reason })
    : cancelledError();
}

function onAbort(signal: AbortSignal | undefined, callback: () => void): () => void {
  if (!signal) return () => undefined;
  if (signal.aborted) {
    callback();
    return () => undefined;
  }
  signal.addEventListener('abort', callback, { once: true });
  return () => signal.removeEventListener('abort', callback);
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signalError(signal);
}

function cancelledError(): P2PError {
  return new P2PError('CANCELLED', 'Transfer cancelled');
}

function signalError(signal: AbortSignal): P2PError {
  return signal.reason instanceof P2PError ? signal.reason : cancelledError();
}

function cleanupFailed(cause: unknown): P2PError {
  return new P2PError('INTERNAL', 'File transfer stream cleanup could not be confirmed', { cause });
}

function destinationCleanupFailed(operation: unknown, cleanup: unknown): P2PError {
  return new P2PError(
    'OUTCOME_UNKNOWN',
    'File destination cleanup could not be confirmed; automatic retry is unsafe',
    { cause: { operation, cleanup } }
  );
}

function preparedSourceCleanupFailed(operation: unknown, cleanup: unknown): P2PError {
  return new P2PError(
    'OUTCOME_UNKNOWN',
    'Prepared file source cleanup could not be confirmed after an operation failure; automatic retry is unsafe',
    { cause: { operation, cleanup } }
  );
}

class SharedPullAttempt<TMetadata> {
  private readonly linked: ReturnType<typeof combinedController>;
  private prepared: PreparedFileSource<TMetadata> | undefined;
  private settled = false;

  constructor(
    private readonly reservation: ShareReservation<TMetadata>,
    operationSignal: AbortSignal
  ) {
    this.linked = combinedController([operationSignal, reservation.signal]);
  }

  get signal(): AbortSignal {
    return this.linked.controller.signal;
  }

  adoptPrepared(source: PreparedFileSource<TMetadata>): void {
    if (this.prepared || this.settled) {
      throw new P2PError('INTERNAL', 'Shared pull prepared-source ownership is already settled');
    }
    this.prepared = source;
  }

  async settle(outcome: ControlOutcome): Promise<P2PError | undefined> {
    if (this.settled) throw new P2PError('INTERNAL', 'Shared pull attempt settled more than once');
    this.settled = true;
    let cleanupFailure: unknown;
    try {
      if (this.prepared) await closePreparedFileSource(this.prepared);
    } catch (cause) {
      cleanupFailure = cause;
    }

    if (outcome.kind === 'success') {
      this.reservation.complete();
      // Acknowledgement is already known. Source cleanup cannot make the peer
      // safely repeat a completed capability operation.
      return undefined;
    }
    if (cleanupFailure !== undefined) {
      this.reservation.complete();
      return preparedSourceCleanupFailed(outcome.error, cleanupFailure);
    }
    if (outcome.kind === 'retryable-transport-loss') this.reservation.release();
    else this.reservation.complete();
    return outcome.error;
  }

  dispose(): void {
    this.linked.dispose();
  }
}

function successOutcome<T>(value: T): AttemptOutcome<T> {
  return { kind: 'success', value };
}

function terminalOutcome<T = never>(cause: unknown): AttemptOutcome<T> {
  return { kind: 'terminal-failure', error: asP2PError(cause) };
}

function attemptOutcome<T>(
  attempt: FileConnectionAttempt,
  cause: unknown,
  streamsDrained: boolean
): AttemptOutcome<T> {
  const error = asP2PError(cause);
  return streamsDrained && attempt.isTransportLoss(cause)
    ? { kind: 'retryable-transport-loss', error }
    : { kind: 'terminal-failure', error };
}

function validatePull(value: unknown, limits: FileTransferLimits): TransferPull {
  if (!isRecord(value) || typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.token)) {
    throw new P2PError('INVALID_FRAME', 'Invalid file pull request');
  }
  assertOnlyKeys(value, ['token', 'requestId', 'options'], 'File pull request');
  const requestId = validateTransferId(value.requestId, limits);
  if (value.options !== undefined && !isRecord(value.options)) throw new P2PError('INVALID_FRAME', 'Invalid file pull options');
  const options = value.options as Record<string, unknown> | undefined;
  if (options) assertOnlyKeys(options, ['chunkSize', 'lanes'], 'File pull options');
  const chunkSize = options?.chunkSize === undefined
    ? undefined
    : validateChunkSize(options.chunkSize as number, limits.maxChunkSize);
  const lanes = options?.lanes === undefined ? undefined : validateLaneCount(options.lanes as number, limits);
  return {
    token: value.token,
    requestId,
    ...((chunkSize !== undefined || lanes !== undefined) ? { options: { ...(chunkSize !== undefined ? { chunkSize } : {}), ...(lanes !== undefined ? { lanes } : {}) } } : {})
  };
}

function validateAccept(value: unknown, manifest: FileManifest, limits: FileTransferLimits): TransferAccept {
  if (!isRecord(value) || value.transferId !== manifest.transferId) throw new P2PError('INVALID_FRAME', 'Invalid transfer acceptance');
  assertOnlyKeys(value, ['transferId', 'attemptId', 'laneToken', 'missingRanges', 'missingCount', 'lanes'], 'Transfer acceptance');
  const attemptId = validateOpaqueId(value.attemptId, 'attempt ID');
  const laneToken = validateLaneToken(value.laneToken);
  const lanes = validateLaneCount(value.lanes as number, limits);
  if (!Number.isSafeInteger(value.missingCount) || (value.missingCount as number) < 0 || (value.missingCount as number) > manifest.chunkCount) {
    throw new P2PError('INVALID_FRAME', 'Invalid missing chunk count');
  }
  if (!Array.isArray(value.missingRanges) || value.missingRanges.length > limits.maxMissingRanges) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid or excessive missing chunk ranges');
  }
  return {
    transferId: manifest.transferId,
    attemptId,
    laneToken,
    missingRanges: value.missingRanges as Array<readonly [number, number]>,
    missingCount: value.missingCount as number,
    lanes
  };
}

function validateLaneHeader(value: unknown, limits: FileTransferLimits): LaneHeader {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer lane header');
  assertOnlyKeys(value, ['transferId', 'attemptId', 'laneToken', 'laneId', 'count'], 'Transfer lane header');
  const transferId = validateTransferId(value.transferId, limits);
  const attemptId = validateOpaqueId(value.attemptId, 'attempt ID');
  const laneToken = validateLaneToken(value.laneToken);
  if (!Number.isSafeInteger(value.laneId) || (value.laneId as number) < 0 || (value.laneId as number) >= limits.maxLanes) {
    throw new P2PError('INVALID_FRAME', 'Invalid transfer lane ID');
  }
  if (!Number.isSafeInteger(value.count) || (value.count as number) < 1 || (value.count as number) > limits.maxChunkCount) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid transfer lane chunk count');
  }
  return { transferId, attemptId, laneToken, laneId: value.laneId as number, count: value.count as number };
}

function validateChunkHeader(value: unknown, manifest: FileManifest): ChunkHeader {
  if (!isRecord(value) || !Number.isSafeInteger(value.index)) throw new P2PError('INVALID_FRAME', 'Invalid chunk header');
  assertOnlyKeys(value, ['index', 'size', 'digest'], 'Chunk header');
  const index = value.index as number;
  const expected = expectedChunkSize(manifest, index);
  if (value.size !== expected) throw new P2PError('INVALID_FRAME', `Invalid size for chunk ${index}`);
  const digest = validateDigest(value.digest, 'chunk digest');
  return { index, size: expected, digest };
}

function validateLaneCount(value: number, limits: FileTransferLimits): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > limits.maxLanes) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid lane count');
  }
  return value;
}

function clampLanes(value: number, max: number, work: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new P2PError('RESOURCE_LIMIT', 'Invalid lane count');
  return Math.max(1, Math.min(value, max, work));
}

function validateMissingRanges(
  ranges: Array<readonly [number, number]>,
  chunkCount: number,
  expectedCount: number
): MissingRanges {
  let count = 0;
  let previousEnd = 0;
  for (const range of ranges) {
    if (!Array.isArray(range) || range.length !== 2) throw new P2PError('INVALID_FRAME', 'Invalid chunk range');
    const [start, end] = range;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < previousEnd || end <= start || end > chunkCount) {
      throw new P2PError('INVALID_FRAME', 'Invalid or overlapping chunk range');
    }
    count += end - start;
    if (count > expectedCount) throw new P2PError('INVALID_FRAME', 'Missing ranges exceed their declared count');
    previousEnd = end;
  }
  if (count !== expectedCount) throw new P2PError('INVALID_FRAME', 'Missing ranges do not match their declared count');
  return new MissingRanges(ranges, count);
}

class MissingRanges {
  constructor(
    private readonly ranges: readonly (readonly [number, number])[],
    readonly count: number
  ) {}

  byteLength(manifest: FileManifest): number {
    let bytes = 0;
    for (const [start, end] of this.ranges) {
      const startOffset = Math.min(manifest.size, start * manifest.chunkSize);
      const endOffset = Math.min(manifest.size, end * manifest.chunkSize);
      bytes += endOffset - startOffset;
    }
    return bytes;
  }

  *slice(offset: number, count: number): Iterable<number> {
    let skipped = 0;
    let emitted = 0;
    for (const [start, end] of this.ranges) {
      const rangeLength = end - start;
      if (skipped + rangeLength <= offset) {
        skipped += rangeLength;
        continue;
      }
      const first = start + Math.max(0, offset - skipped);
      for (let index = first; index < end && emitted < count; index += 1) {
        yield index;
        emitted += 1;
      }
      skipped += rangeLength;
      if (emitted === count) return;
    }
  }
}

/** Compact mutable set for chunk indexes: one bit per possible chunk. */
class ChunkBitmap {
  private constructor(
    private readonly bits: Uint8Array,
    private count: number
  ) {}

  static full(chunkCount: number): ChunkBitmap {
    const bits = new Uint8Array(Math.ceil(chunkCount / 8));
    bits.fill(0xff);
    const remainder = chunkCount % 8;
    if (remainder !== 0) bits[bits.length - 1] = (1 << remainder) - 1;
    return new ChunkBitmap(bits, chunkCount);
  }

  get size(): number {
    return this.count;
  }

  has(index: number): boolean {
    const byte = this.bits[index >>> 3];
    return byte !== undefined && (byte & (1 << (index & 7))) !== 0;
  }

  delete(index: number): boolean {
    const byteIndex = index >>> 3;
    const byte = this.bits[byteIndex];
    const mask = 1 << (index & 7);
    if (byte === undefined || (byte & mask) === 0) return false;
    this.bits[byteIndex] = byte & ~mask;
    this.count -= 1;
    return true;
  }

  ranges(maximumRanges: number): Array<readonly [number, number]> {
    const ranges: Array<readonly [number, number]> = [];
    let start: number | undefined;
    const maximumIndex = this.bits.length * 8;
    for (let index = 0; index < maximumIndex; index += 1) {
      if (this.has(index)) {
        start ??= index;
      } else if (start !== undefined) {
        ranges.push([start, index]);
        start = undefined;
        if (ranges.length > maximumRanges) throw new P2PError('RESOURCE_LIMIT', 'Resume state is too fragmented');
      }
    }
    if (start !== undefined) ranges.push([start, maximumIndex]);
    if (ranges.length > maximumRanges) throw new P2PError('RESOURCE_LIMIT', 'Resume state is too fragmented');
    return ranges;
  }
}

function matchesCompletion(value: unknown, expected: { transferId: string; attemptId: string }): boolean {
  if (!isRecord(value)) return false;
  assertOnlyKeys(value, ['transferId', 'attemptId'], 'Transfer completion');
  return value.transferId === expected.transferId && value.attemptId === expected.attemptId;
}

function validateCompletionAcknowledgement(
  value: unknown,
  expected: CompletionFrame
): CompletionAcknowledgement {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer acknowledgement');
  assertOnlyKeys(value, ['transferId', 'attemptId', 'receiptToken'], 'Transfer acknowledgement');
  if (value.transferId !== expected.transferId || value.attemptId !== expected.attemptId) {
    throw new P2PError('INTEGRITY_FAILED', 'Receiver acknowledged a different transfer attempt');
  }
  return {
    transferId: expected.transferId,
    attemptId: expected.attemptId,
    receiptToken: validateLaneToken(value.receiptToken)
  };
}

function matchesCompletionAcknowledgement(
  value: unknown,
  expected: CompletionAcknowledgement
): boolean {
  if (!isRecord(value)) return false;
  assertOnlyKeys(value, ['transferId', 'attemptId', 'receiptToken'], 'Transfer receipt');
  return value.transferId === expected.transferId &&
    value.attemptId === expected.attemptId &&
    value.receiptToken === expected.receiptToken;
}

function assertSameManifest(expected: FileManifest, actual: FileManifest): void {
  if (
    expected.transferId !== actual.transferId ||
    expected.digest !== actual.digest ||
    expected.size !== actual.size ||
    expected.chunkSize !== actual.chunkSize ||
    expected.chunkCount !== actual.chunkCount ||
    expected.name !== actual.name ||
    !metadataEqual(expected.metadata, actual.metadata)
  ) {
    throw new P2PError('INTEGRITY_FAILED', 'Shared file changed while resuming a download');
  }
}

function metadataEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left instanceof Uint8Array || right instanceof Uint8Array) {
    if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.byteLength !== right.byteLength) return false;
    for (let index = 0; index < left.byteLength; index += 1) {
      if (left[index] !== right[index]) return false;
    }
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => metadataEqual(item, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every((key, index) => key === rightKeys[index] && metadataEqual(left[key], right[key]));
}

function manifestFingerprint(manifest: FileManifest): string {
  const hash = createHash('sha256');
  hashField(hash, 'transfer', manifest.transferId);
  hashField(hash, 'name', manifest.name);
  hashField(hash, 'size', String(manifest.size));
  hashField(hash, 'digest', manifest.digest);
  hashField(hash, 'chunk-size', String(manifest.chunkSize));
  hashField(hash, 'chunk-count', String(manifest.chunkCount));
  hashMetadata(hash, manifest.metadata);
  return hash.digest('base64url');
}

function receiverPrincipalBinding(principal: SessionPrincipal): string {
  return JSON.stringify([
    principal.id,
    principal.subject,
    principal.issuer ?? null,
    principal.clientId ?? null,
    principal.tenantId ?? null
  ]);
}

function receiverOperationKey(principal: SessionPrincipal, transferId: string): string {
  return JSON.stringify([receiverPrincipalBinding(principal), transferId]);
}

function hashMetadata(hash: Hash, value: unknown): void {
  if (value === undefined) {
    hash.update('u');
    return;
  }
  if (value === null) {
    hash.update('n');
    return;
  }
  if (typeof value === 'boolean') {
    hash.update(value ? 't' : 'f');
    return;
  }
  if (typeof value === 'number') {
    hashField(hash, 'd', Object.is(value, -0) ? '-0' : String(value));
    return;
  }
  if (typeof value === 'string') {
    hashField(hash, 's', value);
    return;
  }
  if (value instanceof Uint8Array) {
    hash.update('b');
    hash.update(String(value.byteLength));
    hash.update(':');
    hash.update(value);
    return;
  }
  if (Array.isArray(value)) {
    hash.update('a');
    hash.update(String(value.length));
    hash.update(':');
    for (const item of value) hashMetadata(hash, item);
    return;
  }
  if (!isRecord(value)) throw new P2PError('INTERNAL', 'Validated file metadata changed shape');
  const keys = Object.keys(value).sort();
  hash.update('o');
  hash.update(String(keys.length));
  hash.update(':');
  for (const key of keys) {
    hashField(hash, 'k', key);
    hashMetadata(hash, value[key]);
  }
}

function hashField(hash: Hash, tag: string, value: string): void {
  hash.update(tag);
  hash.update(String(Buffer.byteLength(value)));
  hash.update(':');
  hash.update(value);
}

function publicRejection(cause: unknown): { readonly code: string; readonly reason: string } {
  const error = asP2PError(cause);
  const reason = error.code === 'RESOURCE_LIMIT'
    ? 'Transfer exceeds receiver resource policy'
    : error.code === 'OUTCOME_UNKNOWN'
      ? 'Transfer outcome is indeterminate'
    : error.code === 'INCOMPATIBLE_PROTOCOL'
      ? 'Transfer protocol is incompatible'
      : 'Transfer rejected';
  return { code: error.code, reason };
}

function remoteRejection(value: unknown): P2PError {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer rejection');
  assertOnlyKeys(value, ['code', 'reason'], 'Transfer rejection');
  if (
    typeof value.code !== 'string' ||
    value.code.length === 0 ||
    value.code.length > 64 ||
    typeof value.reason !== 'string'
  ) {
    throw new P2PError('INVALID_FRAME', 'Invalid transfer rejection code');
  }
  const reason = safeRejectionReason(value.reason, 'Transfer rejected');
  return value.code === 'OUTCOME_UNKNOWN'
    ? new P2PError('OUTCOME_UNKNOWN', reason)
    : new P2PError('REJECTED', reason);
}

function safeRejectionReason(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const output = sanitizeBoundedDisplayText(value, 256, fallback);
  return output.trim().length > 0 ? output : fallback;
}

function validateOpaqueId(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(value)) throw new P2PError('INVALID_FRAME', `Invalid ${label}`);
  return value;
}

function validateLaneToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer lane token');
  return value;
}

function randomOpaqueId(): string {
  return randomBytes(16).toString('base64url');
}

function randomTransferId(): string {
  return `r${randomOpaqueId()}`;
}

function isFileMetadataSchema<TMetadata>(value: unknown): value is FileMetadataSchema<TMetadata> {
  if (!isRecord(value) || !isRecord(value['~standard'])) return false;
  const standard = value['~standard'];
  return standard.version === 1 &&
    typeof standard.vendor === 'string' &&
    standard.vendor.length > 0 &&
    typeof standard.validate === 'function';
}

function isFileDestination<TMetadata>(value: unknown): value is FileDestination<TMetadata> {
  return typeof value === 'object' && value !== null &&
    'prepare' in value && typeof value.prepare === 'function' &&
    'writeChunk' in value && typeof value.writeChunk === 'function' &&
    'finalize' in value && typeof value.finalize === 'function' &&
    'abort' in value && typeof value.abort === 'function';
}

function sourceWithMetadata<TMetadata>(
  source: FileSource<TMetadata> | PreparedFileSource<TMetadata>,
  metadata: TMetadata
): FileSource<TMetadata> {
  return Object.freeze({
    name: source.name,
    size: source.size,
    metadata,
    readChunk: (index: number, chunkSize: number, signal?: AbortSignal) =>
      source.readChunk(index, chunkSize, signal)
  });
}

async function prepareFileSource<TMetadata>(
  source: FileSource<TMetadata>,
  signal: AbortSignal
): Promise<PreparedFileSource<TMetadata>> {
  throwIfCancelled(signal);
  if (source.prepare) {
    const candidate: unknown = await source.prepare(signal);
    if (!isPreparedFileSource<TMetadata>(candidate)) {
      const operationFailure = new P2PError('INTERNAL', 'File source returned an invalid prepared lifecycle');
      if (
        typeof candidate === 'object' &&
        candidate !== null &&
        'close' in candidate &&
        typeof candidate.close === 'function'
      ) {
        try {
          await Promise.resolve(candidate.close.call(candidate));
        } catch (cause) {
          throw preparedSourceCleanupFailed(
            operationFailure,
            new P2PError('INTERNAL', 'Prepared file source failed to close', { cause })
          );
        }
      }
      throw operationFailure;
    }
    const prepared = candidate;
    if (signal.aborted) {
      const operationFailure = signalError(signal);
      try {
        await closePreparedFileSource(prepared);
      } catch (cleanupFailure) {
        throw preparedSourceCleanupFailed(operationFailure, cleanupFailure);
      }
      throw operationFailure;
    }
    return prepared;
  }
  return Object.freeze({
    name: source.name,
    size: source.size,
    ...(source.metadata !== undefined ? { metadata: source.metadata } : {}),
    readChunk: (index: number, chunkSize: number, readSignal?: AbortSignal) =>
      source.readChunk(index, chunkSize, readSignal),
    close: async () => undefined
  });
}

async function closePreparedFileSource(source: PreparedFileSource): Promise<void> {
  try {
    await source.close();
  } catch (cause) {
    throw new P2PError('INTERNAL', 'Prepared file source failed to close', { cause });
  }
}

async function settlePreparedFileSource<T>(
  source: PreparedFileSource,
  operation: () => Promise<T>
): Promise<T> {
  const outcome = await Promise.resolve().then(operation).then(
    (value) => ({ status: 'fulfilled' as const, value }),
    (cause: unknown) => ({ status: 'rejected' as const, cause })
  );
  let cleanupFailure: unknown;
  try {
    await closePreparedFileSource(source);
  } catch (cause) {
    cleanupFailure = cause;
  }
  if (outcome.status === 'fulfilled') {
    // The receiver has already acknowledged the operation. Reclassifying that
    // known result as a transfer failure would invite an unsafe duplicate.
    return outcome.value;
  }
  if (cleanupFailure !== undefined) {
    throw preparedSourceCleanupFailed(outcome.cause, cleanupFailure);
  }
  throw outcome.cause;
}

function ignoreFileWork(work: Promise<unknown>): void {
  // Standalone managers do not own node admission. Managed outbound streams
  // retain their own leases; an embedding node supplies a real tracker for
  // manually admitted inbound control streams.
  void work;
}

function physicalClosureProof(connection: QuicConnection): Promise<void> {
  return Promise.resolve().then(() => connection.closed()).then(
    () => undefined,
    // A rejected lifecycle observation is not proof that the native stream is
    // terminal. Conservatively retain admission rather than report quiescence.
    () => new Promise<void>(() => undefined)
  );
}

function isPreparedFileSource<TMetadata>(value: unknown): value is PreparedFileSource<TMetadata> {
  return typeof value === 'object' && value !== null &&
    'name' in value && typeof value.name === 'string' &&
    'size' in value && typeof value.size === 'number' &&
    'readChunk' in value && typeof value.readChunk === 'function' &&
    'close' in value && typeof value.close === 'function';
}

async function boundedOperation<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  message: string,
  signal: AbortSignal | undefined,
  fallback: 'DISCONNECTED' | 'INTERNAL',
  transportOperation = false,
  attempt?: FileConnectionAttempt
): Promise<T> {
  throwIfCancelled(signal);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let detachAbort = (): void => undefined;
  const task = Promise.resolve().then(operation).catch((cause: unknown) => {
    const error = asP2PError(cause, fallback);
    if (transportOperation && error.code === 'DISCONNECTED' && attempt) {
      throw attempt.recordTransportLoss(error);
    }
    throw error;
  });
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new P2PError('TIMEOUT', message)), timeoutMs);
    timer.unref?.();
  });
  const aborted = new Promise<never>((_, reject) => {
    detachAbort = onAbort(signal, () => reject(signal ? signalError(signal) : cancelledError()));
  });
  try {
    return await Promise.race([task, timeout, aborted]);
  } finally {
    if (timer) clearTimeout(timer);
    detachAbort();
  }
}

async function cancellableOperation<T>(
  operation: () => Promise<T>,
  signal: AbortSignal | undefined,
  fallback: 'DISCONNECTED' | 'INTERNAL',
  transportOperation = false,
  attempt?: FileConnectionAttempt
): Promise<T> {
  throwIfCancelled(signal);
  let detachAbort = (): void => undefined;
  const task = Promise.resolve().then(operation).catch((cause: unknown) => {
    const error = asP2PError(cause, fallback);
    if (transportOperation && error.code === 'DISCONNECTED' && attempt) {
      throw attempt.recordTransportLoss(error);
    }
    throw error;
  });
  const aborted = new Promise<never>((_, reject) => {
    detachAbort = onAbort(signal, () => reject(signal ? signalError(signal) : cancelledError()));
  });
  try {
    return await Promise.race([task, aborted]);
  } finally {
    detachAbort();
  }
}

async function cooperativeOperation<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  message: string,
  signal: AbortSignal | undefined
): Promise<T> {
  throwIfCancelled(signal);
  const linked = linkedController(signal);
  const timeoutError = new P2PError('TIMEOUT', message);
  let detachAbort = (): void => undefined;
  const task = Promise.resolve()
    .then(() => operation(linked.controller.signal))
    .then(
      (value) => ({ kind: 'result' as const, value }),
      (cause: unknown) => ({ kind: 'error' as const, error: asP2PError(cause, 'INTERNAL') })
    );
  const aborted = new Promise<{ kind: 'aborted' }>((resolve) => {
    detachAbort = onAbort(linked.controller.signal, () => resolve({ kind: 'aborted' }));
  });
  const timer = setTimeout(() => linked.controller.abort(timeoutError), timeoutMs);
  timer.unref?.();
  try {
    const outcome = await Promise.race([task, aborted]);
    if (outcome.kind === 'result') return outcome.value;
    if (outcome.kind === 'error') throw outcome.error;

    // File callbacks are side-effecting. Once cancelled, wait for them to
    // observe the cooperative signal and settle before returning an error so
    // they cannot publish a destination after the caller sees TIMEOUT.
    const settled = await task;
    // A callback may have crossed an uninterruptible atomic commit just before
    // cancellation. Report that successful commit as success; never report a
    // timeout and then allow its externally visible publication to appear.
    if (settled.kind === 'result') return settled.value;
    throw signalError(linked.controller.signal);
  } finally {
    clearTimeout(timer);
    detachAbort();
    linked.dispose();
  }
}

async function withDeadline<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new P2PError('TIMEOUT', message)), timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
