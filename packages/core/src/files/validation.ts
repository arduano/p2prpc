import { pack } from 'msgpackr';
import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';
import type { FileManifest } from './types.js';

export interface FileTransferLimits {
  readonly chunkSize: number;
  /** Maximum peer-negotiated chunk size and per-lane chunk allocation. */
  readonly maxChunkSize: number;
  readonly lanes: number;
  readonly maxLanes: number;
  readonly maxTransfers: number;
  readonly maxQueuedTransfers: number;
  readonly maxFileSize: number;
  readonly maxChunkCount: number;
  readonly maxNameBytes: number;
  readonly maxMetadataBytes: number;
  readonly maxTransferIdBytes: number;
  readonly maxMissingRanges: number;
}

export const MIN_CHUNK_SIZE = 64 * 1024;
export const MAX_CHUNK_SIZE = 16 * 1024 * 1024;

export const DEFAULT_FILE_TRANSFER_LIMITS: FileTransferLimits = {
  chunkSize: 1024 * 1024,
  maxChunkSize: 4 * 1024 * 1024,
  lanes: 4,
  maxLanes: 16,
  maxTransfers: 4,
  maxQueuedTransfers: 16,
  maxFileSize: 1024 * 1024 * 1024 * 1024,
  maxChunkCount: 256 * 1024,
  maxNameBytes: 255,
  maxMetadataBytes: 64 * 1024,
  maxTransferIdBytes: 128,
  maxMissingRanges: 16 * 1024
};

const textEncoder = new TextEncoder();
const TRANSFER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;

export function resolveFileTransferLimits(limits: Partial<FileTransferLimits> = {}): FileTransferLimits {
  const resolved = { ...DEFAULT_FILE_TRANSFER_LIMITS, ...limits };
  validateChunkSize(resolved.maxChunkSize);
  validateChunkSize(resolved.chunkSize, resolved.maxChunkSize);
  positiveInteger(resolved.lanes, 'default lane count', 64);
  positiveInteger(resolved.maxLanes, 'maximum lane count', 64);
  positiveInteger(resolved.maxTransfers, 'maximum transfer count', 1024);
  nonNegativeInteger(resolved.maxQueuedTransfers, 'maximum queued transfer count', 100_000);
  positiveInteger(resolved.maxFileSize, 'maximum file size', Number.MAX_SAFE_INTEGER);
  positiveInteger(resolved.maxChunkCount, 'maximum chunk count', 16 * 1024 * 1024);
  positiveInteger(resolved.maxNameBytes, 'maximum file name size', 4096);
  nonNegativeInteger(resolved.maxMetadataBytes, 'maximum metadata size', 16 * 1024 * 1024);
  positiveInteger(resolved.maxTransferIdBytes, 'maximum transfer ID size', 1024);
  positiveInteger(resolved.maxMissingRanges, 'maximum missing range count', resolved.maxChunkCount);
  if (resolved.lanes > resolved.maxLanes) {
    throw new P2PError('RESOURCE_LIMIT', 'Default file lane count exceeds the maximum lane count');
  }
  return resolved;
}

export function validateChunkSize(value: number, maximum = MAX_CHUNK_SIZE): number {
  if (!Number.isSafeInteger(value) || value < MIN_CHUNK_SIZE || value > MAX_CHUNK_SIZE || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `Chunk size must be between 64 KiB and ${maximum} bytes`);
  }
  return value;
}

export function validateTransferId(value: unknown, limits: FileTransferLimits): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    textEncoder.encode(value).byteLength > limits.maxTransferIdBytes ||
    !TRANSFER_ID_PATTERN.test(value)
  ) {
    throw new P2PError('INVALID_FRAME', 'Invalid transfer ID');
  }
  return value;
}

export function validateFileName(value: unknown, limits: FileTransferLimits): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    hasControlCharacters(value) ||
    textEncoder.encode(value).byteLength > limits.maxNameBytes
  ) {
    throw new P2PError('INVALID_FRAME', 'Invalid untrusted file name');
  }
  return value;
}

export function validateDigest(value: unknown, label = 'digest'): string {
  if (typeof value !== 'string' || !DIGEST_PATTERN.test(value)) {
    throw new P2PError('INVALID_FRAME', `Invalid ${label}`);
  }
  return value;
}

export function validateManifest<TMetadata>(value: unknown, limits: FileTransferLimits): FileManifest<TMetadata> {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', 'File manifest must be an object');
  const transferId = validateTransferId(value.transferId, limits);
  const name = validateFileName(value.name, limits);
  const rawSize = value.size;
  if (!Number.isSafeInteger(rawSize) || (rawSize as number) < 0 || (rawSize as number) > limits.maxFileSize) {
    throw new P2PError('RESOURCE_LIMIT', `File size exceeds the configured limit of ${limits.maxFileSize} bytes`);
  }
  const size = rawSize as number;
  const digest = validateDigest(value.digest, 'file digest');
  const chunkSize = validateChunkSize(value.chunkSize as number, limits.maxChunkSize);
  const rawChunkCount = value.chunkCount;
  if (!Number.isSafeInteger(rawChunkCount) || (rawChunkCount as number) < 0) {
    throw new P2PError('INVALID_FRAME', 'Invalid file chunk count');
  }
  const chunkCount = rawChunkCount as number;
  if (chunkCount > limits.maxChunkCount) {
    throw new P2PError('RESOURCE_LIMIT', `File chunk count exceeds the configured limit of ${limits.maxChunkCount}`);
  }
  const expectedChunkCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
  if (chunkCount !== expectedChunkCount) {
    throw new P2PError('INVALID_FRAME', 'Manifest chunk count does not match file size');
  }
  const rawMetadata = 'metadata' in value ? value.metadata : undefined;
  const metadata = rawMetadata !== undefined
    ? cloneValidatedMetadata<TMetadata>(rawMetadata as TMetadata, limits.maxMetadataBytes)
    : undefined;
  const manifest: FileManifest<TMetadata> = { transferId, name, size, digest, chunkSize, chunkCount };
  if (metadata !== undefined) {
    // A fresh frozen view is returned on every access. This keeps the
    // canonical validated snapshot private even for mutable Uint8Array values.
    Object.defineProperty(manifest, 'metadata', {
      enumerable: true,
      get: () => cloneAndFreezePlainData(metadata) as TMetadata
    });
  }
  return Object.freeze(manifest);
}

export function validateMetadata(value: unknown, maxBytes: number): void {
  void cloneValidatedMetadata(value, maxBytes);
}

/** Returns a detached canonical snapshot of validated, message-packable metadata. */
export function cloneValidatedMetadata<T>(value: T, maxBytes: number): T {
  const snapshot = clonePlainData(value, 0, { items: 0 }, new WeakSet<object>()) as T;
  let bytes: number;
  try {
    bytes = pack(snapshot).byteLength;
  } catch (cause) {
    throw new P2PError('INVALID_FRAME', 'File metadata is not serializable', { cause });
  }
  if (bytes > maxBytes) throw new P2PError('RESOURCE_LIMIT', `File metadata exceeds ${maxBytes} bytes`);
  return snapshot;
}

export function expectedChunkSize(manifest: FileManifest, index: number): number {
  if (!Number.isSafeInteger(index) || index < 0 || index >= manifest.chunkCount) {
    throw new P2PError('INVALID_FRAME', `Chunk index ${String(index)} is out of range`);
  }
  return Math.min(manifest.chunkSize, manifest.size - index * manifest.chunkSize);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function clonePlainData(
  value: unknown,
  depth: number,
  counter: { items: number },
  seen: WeakSet<object>
): unknown {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new P2PError('INVALID_FRAME', 'File metadata numbers must be finite');
    return value;
  }
  if (value instanceof Uint8Array) return value.slice();
  if (typeof value !== 'object') throw new P2PError('INVALID_FRAME', 'File metadata contains an unsupported value');
  if (depth >= 16) throw new P2PError('RESOURCE_LIMIT', 'File metadata nesting is too deep');
  if (seen.has(value)) throw new P2PError('INVALID_FRAME', 'File metadata must not contain cycles');
  seen.add(value);
  const isArray = Array.isArray(value);
  if (!isArray && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new P2PError('INVALID_FRAME', 'File metadata must contain only plain data');
  }
  const entries: Array<readonly [string, unknown]> = isArray
    ? Array.from({ length: value.length }, (_, index) => [String(index), value[index]] as const)
    : Object.entries(value as Record<string, unknown>);
  counter.items += entries.length;
  if (counter.items > 4096) throw new P2PError('RESOURCE_LIMIT', 'File metadata contains too many values');
  const clone: unknown[] | Record<string, unknown> = isArray ? [] : Object.create(null) as Record<string, unknown>;
  for (const [key, item] of entries) {
    if (textEncoder.encode(key).byteLength > 1024 || hasControlCharacters(key)) {
      throw new P2PError('INVALID_FRAME', 'File metadata contains an invalid key');
    }
    const cloned = clonePlainData(item, depth + 1, counter, seen);
    if (isArray) (clone as unknown[]).push(cloned);
    else Object.defineProperty(clone, key, { value: cloned, enumerable: true, writable: true, configurable: true });
  }
  seen.delete(value);
  return clone;
}

function cloneAndFreezePlainData(value: unknown): unknown {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return Object.freeze(value.map(cloneAndFreezePlainData));
  if (value !== null && typeof value === 'object') {
    const clone = Object.create(null) as Record<string, unknown>;
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      Object.defineProperty(clone, key, {
        value: cloneAndFreezePlainData(item),
        enumerable: true,
        writable: false,
        configurable: false
      });
    }
    return Object.freeze(clone);
  }
  return value;
}

export function hasControlCharacters(value: string): boolean {
  return containsUnsafeDisplayCharacters(value);
}

function positiveInteger(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `Invalid ${label}: ${String(value)}`);
  }
}

function nonNegativeInteger(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `Invalid ${label}: ${String(value)}`);
  }
}
