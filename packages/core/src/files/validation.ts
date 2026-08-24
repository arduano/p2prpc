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
  maxFileSize: 16 * 1024 * 1024 * 1024,
  maxChunkCount: 65_536,
  maxNameBytes: 255,
  maxMetadataBytes: 64 * 1024,
  maxTransferIdBytes: 128,
  maxMissingRanges: 16 * 1024
};

const textEncoder = new TextEncoder();
const TRANSFER_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]*$/;
const DIGEST_PATTERN = /^[0-9a-f]{64}$/;
const validatedManifestMetadata = new WeakMap<object, unknown>();

export function resolveFileTransferLimits(limits: Partial<FileTransferLimits> = {}): FileTransferLimits {
  if (!isRecord(limits)) throw new P2PError('INVALID_FRAME', 'File transfer limits must be an object');
  assertOnlyKeys(limits, [
    'chunkSize',
    'maxChunkSize',
    'lanes',
    'maxLanes',
    'maxTransfers',
    'maxQueuedTransfers',
    'maxFileSize',
    'maxChunkCount',
    'maxNameBytes',
    'maxMetadataBytes',
    'maxTransferIdBytes',
    'maxMissingRanges'
  ], 'File transfer limits');
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
  assertManifestKeys(value);
  for (const required of ['transferId', 'name', 'size', 'digest', 'chunkSize', 'chunkCount']) {
    if (!Object.hasOwn(value, required)) throw new P2PError('INVALID_FRAME', `File manifest is missing ${required}`);
  }
  const transferId = validateTransferId(dataProperty(value, 'transferId'), limits);
  const name = validateFileName(dataProperty(value, 'name'), limits);
  const rawSize = dataProperty(value, 'size');
  if (!Number.isSafeInteger(rawSize) || (rawSize as number) < 0 || (rawSize as number) > limits.maxFileSize) {
    throw new P2PError('RESOURCE_LIMIT', `File size exceeds the configured limit of ${limits.maxFileSize} bytes`);
  }
  const size = rawSize as number;
  const digest = validateDigest(dataProperty(value, 'digest'), 'file digest');
  const chunkSize = validateChunkSize(dataProperty(value, 'chunkSize') as number, limits.maxChunkSize);
  const rawChunkCount = dataProperty(value, 'chunkCount');
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
  const rawMetadata = validatedManifestMetadata.has(value)
    ? validatedManifestMetadata.get(value)
    : Object.hasOwn(value, 'metadata') ? dataProperty(value, 'metadata') : undefined;
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
    validatedManifestMetadata.set(manifest, metadata);
  }
  return Object.freeze(manifest);
}

export function validateMetadata(value: unknown, maxBytes: number): void {
  void cloneValidatedMetadata(value, maxBytes);
}

/** Materialize the private canonical manifest snapshot as accessor-free wire data. */
export function manifestWireValue<TMetadata>(manifest: FileManifest<TMetadata>): Record<string, unknown> {
  const value: Record<string, unknown> = {
    transferId: manifest.transferId,
    name: manifest.name,
    size: manifest.size,
    digest: manifest.digest,
    chunkSize: manifest.chunkSize,
    chunkCount: manifest.chunkCount
  };
  if (validatedManifestMetadata.has(manifest)) {
    value.metadata = cloneAndFreezePlainData(validatedManifestMetadata.get(manifest));
  } else if (Object.hasOwn(manifest, 'metadata')) {
    throw new P2PError('INTERNAL', 'Manifest metadata lacks a private validated snapshot');
  }
  return Object.freeze(value);
}

/** Returns a detached canonical snapshot of validated, message-packable metadata. */
export function cloneValidatedMetadata<T>(value: T, maxBytes: number): T {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid file metadata byte limit');
  }
  const snapshot = clonePlainData(
    value,
    0,
    { items: 0, estimatedBytes: 0, maxBytes },
    new WeakSet<object>()
  ) as T;
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
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function assertOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string
): void {
  const allowedKeys = new Set(allowed);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !allowedKeys.has(key)) {
      throw new P2PError('INVALID_FRAME', `${label} contains an unknown field`);
    }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new P2PError('INVALID_FRAME', `${label} contains an unsafe field`);
    }
  }
}

function assertManifestKeys(value: Record<string, unknown>): void {
  const allowed = new Set(['transferId', 'name', 'size', 'digest', 'chunkSize', 'chunkCount', 'metadata']);
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowed.has(key)) {
      throw new P2PError('INVALID_FRAME', 'File manifest contains an unknown field');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable) {
      throw new P2PError('INVALID_FRAME', 'File manifest contains an unsafe field');
    }
    if (Object.hasOwn(descriptor, 'value')) continue;
    if (
      key !== 'metadata' ||
      !validatedManifestMetadata.has(value) ||
      typeof descriptor.get !== 'function' ||
      descriptor.set !== undefined
    ) {
      throw new P2PError('INVALID_FRAME', 'File manifest contains an unsafe field');
    }
  }
}

function clonePlainData(
  value: unknown,
  depth: number,
  budget: { items: number; estimatedBytes: number; readonly maxBytes: number },
  seen: WeakSet<object>
): unknown {
  consumeMetadataBudget(budget, 1, 0);
  if (value === null || typeof value === 'boolean') {
    consumeMetadataBudget(budget, 0, 1);
    return value;
  }
  if (typeof value === 'string') {
    consumeMetadataBudget(budget, 0, encodedMetadataLength(value));
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new P2PError('INVALID_FRAME', 'File metadata numbers must be finite and wire-stable');
    }
    consumeMetadataBudget(budget, 0, 9);
    return value;
  }
  if (value instanceof Uint8Array) {
    if (
      Object.getPrototypeOf(value) !== Uint8Array.prototype &&
      Object.getPrototypeOf(value) !== Buffer.prototype
    ) throw new P2PError('INVALID_FRAME', 'File metadata must contain only plain byte arrays');
    if (
      Object.getOwnPropertyDescriptor(value, 'byteLength') ||
      Object.getOwnPropertyDescriptor(value, 'constructor') ||
      Object.getOwnPropertyDescriptor(value, Symbol.iterator)
    ) throw new P2PError('INVALID_FRAME', 'File metadata byte arrays must be accessor-free');
    consumeMetadataBudget(budget, 0, checkedMetadataLength(value.byteLength));
    return new Uint8Array(value);
  }
  if (typeof value !== 'object') throw new P2PError('INVALID_FRAME', 'File metadata contains an unsupported value');
  if (depth >= 16) throw new P2PError('RESOURCE_LIMIT', 'File metadata nesting is too deep');
  if (seen.has(value)) throw new P2PError('INVALID_FRAME', 'File metadata must not contain cycles');
  seen.add(value);
  const isArray = Array.isArray(value);
  if (!isArray && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
    throw new P2PError('INVALID_FRAME', 'File metadata must contain only plain data');
  }
  consumeMetadataBudget(budget, 0, 5);
  if (isArray) {
    if (
      value.length > 4096 - budget.items ||
      value.length > budget.maxBytes - budget.estimatedBytes
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'File metadata array exceeds configured limits');
    }
    const clone: unknown[] = [];
    let elements = 0;
    for (const key of Reflect.ownKeys(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw new P2PError('INVALID_FRAME', 'File metadata arrays must be dense and accessor-free');
      }
      if (key === 'length') continue;
      if (
        typeof key !== 'string' ||
        !descriptor.enumerable ||
        !/^(?:0|[1-9]\d*)$/.test(key) ||
        Number(key) >= value.length
      ) {
        throw new P2PError('INVALID_FRAME', 'File metadata arrays must not contain extra properties');
      }
      elements += 1;
    }
    if (elements !== value.length) {
      throw new P2PError('INVALID_FRAME', 'File metadata arrays must be dense and accessor-free');
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw new P2PError('INVALID_FRAME', 'File metadata arrays must be dense and accessor-free');
      }
      clone.push(clonePlainData(descriptor.value, depth + 1, budget, seen));
    }
    seen.delete(value);
    return clone;
  }

  const clone = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      throw new P2PError('INVALID_FRAME', 'File metadata contains an invalid key');
    }
    const keyBytes = Buffer.byteLength(key);
    if (
      keyBytes > 1024 ||
      hasControlCharacters(key) ||
      key === '__proto__' ||
      key === 'constructor' ||
      key === 'prototype'
    ) {
      throw new P2PError('INVALID_FRAME', 'File metadata contains an invalid key');
    }
    consumeMetadataBudget(budget, 1, checkedMetadataLength(keyBytes));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new P2PError('INVALID_FRAME', 'File metadata objects must be accessor-free');
    }
    Object.defineProperty(clone, key, {
      value: clonePlainData(descriptor.value, depth + 1, budget, seen),
      enumerable: true,
      writable: true,
      configurable: true
    });
  }
  seen.delete(value);
  return clone;
}

function dataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
    throw new P2PError('INVALID_FRAME', 'File manifest fields must be enumerable data properties');
  }
  return descriptor.value;
}

function consumeMetadataBudget(
  budget: { items: number; estimatedBytes: number; readonly maxBytes: number },
  items: number,
  bytes: number
): void {
  if (
    !Number.isSafeInteger(items) ||
    !Number.isSafeInteger(bytes) ||
    budget.items + items > 4096
  ) {
    throw new P2PError('RESOURCE_LIMIT', 'File metadata contains too many values');
  }
  if (bytes > budget.maxBytes - budget.estimatedBytes) {
    throw new P2PError('RESOURCE_LIMIT', `File metadata exceeds ${budget.maxBytes} bytes`);
  }
  budget.items += items;
  budget.estimatedBytes += bytes;
}

function encodedMetadataLength(value: string): number {
  return checkedMetadataLength(Buffer.byteLength(value));
}

function checkedMetadataLength(length: number): number {
  if (!Number.isSafeInteger(length) || length < 0 || length > Number.MAX_SAFE_INTEGER - 5) {
    throw new P2PError('RESOURCE_LIMIT', 'File metadata length is invalid');
  }
  return length + 5;
}

function cloneAndFreezePlainData(value: unknown): unknown {
  if (value instanceof Uint8Array) return new Uint8Array(value);
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
