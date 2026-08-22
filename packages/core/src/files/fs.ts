import { Blake3Hasher, blake3 } from '@napi-rs/blake-hash';
import { randomUUID } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { basename, dirname } from 'node:path';
import { link, lstat, open, rename, unlink, type FileHandle } from 'node:fs/promises';
import { P2PError } from '../errors.js';
import type { FileDestination, FileManifest, FileSource } from './types.js';
import {
  DEFAULT_FILE_TRANSFER_LIMITS,
  cloneValidatedMetadata,
  expectedChunkSize,
  resolveFileTransferLimits,
  validateChunkSize,
  validateDigest,
  validateFileName,
  validateManifest,
  validateTransferId,
  type FileTransferLimits
} from './validation.js';

const NO_FOLLOW = constants.O_NOFOLLOW ?? 0;
const MAX_RESUME_STATE_BYTES = 32 * 1024 * 1024;
const FILE_IO_SEGMENT_BYTES = 64 * 1024;

interface FileIdentity {
  readonly dev: bigint;
  readonly ino: bigint;
  readonly size: bigint;
  readonly mtimeNs: bigint;
  readonly ctimeNs: bigint;
}

export async function fileSource<TMetadata = unknown>(path: string, metadata?: TMetadata): Promise<FileSource<TMetadata>> {
  const initialHandle = await openSecure(path, constants.O_RDONLY, 'source');
  let initialStats: BigIntStats;
  try {
    initialStats = await initialHandle.stat({ bigint: true });
    if (!initialStats.isFile()) throw new P2PError('NOT_FOUND', 'File source is not a regular file');
  } finally {
    await initialHandle.close();
  }
  if (initialStats.size > BigInt(Number.MAX_SAFE_INTEGER)) throw new P2PError('RESOURCE_LIMIT', 'File source is too large');
  const identity = fileIdentity(initialStats);
  const name = basename(path);
  validateFileName(name, DEFAULT_FILE_TRANSFER_LIMITS);
  const size = Number(initialStats.size);
  const source: FileSource<TMetadata> = {
    name,
    size,
    async readChunk(index, chunkSize, signal) {
      throwIfCancelled(signal);
      validateChunkSize(chunkSize);
      const chunkCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
      if (!Number.isSafeInteger(index) || index < 0 || index >= chunkCount) {
        throw new P2PError('INVALID_FRAME', `Chunk ${String(index)} is out of range`);
      }
      const offset = index * chunkSize;
      const length = Math.min(chunkSize, size - offset);
      const handle = await openSecure(path, constants.O_RDONLY, 'source');
      try {
        throwIfCancelled(signal);
        assertStableSource(await handle.stat({ bigint: true }), identity);
        throwIfCancelled(signal);
        const data = Buffer.allocUnsafe(length);
        await readFully(handle, data, offset, signal);
        throwIfCancelled(signal);
        assertStableSource(await handle.stat({ bigint: true }), identity);
        throwIfCancelled(signal);
        return data;
      } finally {
        await handle.close();
      }
    }
  };
  if (metadata !== undefined) Object.defineProperty(source, 'metadata', { value: metadata, enumerable: true });
  return source;
}

interface ResumeState {
  readonly version: 1;
  readonly digest: string;
  readonly size: number;
  readonly chunkSize: number;
  readonly chunks: Array<readonly [index: number, digest: string]>;
}

export interface FileDestinationOptions {
  readonly overwrite?: boolean;
  /** Sync file data and metadata before publishing. Defaults to true. */
  readonly durable?: boolean;
  /**
   * Maximum accepted manifest chunk size. Defaults to 4 MiB. Set this to the
   * node's maxFileChunkSize when intentionally accepting larger chunks.
   */
  readonly maxChunkSize?: number;
}

export function fileDestination<TMetadata = unknown>(
  path: string,
  options: FileDestinationOptions = {}
): FileDestination<TMetadata> {
  if (options.overwrite !== undefined && typeof options.overwrite !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'File destination overwrite must be a boolean');
  }
  if (options.durable !== undefined && typeof options.durable !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'File destination durable must be a boolean');
  }
  const maxChunkSize = validateChunkSize(options.maxChunkSize ?? DEFAULT_FILE_TRANSFER_LIMITS.maxChunkSize);
  const destinationLimits: FileTransferLimits = { ...DEFAULT_FILE_TRANSFER_LIMITS, maxChunkSize };
  const partialPath = `${path}.p2prpc.part`;
  const statePath = `${path}.p2prpc.state.json`;
  const lockPath = `${path}.p2prpc.lock`;
  const completed = new Map<number, string>();
  let partialHandle: FileHandle | undefined;
  let partialIdentity: FileIdentity | undefined;
  let lockHandle: FileHandle | undefined;
  let lockIdentity: FileIdentity | undefined;
  let preparedKey: string | undefined;
  let writesSinceFlush = 0;
  let persistChain = Promise.resolve();
  let finished = false;

  const enqueuePersist = (manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<void> => {
    const task = persistChain.then(() => persistState(manifest, signal));
    persistChain = task.catch(() => undefined);
    return task;
  };

  const persistState = async (manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<void> => {
    throwIfCancelled(signal);
    requirePrepared(manifest);
    const state: ResumeState = {
      version: 1,
      digest: manifest.digest,
      size: manifest.size,
      chunkSize: manifest.chunkSize,
      chunks: [...completed.entries()].sort(([left], [right]) => left - right)
    };
    const serialized = JSON.stringify(state);
    if (Buffer.byteLength(serialized) > MAX_RESUME_STATE_BYTES) {
      throw new P2PError('RESOURCE_LIMIT', 'File resume state exceeds its maximum size');
    }
    const temporaryStatePath = `${statePath}.${randomUUID()}.tmp`;
    let temporary: FileHandle | undefined;
    try {
      throwIfCancelled(signal);
      temporary = await open(
        temporaryStatePath,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
        0o600
      );
      throwIfCancelled(signal);
      await writeFully(temporary, Buffer.from(serialized), 0, signal);
      throwIfCancelled(signal);
      if (options.durable !== false) {
        await temporary.sync();
        throwIfCancelled(signal);
      }
      await temporary.close();
      temporary = undefined;
      throwIfCancelled(signal);
      await rename(temporaryStatePath, statePath);
      throwIfCancelled(signal);
      if (options.durable !== false) await syncDirectory(dirname(path), signal);
      writesSinceFlush = 0;
    } finally {
      await temporary?.close().catch(() => undefined);
      await unlink(temporaryStatePath).catch(() => undefined);
    }
  };

  const requirePrepared = (manifest: FileManifest<TMetadata>): FileHandle => {
    if (finished || !partialHandle || preparedKey !== manifestKey(manifest)) {
      throw new P2PError('INTERNAL', 'File destination is not prepared for this manifest');
    }
    return partialHandle;
  };

  const releaseLock = async (): Promise<void> => {
    const handle = lockHandle;
    let identity = lockIdentity;
    lockHandle = undefined;
    lockIdentity = undefined;
    if (handle && !identity) {
      identity = await handle.stat({ bigint: true }).then(fileIdentity, () => undefined);
    }
    await handle?.close().catch(() => undefined);
    if (identity) await unlinkIfIdentity(lockPath, identity);
  };

  return {
    async prepare(manifest, signal) {
      throwIfCancelled(signal);
      if (finished || partialHandle || lockHandle) throw new P2PError('INTERNAL', 'File destination has already been prepared');
      const validated = validateManifest<TMetadata>(manifest, destinationLimits);
      preparedKey = manifestKey(validated);
      completed.clear();
      try {
        throwIfCancelled(signal);
        lockHandle = await open(
          lockPath,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
          0o600
        );
        throwIfCancelled(signal);
        lockIdentity = fileIdentity(await lockHandle.stat({ bigint: true }));
        throwIfCancelled(signal);
      } catch (cause) {
        preparedKey = undefined;
        await releaseLock();
        if (errorCode(cause) === 'EEXIST' || errorCode(cause) === 'ELOOP') {
          throw new P2PError('REJECTED', 'Destination is already being written');
        }
        throw cause;
      }

      try {
        throwIfCancelled(signal);
        if (!options.overwrite && await pathExists(path)) {
          throw new P2PError('REJECTED', 'Destination already exists');
        }
        throwIfCancelled(signal);
        const state = await readState(statePath, manifest, signal);
        if (state) {
          partialHandle = await openSecure(partialPath, constants.O_RDWR, 'partial destination').catch(() => undefined);
          if (partialHandle) {
            throwIfCancelled(signal);
            const stats = await partialHandle.stat({ bigint: true });
            if (!stats.isFile() || stats.size !== BigInt(manifest.size)) {
              await partialHandle.close();
              partialHandle = undefined;
            } else {
              partialIdentity = fileIdentity(stats);
              await partialHandle.chmod(0o600);
              for (const [index, digest] of state.chunks) {
                throwIfCancelled(signal);
                const length = expectedChunkSize(manifest, index);
                const data = Buffer.allocUnsafe(length);
                await readFully(partialHandle, data, index * manifest.chunkSize, signal);
                if (chunkDigest(data) === digest) completed.set(index, digest);
              }
            }
          }
        }
        if (!partialHandle) {
          throwIfCancelled(signal);
          await unlink(partialPath).catch(() => undefined);
          await unlink(statePath).catch(() => undefined);
          throwIfCancelled(signal);
          partialHandle = await open(
            partialPath,
            constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW,
            0o600
          );
          throwIfCancelled(signal);
          await partialHandle.truncate(manifest.size);
          throwIfCancelled(signal);
          partialIdentity = fileIdentity(await partialHandle.stat({ bigint: true }));
        }
        throwIfCancelled(signal);
        return new Set(completed.keys());
      } catch (cause) {
        await partialHandle?.close().catch(() => undefined);
        partialHandle = undefined;
        partialIdentity = undefined;
        preparedKey = undefined;
        await releaseLock();
        throw cause;
      }
    },

    async writeChunk(manifest, index, data, signal) {
      throwIfCancelled(signal);
      const handle = requirePrepared(manifest);
      const expected = expectedChunkSize(manifest, index);
      if (data.byteLength !== expected) throw new P2PError('INVALID_FRAME', `Wrong size for chunk ${index}`);
      await writeFully(handle, data, index * manifest.chunkSize, signal);
      throwIfCancelled(signal);
      completed.set(index, chunkDigest(data));
      writesSinceFlush += 1;
      if (writesSinceFlush >= 16) await enqueuePersist(manifest, signal);
    },

    async finalize(manifest, signal) {
      throwIfCancelled(signal);
      const handle = requirePrepared(manifest);
      if (completed.size !== manifest.chunkCount) throw new P2PError('INTEGRITY_FAILED', 'File has missing chunks');
      await enqueuePersist(manifest, signal);
      await persistChain;
      throwIfCancelled(signal);
      const stats = await handle.stat({ bigint: true });
      if (!stats.isFile() || stats.size !== BigInt(manifest.size)) {
        throw new P2PError('INTEGRITY_FAILED', 'File size changed before finalization');
      }
      throwIfCancelled(signal);
      const actual = await hashHandle(handle, manifest.size, signal);
      if (actual !== manifest.digest) throw new P2PError('INTEGRITY_FAILED', 'File failed final integrity verification');
      throwIfCancelled(signal);
      if (options.durable !== false) {
        await handle.sync();
        throwIfCancelled(signal);
      }
      if (!partialIdentity || !await pathHasIdentity(partialPath, partialIdentity)) {
        throw new P2PError('INTEGRITY_FAILED', 'Partial file path changed before finalization');
      }

      // Atomic publication is the commit point. Abort is checked immediately
      // before it; once the syscall starts, finalize runs to success so callers
      // never observe TIMEOUT followed by a later published file.
      throwIfCancelled(signal);
      if (options.overwrite) {
        await rename(partialPath, path);
      } else {
        try {
          await link(partialPath, path);
        } catch (cause) {
          if (errorCode(cause) === 'EEXIST') throw new P2PError('REJECTED', 'Destination already exists');
          throw cause;
        }
        await unlink(partialPath).catch(() => undefined);
      }
      // Nothing after this point may turn a successful atomic publication into
      // an error observed by the caller.
      finished = true;
      partialHandle = undefined;
      partialIdentity = undefined;
      if (options.durable !== false) await syncDirectory(dirname(path));
      await handle.close().catch(() => undefined);
      await unlink(statePath).catch(() => undefined);
      await releaseLock();
    },

    async abort(manifest, abortOptions, signal) {
      if (finished) return;
      if (!signal?.aborted && partialHandle && preparedKey === manifestKey(manifest) && !abortOptions.discard) {
        await enqueuePersist(manifest, signal).catch(() => undefined);
        await persistChain.catch(() => undefined);
      }
      const identity = partialIdentity;
      await partialHandle?.close().catch(() => undefined);
      partialHandle = undefined;
      partialIdentity = undefined;
      if (abortOptions.discard) {
        if (identity) await unlinkIfIdentity(partialPath, identity);
        await unlink(statePath).catch(() => undefined);
      }
      preparedKey = undefined;
      completed.clear();
      writesSinceFlush = 0;
      finished = abortOptions.discard;
      await releaseLock();
    }
  };
}

export async function createManifest<TMetadata>(
  source: FileSource<TMetadata>,
  options: {
    chunkSize: number;
    transferId?: string;
    limits?: Partial<FileTransferLimits>;
    signal?: AbortSignal;
    readTimeoutMs?: number;
  }
): Promise<FileManifest<TMetadata>> {
  throwIfCancelled(options.signal);
  const limits = resolveFileTransferLimits(options.limits);
  const chunkSize = validateChunkSize(options.chunkSize, limits.maxChunkSize);
  const readTimeoutMs = options.readTimeoutMs === undefined
    ? undefined
    : validateReadTimeout(options.readTimeoutMs);
  const sourceName = source.name;
  const sourceSize = source.size;
  const sourceMetadata = source.metadata;
  validateFileName(sourceName, limits);
  if (!Number.isSafeInteger(sourceSize) || sourceSize < 0 || sourceSize > limits.maxFileSize) {
    throw new P2PError('RESOURCE_LIMIT', `File size exceeds the configured limit of ${limits.maxFileSize} bytes`);
  }
  const transferId = options.transferId ?? randomUUID();
  validateTransferId(transferId, limits);
  const metadata = sourceMetadata === undefined
    ? undefined
    : cloneValidatedMetadata(sourceMetadata, limits.maxMetadataBytes);
  const chunkCount = sourceSize === 0 ? 0 : Math.ceil(sourceSize / chunkSize);
  if (chunkCount > limits.maxChunkCount) {
    throw new P2PError('RESOURCE_LIMIT', `File chunk count exceeds the configured limit of ${limits.maxChunkCount}`);
  }
  const hasher = new Blake3Hasher();
  for (let index = 0; index < chunkCount; index += 1) {
    const data = await boundedSourceRead(
      (signal) => source.readChunk(index, chunkSize, signal),
      options.signal,
      readTimeoutMs
    );
    const expected = Math.min(chunkSize, sourceSize - index * chunkSize);
    if (data.byteLength !== expected) throw new P2PError('INTERNAL', `Source returned the wrong size for chunk ${index}`);
    hasher.update(data);
  }
  const manifest: FileManifest<TMetadata> = {
    transferId,
    name: sourceName,
    size: sourceSize,
    digest: hasher.digestBuffer().toString('hex'),
    chunkSize,
    chunkCount
  };
  if (metadata !== undefined) Object.defineProperty(manifest, 'metadata', { value: metadata, enumerable: true });
  return validateManifest<TMetadata>(manifest, limits);
}

async function boundedSourceRead<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  signal: AbortSignal | undefined,
  timeoutMs: number | undefined
): Promise<T> {
  throwIfCancelled(signal);
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const onAbort = (): void => controller.abort(signal?.reason);
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) onAbort();
  const read = Promise.resolve()
    .then(() => operation(controller.signal))
    .then(
      (value) => ({ kind: 'result' as const, value }),
      (cause: unknown) => ({
        kind: 'error' as const,
        error: cause instanceof P2PError
          ? cause
          : new P2PError('INTERNAL', cause instanceof Error ? cause.message : 'File source read failed', { cause })
      })
    );
  if (timeoutMs !== undefined) {
    timer = setTimeout(
      () => controller.abort(new P2PError('TIMEOUT', 'File source read timed out')),
      timeoutMs
    );
    timer.unref?.();
  }
  const aborted = new Promise<{ kind: 'aborted' }>((resolve) => {
    if (controller.signal.aborted) resolve({ kind: 'aborted' });
    else controller.signal.addEventListener('abort', () => resolve({ kind: 'aborted' }), { once: true });
  });
  try {
    const outcome = await Promise.race([read, aborted]);
    if (outcome.kind === 'result') return outcome.value;
    if (outcome.kind === 'error') throw outcome.error;
    await read;
    throw signalError(controller.signal);
  } finally {
    if (timer) clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
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

function validateReadTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 10 * 60_000) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid file source read timeout');
  }
  return value;
}

export function chunkDigest(data: Uint8Array): string {
  return blake3(data).toString('hex');
}

async function hashHandle(handle: FileHandle, size: number, signal?: AbortSignal): Promise<string> {
  const hasher = new Blake3Hasher();
  const buffer = Buffer.allocUnsafe(FILE_IO_SEGMENT_BYTES);
  let position = 0;
  while (position < size) {
    throwIfCancelled(signal);
    const length = Math.min(buffer.byteLength, size - position);
    const bytesRead = await readFully(handle, buffer.subarray(0, length), position, signal);
    throwIfCancelled(signal);
    hasher.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return hasher.digestBuffer().toString('hex');
}

async function readState<TMetadata>(
  path: string,
  manifest: FileManifest<TMetadata>,
  signal?: AbortSignal
): Promise<ResumeState | undefined> {
  let handle: FileHandle | undefined;
  try {
    throwIfCancelled(signal);
    handle = await openSecure(path, constants.O_RDONLY, 'resume state');
    throwIfCancelled(signal);
    const stats = await handle.stat({ bigint: true });
    if (!stats.isFile() || stats.size > BigInt(MAX_RESUME_STATE_BYTES)) return undefined;
    throwIfCancelled(signal);
    const serialized = Buffer.alloc(Number(stats.size));
    await readFully(handle, serialized, 0, signal);
    throwIfCancelled(signal);
    const parsed = JSON.parse(serialized.toString('utf8')) as unknown;
    if (!isResumeState(parsed) || parsed.digest !== manifest.digest || parsed.size !== manifest.size || parsed.chunkSize !== manifest.chunkSize) {
      return undefined;
    }
    const seen = new Set<number>();
    for (const [index, digest] of parsed.chunks) {
      if (!Number.isSafeInteger(index) || index < 0 || index >= manifest.chunkCount || seen.has(index)) return undefined;
      validateDigest(digest, 'resume chunk digest');
      seen.add(index);
    }
    return parsed;
  } catch {
    if (signal?.aborted) throw signalError(signal);
    return undefined;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function isResumeState(value: unknown): value is ResumeState {
  if (typeof value !== 'object' || value === null) return false;
  const state = value as Partial<ResumeState>;
  return state.version === 1 &&
    typeof state.digest === 'string' &&
    Number.isSafeInteger(state.size) &&
    Number.isSafeInteger(state.chunkSize) &&
    Array.isArray(state.chunks) &&
    state.chunks.length <= DEFAULT_FILE_TRANSFER_LIMITS.maxChunkCount &&
    state.chunks.every((entry) => Array.isArray(entry) && entry.length === 2);
}

async function openSecure(path: string, flags: number, label: string): Promise<FileHandle> {
  // Open first and perform subsequent I/O through the descriptor. O_NOFOLLOW
  // rejects leaf symlinks where supported; the descriptor/path identity check
  // below preserves fail-closed behavior on platforms where it is unavailable.
  let handle: FileHandle;
  try {
    handle = await open(path, flags | NO_FOLLOW);
  } catch (cause) {
    if (errorCode(cause) === 'ELOOP') throw new P2PError('REJECTED', `${label} must not be a symbolic link`);
    if (errorCode(cause) === 'ENOENT') throw new P2PError('NOT_FOUND', `${label} was not found`);
    throw cause;
  }
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile()) throw new P2PError('NOT_FOUND', `${label} is not a regular file`);
    let after: BigIntStats;
    try {
      after = await lstat(path, { bigint: true });
    } catch (cause) {
      if (errorCode(cause) === 'ENOENT') {
        throw new P2PError('REJECTED', `${label} path changed while it was being opened`);
      }
      throw cause;
    }
    if (
      after.isSymbolicLink() ||
      !after.isFile() ||
      after.dev !== opened.dev ||
      after.ino !== opened.ino
    ) {
      throw new P2PError('REJECTED', `${label} path changed while it was being opened`);
    }
    return handle;
  } catch (cause) {
    await handle.close().catch(() => undefined);
    throw cause;
  }
}

function fileIdentity(stats: BigIntStats): FileIdentity {
  return {
    dev: stats.dev,
    ino: stats.ino,
    size: stats.size,
    mtimeNs: stats.mtimeNs,
    ctimeNs: stats.ctimeNs
  };
}

function assertStableSource(stats: BigIntStats, expected: FileIdentity): void {
  const actual = fileIdentity(stats);
  if (
    !stats.isFile() ||
    actual.dev !== expected.dev ||
    actual.ino !== expected.ino ||
    actual.size !== expected.size ||
    actual.mtimeNs !== expected.mtimeNs ||
    actual.ctimeNs !== expected.ctimeNs
  ) {
    throw new P2PError('INTEGRITY_FAILED', 'File source changed after it was opened');
  }
}

async function readFully(
  handle: FileHandle,
  output: Uint8Array,
  position: number,
  signal?: AbortSignal
): Promise<number> {
  let offset = 0;
  while (offset < output.byteLength) {
    throwIfCancelled(signal);
    const length = Math.min(FILE_IO_SEGMENT_BYTES, output.byteLength - offset);
    const result = await handle.read(output, offset, length, position + offset);
    throwIfCancelled(signal);
    if (result.bytesRead === 0) throw new P2PError('INTEGRITY_FAILED', 'Unexpected end of file');
    offset += result.bytesRead;
  }
  return offset;
}

async function writeFully(
  handle: FileHandle,
  data: Uint8Array,
  position: number,
  signal?: AbortSignal
): Promise<void> {
  let offset = 0;
  while (offset < data.byteLength) {
    throwIfCancelled(signal);
    const length = Math.min(FILE_IO_SEGMENT_BYTES, data.byteLength - offset);
    const result = await handle.write(data, offset, length, position + offset);
    throwIfCancelled(signal);
    if (result.bytesWritten === 0) throw new P2PError('INTERNAL', 'File write made no progress');
    offset += result.bytesWritten;
  }
}

async function pathExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (cause) {
    if (errorCode(cause) === 'ENOENT') return false;
    throw cause;
  }
}

async function pathHasIdentity(path: string, identity: FileIdentity): Promise<boolean> {
  try {
    const stats = await lstat(path, { bigint: true });
    return stats.isFile() && stats.dev === identity.dev && stats.ino === identity.ino;
  } catch {
    return false;
  }
}

async function unlinkIfIdentity(path: string, identity: FileIdentity): Promise<void> {
  if (await pathHasIdentity(path, identity)) await unlink(path).catch(() => undefined);
}

async function syncDirectory(path: string, signal?: AbortSignal): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    throwIfCancelled(signal);
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    throwIfCancelled(signal);
    await handle.sync();
    throwIfCancelled(signal);
  } catch {
    if (signal?.aborted) throw signalError(signal);
    // Directory fsync is not supported by every Node platform/filesystem.
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function manifestKey(manifest: FileManifest): string {
  return `${manifest.digest}:${manifest.size}:${manifest.chunkSize}:${manifest.chunkCount}`;
}

function errorCode(value: unknown): string | undefined {
  return typeof value === 'object' && value !== null && 'code' in value && typeof value.code === 'string'
    ? value.code
    : undefined;
}
