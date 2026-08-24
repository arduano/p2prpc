import { Blake3Hasher, blake3 } from '@napi-rs/blake-hash';
import { randomUUID } from 'node:crypto';
import { constants, type BigIntStats } from 'node:fs';
import { basename, dirname } from 'node:path';
import { link, lstat, open, rename, unlink, type FileHandle } from 'node:fs/promises';
import { P2PError } from '../errors.js';
import type {
  FileDestination,
  FileDestinationFinalizeContext,
  FileManifest,
  FileSource,
  PreparedFileSource
} from './types.js';
import {
  DEFAULT_FILE_TRANSFER_LIMITS,
  assertOnlyKeys,
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
const RESUME_HEADER_BYTES = 64;
const RESUME_RECORD_BYTES = 33;
const RESUME_MAGIC = Buffer.from([0x50, 0x32, 0x50, 0x52, 0x50, 0x43, 0x33, 0x00]);

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
  const prepare = async (signal?: AbortSignal): Promise<PreparedFileSource<TMetadata>> => {
    throwIfCancelled(signal);
    const handle = await openSecure(path, constants.O_RDONLY, 'source');
    let closed = false;
    try {
      assertStableSource(await handle.stat({ bigint: true }), identity);
      throwIfCancelled(signal);
    } catch (cause) {
      try {
        await handle.close();
      } catch (cleanup) {
        throw cleanupAfterFailure('Prepared file source cleanup failed', cause, cleanup);
      }
      throw cause;
    }
    const prepared: PreparedFileSource<TMetadata> = {
      name,
      size,
      async readChunk(index, chunkSize, readSignal) {
        if (closed) throw new P2PError('INTERNAL', 'Prepared file source is closed');
        throwIfCancelled(readSignal);
        validateChunkSize(chunkSize);
        const chunkCount = size === 0 ? 0 : Math.ceil(size / chunkSize);
        if (!Number.isSafeInteger(index) || index < 0 || index >= chunkCount) {
          throw new P2PError('INVALID_FRAME', `Chunk ${String(index)} is out of range`);
        }
        assertStableSource(await handle.stat({ bigint: true }), identity);
        const offset = index * chunkSize;
        const data = Buffer.allocUnsafe(Math.min(chunkSize, size - offset));
        await readFully(handle, data, offset, readSignal);
        throwIfCancelled(readSignal);
        assertStableSource(await handle.stat({ bigint: true }), identity);
        return data;
      },
      async close() {
        if (closed) return;
        closed = true;
        await handle.close();
      }
    };
    if (metadata !== undefined) Object.defineProperty(prepared, 'metadata', { value: metadata, enumerable: true });
    return Object.freeze(prepared);
  };
  const source: FileSource<TMetadata> = {
    name,
    size,
    prepare,
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
  readonly chunks: Array<readonly [index: number, digest: string]>;
}

interface LoadedResumeState {
  readonly state: ResumeState;
  readonly handle: FileHandle;
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
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new P2PError('INVALID_FRAME', 'File destination options must be an object');
  }
  assertOnlyKeys(options as Record<string, unknown>, ['overwrite', 'durable', 'maxChunkSize'], 'File destination options');
  if (options.overwrite !== undefined && typeof options.overwrite !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'File destination overwrite must be a boolean');
  }
  if (options.durable !== undefined && typeof options.durable !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'File destination durable must be a boolean');
  }
  const maxChunkSize = validateChunkSize(options.maxChunkSize ?? DEFAULT_FILE_TRANSFER_LIMITS.maxChunkSize);
  const destinationLimits: FileTransferLimits = { ...DEFAULT_FILE_TRANSFER_LIMITS, maxChunkSize };
  const partialPath = `${path}.p2prpc.part`;
  const statePath = `${path}.p2prpc.state`;
  const lockPath = `${path}.p2prpc.lock`;
  const completed = new Map<number, string>();
  let partialHandle: FileHandle | undefined;
  let partialIdentity: FileIdentity | undefined;
  let stateHandle: FileHandle | undefined;
  let stateIdentity: FileIdentity | undefined;
  let lockHandle: FileHandle | undefined;
  let lockIdentity: FileIdentity | undefined;
  let preparedKey: string | undefined;
  let writesSinceFlush = 0;
  let flushChain = Promise.resolve();
  let finished = false;

  const enqueueFlush = (manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<void> => {
    const task = flushChain.then(() => flushState(manifest, signal));
    flushChain = task.catch(() => undefined);
    return task;
  };

  const flushState = async (manifest: FileManifest<TMetadata>, signal?: AbortSignal): Promise<void> => {
    throwIfCancelled(signal);
    requirePrepared(manifest);
    if (!stateHandle) throw new P2PError('INTERNAL', 'File resume state is not open');
    if (options.durable !== false) await stateHandle.sync();
    throwIfCancelled(signal);
    writesSinceFlush = 0;
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
    await cleanupAll('File destination lock cleanup failed', [
      async () => {
        if (handle && !identity) identity = fileIdentity(await handle.stat({ bigint: true }));
      },
      async () => { if (handle) await handle.close(); },
      async () => { if (identity) await unlinkIfIdentity(lockPath, identity); }
    ]);
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
        try {
          await releaseLock();
        } catch (cleanup) {
          throw cleanupAfterFailure('File destination lock acquisition cleanup failed', cause, cleanup);
        }
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
        const loadedState = await readState(statePath, manifest, signal);
        if (loadedState) {
          stateHandle = loadedState.handle;
          stateIdentity = fileIdentity(await stateHandle.stat({ bigint: true }));
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
              for (const [index, digest] of loadedState.state.chunks) {
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
          await stateHandle?.close();
          stateHandle = undefined;
          if (stateIdentity) await unlinkIfIdentity(statePath, stateIdentity);
          else await unlinkIfPresent(statePath);
          stateIdentity = undefined;
          throwIfCancelled(signal);
          await unlinkIfPresent(partialPath);
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
          stateHandle = await createResumeState(statePath, manifest, options.durable !== false, signal);
          stateIdentity = fileIdentity(await stateHandle.stat({ bigint: true }));
          if (options.durable !== false) await syncDirectory(dirname(path), signal);
        }
        throwIfCancelled(signal);
        return new Set(completed.keys());
      } catch (cause) {
        const partialToClose = partialHandle;
        const stateToClose = stateHandle;
        partialHandle = undefined;
        partialIdentity = undefined;
        stateHandle = undefined;
        stateIdentity = undefined;
        preparedKey = undefined;
        try {
          await cleanupAll('File destination preparation cleanup failed', [
            async () => { if (partialToClose) await partialToClose.close(); },
            async () => { if (stateToClose) await stateToClose.close(); },
            releaseLock
          ]);
        } catch (cleanup) {
          throw cleanupAfterFailure('File destination preparation cleanup failed', cause, cleanup);
        }
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
      const digest = chunkDigest(data);
      if (!stateHandle) throw new P2PError('INTERNAL', 'File resume state is not open');
      await writeResumeRecord(stateHandle, index, digest, signal);
      completed.set(index, digest);
      writesSinceFlush += 1;
      if (writesSinceFlush >= 16) await enqueueFlush(manifest, signal);
    },

    async finalize(manifest, context) {
      const { signal, markCommitted } = validateFinalizeContext(context);
      throwIfCancelled(signal);
      const handle = requirePrepared(manifest);
      if (completed.size !== manifest.chunkCount) throw new P2PError('INTEGRITY_FAILED', 'File has missing chunks');
      await enqueueFlush(manifest, signal);
      await flushChain;
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
      let linkedPublication = false;
      if (options.overwrite) {
        await rename(partialPath, path);
      } else {
        try {
          await link(partialPath, path);
          linkedPublication = true;
        } catch (cause) {
          if (errorCode(cause) === 'EEXIST') throw new P2PError('REJECTED', 'Destination already exists');
          throw cause;
        }
      }
      // The rename/link above is the irreversible publication boundary. Tell
      // the manager synchronously before descriptor, staging, lock, or
      // directory-durability cleanup can fail. This prevents a known commit
      // from being reclassified as a reject/retry.
      finished = true;
      let commitNotificationFailure: unknown;
      try {
        markCommitted();
      } catch (cause) {
        // A caller-supplied notification must not strand native resources.
        // Preserve it and finish every post-commit cleanup operation below.
        commitNotificationFailure = cause;
      }
      // Publication is known. Cleanup and directory durability are one
      // explicit post-commit phase: every operation is attempted, and any
      // failure is surfaced as OUTCOME_UNKNOWN rather than returning success
      // with leaked descriptors or persistent staging/lock files.
      partialHandle = undefined;
      partialIdentity = undefined;
      const resumeHandle = stateHandle;
      const resumeIdentity = stateIdentity;
      stateHandle = undefined;
      stateIdentity = undefined;
      try {
        await cleanupAll('Published file cleanup or durability confirmation failed', [
          async () => {
            if (commitNotificationFailure !== undefined) throw commitNotificationFailure;
          },
          async () => { await handle.close(); },
          async () => { if (resumeHandle) await resumeHandle.close(); },
          async () => { if (linkedPublication) await unlinkIfPresent(partialPath); },
          async () => { if (resumeIdentity) await unlinkIfIdentity(statePath, resumeIdentity); },
          releaseLock,
          async () => { if (options.durable !== false) await syncDirectory(dirname(path)); }
        ]);
      } catch (cause) {
        throw new P2PError(
          'OUTCOME_UNKNOWN',
          'File was published, but cleanup or directory durability could not be confirmed',
          { cause }
        );
      }
    },

    async abort(manifest, abortOptions, signal) {
      if (finished) return;
      if (!signal?.aborted && partialHandle && preparedKey === manifestKey(manifest) && !abortOptions.discard) {
        await enqueueFlush(manifest, signal).catch(() => undefined);
        await flushChain.catch(() => undefined);
      }
      const identity = partialIdentity;
      const partialToClose = partialHandle;
      partialHandle = undefined;
      partialIdentity = undefined;
      const stateToClose = stateHandle;
      stateHandle = undefined;
      const resumeIdentity = stateIdentity;
      stateIdentity = undefined;
      preparedKey = undefined;
      completed.clear();
      writesSinceFlush = 0;
      finished = abortOptions.discard;
      await cleanupAll('File destination rollback cleanup failed', [
        async () => { if (partialToClose) await partialToClose.close(); },
        async () => { if (stateToClose) await stateToClose.close(); },
        async () => { if (abortOptions.discard && identity) await unlinkIfIdentity(partialPath, identity); },
        async () => { if (abortOptions.discard && resumeIdentity) await unlinkIfIdentity(statePath, resumeIdentity); },
        releaseLock
      ]);
    }
  };
}

function validateFinalizeContext(
  value: FileDestinationFinalizeContext
): FileDestinationFinalizeContext {
  if (
    typeof value !== 'object' ||
    value === null ||
    Array.isArray(value) ||
    typeof value.markCommitted !== 'function' ||
    (value.signal !== undefined && !(value.signal instanceof AbortSignal))
  ) {
    throw new P2PError('INVALID_FRAME', 'File destination finalize context is invalid');
  }
  return value;
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
): Promise<LoadedResumeState | undefined> {
  let handle: FileHandle | undefined;
  try {
    throwIfCancelled(signal);
    handle = await openSecure(path, constants.O_RDWR, 'resume state');
    throwIfCancelled(signal);
    const stats = await handle.stat({ bigint: true });
    const expectedSize = resumeStateSize(manifest.chunkCount);
    if (!stats.isFile() || stats.size !== BigInt(expectedSize)) return undefined;
    throwIfCancelled(signal);
    const serialized = Buffer.alloc(expectedSize);
    await readFully(handle, serialized, 0, signal);
    throwIfCancelled(signal);
    if (!resumeHeaderMatches(serialized.subarray(0, RESUME_HEADER_BYTES), manifest)) return undefined;
    const chunks: Array<readonly [number, string]> = [];
    for (let index = 0; index < manifest.chunkCount; index += 1) {
      const offset = resumeRecordOffset(index);
      const marker = serialized[offset];
      if (marker === 0) continue;
      if (marker !== 1) return undefined;
      const digest = serialized.subarray(offset + 1, offset + RESUME_RECORD_BYTES).toString('hex');
      validateDigest(digest, 'resume chunk digest');
      chunks.push([index, digest]);
    }
    const loaded = { state: { chunks }, handle };
    handle = undefined;
    return loaded;
  } catch {
    if (signal?.aborted) throw signalError(signal);
    return undefined;
  } finally {
    await handle?.close();
  }
}

async function createResumeState<TMetadata>(
  path: string,
  manifest: FileManifest<TMetadata>,
  durable: boolean,
  signal?: AbortSignal
): Promise<FileHandle> {
  const size = resumeStateSize(manifest.chunkCount);
  let handle: FileHandle | undefined;
  try {
    throwIfCancelled(signal);
    handle = await open(path, constants.O_RDWR | constants.O_CREAT | constants.O_EXCL | NO_FOLLOW, 0o600);
    throwIfCancelled(signal);
    await handle.truncate(size);
    await writeFully(handle, createResumeHeader(manifest), 0, signal);
    if (durable) await handle.sync();
    throwIfCancelled(signal);
    const output = handle;
    handle = undefined;
    return output;
  } finally {
    await handle?.close();
  }
}

async function writeResumeRecord(
  handle: FileHandle,
  index: number,
  digest: string,
  signal?: AbortSignal
): Promise<void> {
  const offset = resumeRecordOffset(index);
  await writeFully(handle, Uint8Array.of(0), offset, signal);
  await writeFully(handle, Buffer.from(digest, 'hex'), offset + 1, signal);
  // The completion marker is last. A crash can lose work and cause a safe
  // retransmit, but cannot bless an incompletely written digest record.
  await writeFully(handle, Uint8Array.of(1), offset, signal);
}

function createResumeHeader<TMetadata>(manifest: FileManifest<TMetadata>): Buffer {
  const header = Buffer.alloc(RESUME_HEADER_BYTES);
  RESUME_MAGIC.copy(header, 0);
  header.writeUInt32BE(3, 8);
  header.writeUInt32BE(RESUME_HEADER_BYTES, 12);
  header.writeBigUInt64BE(BigInt(manifest.size), 16);
  header.writeUInt32BE(manifest.chunkSize, 24);
  header.writeUInt32BE(manifest.chunkCount, 28);
  Buffer.from(manifest.digest, 'hex').copy(header, 32);
  return header;
}

function resumeHeaderMatches<TMetadata>(header: Uint8Array, manifest: FileManifest<TMetadata>): boolean {
  const view = Buffer.from(header.buffer, header.byteOffset, header.byteLength);
  return view.subarray(0, RESUME_MAGIC.byteLength).equals(RESUME_MAGIC) &&
    view.readUInt32BE(8) === 3 &&
    view.readUInt32BE(12) === RESUME_HEADER_BYTES &&
    view.readBigUInt64BE(16) === BigInt(manifest.size) &&
    view.readUInt32BE(24) === manifest.chunkSize &&
    view.readUInt32BE(28) === manifest.chunkCount &&
    view.subarray(32, 64).toString('hex') === manifest.digest;
}

function resumeStateSize(chunkCount: number): number {
  const size = RESUME_HEADER_BYTES + chunkCount * RESUME_RECORD_BYTES;
  if (!Number.isSafeInteger(size) || size > MAX_RESUME_STATE_BYTES) {
    throw new P2PError('RESOURCE_LIMIT', 'File resume state exceeds its maximum size');
  }
  return size;
}

function resumeRecordOffset(index: number): number {
  return RESUME_HEADER_BYTES + index * RESUME_RECORD_BYTES;
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
    try {
      await handle.close();
    } catch (cleanup) {
      throw cleanupAfterFailure(`Secure ${label} handle cleanup failed`, cause, cleanup);
    }
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
  let stats: BigIntStats;
  try {
    stats = await lstat(path, { bigint: true });
  } catch (cause) {
    if (errorCode(cause) === 'ENOENT') return;
    throw cause;
  }
  if (!stats.isFile() || stats.dev !== identity.dev || stats.ino !== identity.ino) {
    throw new P2PError('INTEGRITY_FAILED', 'Managed file path changed during cleanup');
  }
  await unlinkIfPresent(path);
}

async function unlinkIfPresent(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (cause) {
    if (errorCode(cause) !== 'ENOENT') throw cause;
  }
}

async function syncDirectory(path: string, signal?: AbortSignal): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    throwIfCancelled(signal);
    handle = await open(path, constants.O_RDONLY | NO_FOLLOW);
    throwIfCancelled(signal);
    await handle.sync();
    throwIfCancelled(signal);
  } catch (cause) {
    if (signal?.aborted) throw signalError(signal);
    // Node reports these codes when directory fsync is unavailable on the
    // current platform/filesystem. Authorization and I/O failures remain
    // visible instead of silently weakening the requested durability.
    if (!DIRECTORY_SYNC_UNSUPPORTED_CODES.has(errorCode(cause) ?? '')) throw cause;
  } finally {
    await handle?.close();
  }
}

async function cleanupAll(
  message: string,
  operations: readonly (() => Promise<void>)[]
): Promise<void> {
  const failures: unknown[] = [];
  for (const operation of operations) {
    try {
      await operation();
    } catch (cause) {
      failures.push(cause);
    }
  }
  if (failures.length > 0) {
    throw new P2PError('INTERNAL', message, {
      cause: new AggregateError(failures, message)
    });
  }
}

function cleanupAfterFailure(message: string, operation: unknown, cleanup: unknown): P2PError {
  return new P2PError('OUTCOME_UNKNOWN', message, { cause: { operation, cleanup } });
}

const DIRECTORY_SYNC_UNSUPPORTED_CODES = new Set(['EBADF', 'EISDIR', 'EINVAL', 'ENOTSUP', 'EOPNOTSUPP']);

function manifestKey(manifest: FileManifest): string {
  return `${manifest.digest}:${manifest.size}:${manifest.chunkSize}:${manifest.chunkCount}`;
}

function errorCode(value: unknown): string | undefined {
  return typeof value === 'object' && value !== null && 'code' in value && typeof value.code === 'string'
    ? value.code
    : undefined;
}
