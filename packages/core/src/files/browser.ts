import { P2PError } from '../errors.js';
import { chunkDigest } from './digest.js';
import type { FileDestination, FileManifest, FileSource } from './types.js';
import {
  cloneValidatedMetadata,
  DEFAULT_FILE_TRANSFER_LIMITS,
  expectedChunkSize,
  manifestWireValue,
  validateChunkSize,
  validateFileName,
  validateManifest
} from './validation.js';

/** Blob bytes are immutable and rereadable, including manifest hashing/retries. */
export function blobSource<TMetadata = unknown>(
  blob: Blob,
  options: { readonly name: string; readonly metadata?: TMetadata }
): FileSource<TMetadata> {
  if (!(blob instanceof Blob)) throw new P2PError('INVALID_FRAME', 'File source must be a Blob');
  validateFileName(options.name, DEFAULT_FILE_TRANSFER_LIMITS);
  const name = options.name;
  const size = blob.size;
  const metadata = options.metadata === undefined
    ? undefined
    : cloneValidatedMetadata(options.metadata, DEFAULT_FILE_TRANSFER_LIMITS.maxMetadataBytes);
  return Object.freeze({
    name,
    size,
    ...(metadata === undefined ? {} : { metadata }),
    async readChunk(index: number, chunkSize: number, signal?: AbortSignal) {
      checkAbort(signal);
      validateChunkSize(chunkSize);
      const count = size === 0 ? 0 : Math.ceil(size / chunkSize);
      if (!Number.isSafeInteger(index) || index < 0 || index >= count) {
        throw new P2PError('INVALID_FRAME', 'Blob chunk is out of range');
      }
      const offset = index * chunkSize;
      const bytes = await Blob.prototype.slice.call(blob, offset, Math.min(size, offset + chunkSize)).arrayBuffer();
      checkAbort(signal);
      return new Uint8Array(bytes);
    }
  });
}

export interface MemoryFileDestination<TMetadata = unknown> extends FileDestination<TMetadata> {
  /** Available only after successful whole-file verification and publication. */
  blob(): Blob | null;
}

/**
 * Explicit small-file staging, not a browser filesystem or persistent cache.
 * Staging is <=maxBytes (hard maximum 64 MiB). Publishing Blob may temporarily
 * copy those bytes, so budget up to 2*maxBytes plus transfer lane buffers.
 * A non-discarding abort preserves verified chunks for this handle's retries.
 * Drop the destination/returned Blob references to release their memory.
 */
export function memoryDestination<TMetadata = unknown>(
  options: { readonly maxBytes: number }
): MemoryFileDestination<TMetadata> {
  if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes < 0 || options.maxBytes > 64 * 1024 * 1024) {
    throw new P2PError('RESOURCE_LIMIT', 'Memory destination requires a limit between zero and 64 MiB');
  }
  const maxBytes = options.maxBytes;
  let bytes: Uint8Array<ArrayBuffer> | undefined;
  let key: string | undefined;
  let manifest: FileManifest<TMetadata> | undefined;
  let active = false;
  let published: Blob | null = null;
  const completed = new Set<number>();
  const exact = (input: FileManifest<TMetadata>): void => {
    if (!active || !manifest || key !== JSON.stringify(manifestWireValue(validateManifest<TMetadata>(input, DEFAULT_FILE_TRANSFER_LIMITS)))) {
      throw new P2PError('INTEGRITY_FAILED', 'Memory destination manifest changed or is inactive');
    }
  };
  return Object.freeze({
    async prepare(input: FileManifest<TMetadata>, signal?: AbortSignal) {
      checkAbort(signal);
      if (active || published) throw new P2PError('REJECTED', 'Memory destination is already active or published');
      const checked = validateManifest<TMetadata>(input, DEFAULT_FILE_TRANSFER_LIMITS);
      if (checked.size > maxBytes) throw new P2PError('RESOURCE_LIMIT', 'File exceeds memory staging limit');
      const nextKey = JSON.stringify(manifestWireValue(checked));
      if (key !== undefined && key !== nextKey) throw new P2PError('INTEGRITY_FAILED', 'Memory destination manifest changed');
      bytes ??= new Uint8Array(checked.size);
      key = nextKey;
      manifest = checked;
      active = true;
      return new Set(completed);
    },
    async writeChunk(input: FileManifest<TMetadata>, index: number, data: Uint8Array, signal?: AbortSignal) {
      checkAbort(signal);
      exact(input);
      if (!Number.isSafeInteger(index) || index < 0 || index >= input.chunkCount ||
        data.byteLength !== expectedChunkSize(input, index)) {
        throw new P2PError('INVALID_FRAME', 'Memory destination chunk is invalid');
      }
      if (completed.has(index)) throw new P2PError('INVALID_FRAME', 'Memory destination chunk is duplicated');
      bytes!.set(data, index * input.chunkSize);
      completed.add(index);
    },
    async finalize(input: FileManifest<TMetadata>, context: { readonly signal?: AbortSignal; readonly markCommitted: () => void }) {
      exact(input);
      checkAbort(context.signal);
      if (completed.size !== input.chunkCount || chunkDigest(bytes!) !== input.digest) {
        throw new P2PError('INTEGRITY_FAILED', 'Memory destination final digest does not match');
      }
      const output = new Blob([bytes!]);
      checkAbort(context.signal);
      published = output;
      context.markCommitted();
      bytes = undefined;
      completed.clear();
      active = false;
    },
    async abort(input: FileManifest<TMetadata>, abortOptions: { readonly discard: boolean }) {
      if (published) return;
      if (key !== undefined && key !== JSON.stringify(manifestWireValue(validateManifest<TMetadata>(input, DEFAULT_FILE_TRANSFER_LIMITS)))) {
        throw new P2PError('INTEGRITY_FAILED', 'Memory destination abort manifest changed');
      }
      active = false;
      if (abortOptions.discard) {
        bytes = undefined;
        key = undefined;
        manifest = undefined;
        completed.clear();
      }
    },
    blob: () => published
  });
}

function checkAbort(signal?: AbortSignal): void {
  if (signal?.aborted) throw signal.reason instanceof P2PError
    ? signal.reason
    : new P2PError('CANCELLED', 'File operation cancelled');
}
