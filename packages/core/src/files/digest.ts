import { blake3 } from '@noble/hashes/blake3';
import { P2PError } from '../errors.js';
import { hex, randomUuid, unrefTimer } from '../platform.js';
import type { FileManifest, FileSource } from './types.js';
import {
  cloneValidatedMetadata, resolveFileTransferLimits, validateChunkSize,
  validateFileName, validateManifest, validateTransferId, type FileTransferLimits
} from './validation.js';

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
  const transferId = options.transferId ?? randomUuid();
  validateTransferId(transferId, limits);
  const metadata = sourceMetadata === undefined
    ? undefined
    : cloneValidatedMetadata(sourceMetadata, limits.maxMetadataBytes);
  const chunkCount = sourceSize === 0 ? 0 : Math.ceil(sourceSize / chunkSize);
  if (chunkCount > limits.maxChunkCount) {
    throw new P2PError('RESOURCE_LIMIT', `File chunk count exceeds the configured limit of ${limits.maxChunkCount}`);
  }
  const hasher = blake3.create();
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
    digest: hex(hasher.digest()),
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
    unrefTimer(timer);
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
  return hex(blake3(data));
}
