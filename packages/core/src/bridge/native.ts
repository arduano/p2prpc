import { z } from 'zod';
import { P2PError } from '../errors.js';
import { unrefTimer } from '../platform.js';
import { readFrame, writeFrame, writeStreamKind, StreamKind } from '../protocol.js';
import { normalizeRpcHeaders, type RpcHeaderInput, type RpcHeaders } from '../rpc/headers.js';
import type { AuthenticatedSession } from '../security/types.js';
import type { QuicBiStream, QuicConnection } from '../transport/types.js';
import type { ByteDuplex } from './transport/contracts.js';

const limits = { maxControlFrameBytes: 32768 };
const requestSchema = z.object({ version: z.literal(1), headers: z.record(z.string(), z.string()) }).strict();
const acceptedSchema = z.object({ version: z.literal(1) }).strict();
export interface OpenBridgeOptions {
  readonly headers?: RpcHeaderInput;
  readonly signal?: AbortSignal;
}
export interface NativeBridgeOffer {
  readonly localPeerId: string;
  /** Actual authenticated Gateway endpoint. Never a browser-provided identity. */
  readonly peer: { readonly id: string; readonly direction: 'inbound' | 'outbound' };
  readonly auth: AuthenticatedSession;
  readonly headers: RpcHeaders;
  readonly signal: AbortSignal;
  readonly channel: ByteDuplex;
}

/** Opt-in versioned stream service. Existing RPC/file stream formats are unchanged. */
export async function openNativeBridge(
  connection: () => Promise<QuicConnection>, options: OpenBridgeOptions,
  track: (work: Promise<unknown>) => void
): Promise<ByteDuplex> {
  const headers = normalizeRpcHeaders(options.headers);
  options.signal?.throwIfAborted();
  const controller = new AbortController();
  let channel: ByteDuplex | undefined;
  const abort = (reason: unknown): void => {
    controller.abort(reason);
    if (channel) void Promise.resolve(channel.close()).catch(() => undefined);
  };
  const cancelled = () => abort(options.signal?.reason ?? new P2PError('CANCELLED', 'Bridge opening cancelled'));
  options.signal?.addEventListener('abort', cancelled, { once: true });
  const timer = setTimeout(() => abort(new P2PError('TIMEOUT', 'Bridge opening timed out')), 10_000);
  unrefTimer(timer);
  // Do not cancel ManagedConnection.openBi: its native-open quarantine would
  // close the borrowed outer Peer. Retain and clean up a late stream instead.
  const work = (async () => {
    const upstream = await connection();
    controller.signal.throwIfAborted();
    const stream = await upstream.openBi();
    channel = nativeCarrier(stream);
    try {
      controller.signal.throwIfAborted();
      await writeStreamKind(stream.send, StreamKind.Bridge);
      await writeFrame(stream.send, 60, { version: 1, headers }, limits);
      const response = await readFrame(stream.recv, limits);
      if (response.kind !== 61) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Bridge service unavailable');
      acceptedSchema.parse(response.value);
      controller.signal.throwIfAborted();
      return channel;
    } catch (error) {
      await channel.close();
      throw error;
    }
  })();
  track(work);
  let onAbort: (() => void) | undefined;
  try {
    const stopped = new Promise<never>((_, reject) => {
      onAbort = () => reject(controller.signal.reason);
      if (controller.signal.aborted) onAbort();
      else controller.signal.addEventListener('abort', onAbort, { once: true });
    });
    return await Promise.race([work, stopped]);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', cancelled);
    if (onAbort) controller.signal.removeEventListener('abort', onAbort);
  }
}

export async function readBridgeRequest(stream: QuicBiStream): Promise<RpcHeaders> {
  const request = await readFrame(stream.recv, limits);
  if (request.kind !== 60) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Expected bridge opening');
  return normalizeRpcHeaders(requestSchema.parse(request.value).headers);
}
export async function acceptNativeBridge(stream: QuicBiStream): Promise<ByteDuplex> {
  await writeFrame(stream.send, 61, { version: 1 }, limits);
  return nativeCarrier(stream);
}

/** Message boundaries adapt the existing exact-read stream API to a byte carrier.
 * The standard mux above this adapter owns logical stream IDs and flow control. */
function nativeCarrier(stream: QuicBiStream): ByteDuplex {
  let finish!: () => void, fail!: (error: unknown) => void;
  const closed = new Promise<void>((resolve, reject) => { finish = resolve; fail = reject; });
  void closed.catch(() => undefined);
  let closing: Promise<void> | undefined;
  let writes = Promise.resolve();
  let queuedBytes = 0, queuedWrites = 0;
  let reading: Promise<Uint8Array> | undefined;
  const read = (size: number): Promise<Uint8Array> => reading = stream.recv.readExact(size);
  const close = (): Promise<void> => closing ??= (async () => {
    const result = await Promise.allSettled([stream.send.reset(0n), stream.recv.stop(0n)]);
    await Promise.allSettled([writes, ...(reading ? [reading] : [])]);
    const failed = result.find((value) => value.status === 'rejected');
    if (failed?.status === 'rejected') { fail(failed.reason); throw failed.reason; }
    finish();
  })();
  return {
    closed, close,
    readable: { async *[Symbol.asyncIterator]() {
      try {
        while (!closing) {
          const header = await read(4);
          const size = new DataView(header.buffer, header.byteOffset, 4).getUint32(0);
          if (size < 1 || size > 65536) throw new P2PError('RESOURCE_LIMIT', 'Invalid bridge carrier packet');
          yield await read(size);
        }
      } finally { await close(); }
    } },
    write(bytes) {
      if (closing) return Promise.reject(new P2PError('DISCONNECTED', 'Bridge carrier closed'));
      if (queuedWrites >= 16 || queuedBytes + bytes.byteLength > 8 * 1024 * 1024) {
        return Promise.reject(new P2PError('RESOURCE_LIMIT', 'Bridge carrier write capacity'));
      }
      queuedWrites += 1; queuedBytes += bytes.byteLength;
      const operation = writes.then(async () => {
        for (let offset = 0; offset < bytes.byteLength; offset += 65536) {
          const chunk = bytes.subarray(offset, offset + 65536);
          const header = new Uint8Array(4);
          new DataView(header.buffer).setUint32(0, chunk.byteLength);
          await stream.send.writeAll(header);
          await stream.send.writeAll(chunk);
        }
      }).finally(() => { queuedWrites -= 1; queuedBytes -= bytes.byteLength; });
      writes = operation.catch(() => undefined);
      return operation;
    }
  };
}
