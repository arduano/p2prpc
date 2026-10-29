import { z } from 'zod';
import { P2PError } from '../errors.js';
import { readFrame, writeFrame } from '../protocol.js';
import type { QuicRecvStream, QuicSendStream } from '../transport/types.js';
import type { ByteDuplex } from './transport/contracts.js';
import { unrefTimer } from '../platform.js';

const id = z.string().min(1).max(2048);
export const publicPrincipalSchema = z.object({
  id, subject: id, issuer: id.optional(), clientId: id.optional(), tenantId: id.optional(),
  expiresAt: z.number().int().positive()
}).strict();
export const helloSchema = z.object({ version: z.literal(1), resume: z.string().min(32).max(128).optional() }).strict();
export const readySchema = z.object({
  version: z.literal(1), hostId: id, peerId: id, sessionId: id,
  resume: z.string().min(32).max(128), expiresAt: z.number().int().positive(),
  principal: publicPrincipalSchema,
  gateway: z.object({ peerId: id, principal: publicPrincipalSchema }).strict()
}).strict();
export const bridgeFrameLimits = { maxControlFrameBytes: 16384 };

/** Read the bounded admission frame, then hand the SAME reader to the mux. */
export function controlChannel(channel: ByteDuplex) {
  const iterator = channel.readable[Symbol.asyncIterator]();
  let chunk: Uint8Array = new Uint8Array(0), offset = 0;
  const recv: QuicRecvStream = {
    async readExact(size) {
      const out = new Uint8Array(size);
      let copied = 0;
      while (copied < size) {
        if (offset === chunk.byteLength) {
          const next = await iterator.next();
          if (next.done) throw new P2PError('DISCONNECTED', 'Bridge admission closed');
          chunk = new Uint8Array(next.value.buffer, next.value.byteOffset, next.value.byteLength);
          offset = 0;
        }
        const count = Math.min(size - copied, chunk.byteLength - offset);
        out.set(chunk.subarray(offset, offset + count), copied);
        offset += count;
        copied += count;
      }
      return out;
    },
    async expectEnd() { throw new P2PError('INTERNAL', 'Admission has no separate stream FIN'); },
    async stop() { await channel.close(); }
  };
  const send: QuicSendStream = {
    writeAll: (bytes) => channel.write(bytes),
    async finish() { await channel.close(); },
    async reset() { await channel.close(); },
    async setPriority() {}
  };
  return {
    read: () => readFrame(recv, bridgeFrameLimits),
    write: (kind: number, value: unknown) => writeFrame(send, kind, value, bridgeFrameLimits),
    remaining: {
      ...channel,
      readable: { async *[Symbol.asyncIterator]() {
        try {
          if (offset < chunk.byteLength) yield chunk.subarray(offset);
          for (;;) {
            const value = await iterator.next();
            if (value.done) return;
            yield value.value;
          }
        } finally { await iterator.return?.(); }
      } }
    } satisfies ByteDuplex
  };
}

/** Only the small admission exchange has this deadline; it never retries work. */
export async function admission<T>(operation: (signal: AbortSignal) => Promise<T>, channel: ByteDuplex, signal?: AbortSignal, timeoutMs = 5_000): Promise<T> {
  const controller = new AbortController();
  const abort = (): void => controller.abort(signal?.reason ?? new P2PError('CANCELLED', 'Bridge admission cancelled'));
  if (signal?.aborted) abort();
  else signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(() => controller.abort(new P2PError('TIMEOUT', 'Bridge admission timed out')), timeoutMs);
  unrefTimer(timer);
  const work = Promise.resolve().then(() => { controller.signal.throwIfAborted(); return operation(controller.signal); });
  let cancel: (() => void) | undefined;
  try {
    const cancelled = new Promise<never>((_, reject) => {
      cancel = () => reject(controller.signal.reason);
      if (controller.signal.aborted) cancel();
      else controller.signal.addEventListener('abort', cancel, { once: true });
    });
    return await Promise.race([work, cancelled]);
  } catch (error) {
    const cleanup = Promise.resolve().then(() => channel.close(error instanceof Error ? error : new P2PError('REJECTED', 'Bridge admission refused'))).then(() => channel.closed);
    const results = await Promise.allSettled([work, cleanup]);
    const release = results[1];
    if (release?.status === 'rejected') throw new AggregateError([error, release.reason], 'Bridge admission cleanup failed', { cause: error });
    throw error;
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    if (cancel) controller.signal.removeEventListener('abort', cancel);
  }
}
