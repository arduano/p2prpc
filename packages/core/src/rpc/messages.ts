import { P2PError } from '../errors.js';
import { encodeFrameBody, measureFrameValue, readFrameBody, readFrameHeader, RpcFrameKind, writeFrameBody, type Frame, type FrameLimits } from '../protocol.js';
import { ResourceScheduler } from '../runtime/resources.js';
import type { QuicRecvStream, QuicSendStream } from '../transport/types.js';
import { deserializeValue, measureValue, serializeValue } from './wire.js';

/** RPC envelopes are independent of the small authentication/file controls. */
export const DEFAULT_RPC_FRAME_LIMITS: FrameLimits = Object.freeze({
  maxControlFrameBytes: 64 * 1024 * 1024,
  maxControlFrameItems: 256 * 1024,
  maxControlFrameDepth: 64
});

function pool(bufferedBytes: number): ResourceScheduler {
  const capacity = { bufferedBytes, queued: 256, streams: 1, handshakes: 1, callbacks: 1, inboundTransfers: 1, outboundTransfers: 1 };
  const zero = { streams: 0, bufferedBytes: 0 };
  const directions = { inbound: zero, outbound: zero };
  return new ResourceScheduler({
    global: capacity, perPeer: capacity, perPrincipal: capacity,
    fileDataReserve: { global: directions, perPeer: directions, perPrincipal: directions },
    fileControlReserve: { global: directions, perPeer: directions, perPrincipal: directions },
    generalReserve: { global: zero, perPeer: zero, perPrincipal: zero }
  });
}

/** One shared encoded-buffer owner for a runtime, not one per peer or stream.
 * Directional pools prevent duplex deadlock. Small controls cannot queue behind
 * bulk data. Leases end on actual read/write settlement, never caller timeout.
 * This bounds encoded bodies, not application DTOs or the JavaScript heap.
 */
export class RpcMessageBudget {
  private readonly pools = {
    inboundBulk: pool(64 * 1024 * 1024), outboundBulk: pool(64 * 1024 * 1024),
    inboundSmall: pool(1024 * 1024), outboundSmall: pool(1024 * 1024)
  };

  acquire(direction: 'inbound' | 'outbound', bytes: number, signal?: AbortSignal) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > 64 * 1024 * 1024) {
      throw new P2PError('RESOURCE_LIMIT', 'RPC message exceeds encoded-buffer capacity');
    }
    return this.pools[`${direction}${bytes <= 64 * 1024 ? 'Small' : 'Bulk'}`]
      .acquire('rpc', { bufferedBytes: bytes }, signal);
  }

  diagnostics() {
    return Object.fromEntries(Object.entries(this.pools).map(([name, scheduler]) => [name, scheduler.snapshot()]));
  }

  close(): void { for (const scheduler of Object.values(this.pools)) scheduler.close(new P2PError('DISCONNECTED', 'RPC message owner closed')); }
  async whenIdle(): Promise<void> { await Promise.all(Object.values(this.pools).map(scheduler => scheduler.whenIdle())); }
}

function payloadKey(kind: number): 'input' | 'data' | undefined {
  return kind === RpcFrameKind.Request ? 'input' : kind === RpcFrameKind.Data ? 'data' : undefined;
}

/** Accepts native RPC values; SuperJSON transformation happens inside admission. */
export async function writeRpcFrame(
  send: QuicSendStream, kind: number, value: Record<string, unknown>, budget: RpcMessageBudget,
  limits: FrameLimits = DEFAULT_RPC_FRAME_LIMITS, signal?: AbortSignal
): Promise<void> {
  const key = payloadKey(kind);
  const measure = (): number => key
    ? measureFrameValue({ ...value, [key]: null }, limits) - 1 + measureValue(value[key], limits)
    : measureFrameValue(value, limits);
  const bytes = measure();
  if (bytes > limits.maxControlFrameBytes) throw new P2PError('RESOURCE_LIMIT', 'RPC envelope exceeds frame limit');
  const lease = await budget.acquire('outbound', bytes, signal);
  try {
    signal?.throwIfAborted();
    // Caller-owned input can change while admission waits. No retry, and no
    // encoding beyond this lease even if the new value fits the overall limit.
    if (measure() > bytes) throw new P2PError('RESOURCE_LIMIT', 'RPC value grew during message admission');
    const envelope = key ? { ...value, [key]: serializeValue(value[key], limits) } : value;
    const body = encodeFrameBody(envelope, { ...limits, maxControlFrameBytes: bytes });
    await writeFrameBody(send, kind, body);
  } finally { lease.release(); }
}

/** Validates declared size before allocating; transfers decoded ownership once. */
export async function readRpcFrame<T>(
  recv: QuicRecvStream, budget: RpcMessageBudget,
  limits: FrameLimits = DEFAULT_RPC_FRAME_LIMITS, signal?: AbortSignal
): Promise<Frame<T>> {
  const { kind, length } = await readFrameHeader(recv, limits);
  const lease = await budget.acquire('inbound', length, signal);
  try {
    signal?.throwIfAborted();
    const value = await readFrameBody<Record<string, unknown>>(recv, length, limits);
    const key = payloadKey(kind);
    if (key && value && typeof value === 'object' && Object.hasOwn(value, key)) {
      value[key] = deserializeValue(value[key], limits);
    }
    return { kind, value: value as T };
  } finally { lease.release(); }
}
