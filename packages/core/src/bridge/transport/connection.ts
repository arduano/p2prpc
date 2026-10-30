import { yamux } from '@chainsafe/libp2p-yamux';
import { logger } from '@libp2p/logger';
import { AbstractMessageStream } from '@libp2p/utils';
import { P2PError } from '../../errors.js';
import type { QuicBiStream, QuicRecvStream, QuicSendStream } from '../../transport/types.js';
import type { ByteDuplex, LogicalConnection, LogicalConnectionLimits, LogicalConnectionOptions } from './contracts.js';

type Muxer = ReturnType<ReturnType<ReturnType<typeof yamux>>['createStreamMuxer']>;
type Stream = Awaited<ReturnType<Muxer['createStream']>>;
type Bytes = Parameters<AbstractMessageStream['sendData']>[0];
const FRAME_BYTES = 16 * 1024;
const WINDOW_BYTES = 256 * 1024;
const DEFAULTS: LogicalConnectionLimits = {
  maxStreams: 64, maxPendingIncoming: 16, maxReadBytes: 1024 * 1024,
  maxBufferedBytes: 8 * 1024 * 1024, pairTimeoutMs: 15_000
};
const disconnected = () => new P2PError('DISCONNECTED', 'Logical channel closed');
const resource = () => new P2PError('RESOURCE_LIMIT', 'Logical channel resource limit');
const invalid = () => new P2PError('INVALID_FRAME', 'Invalid logical stream header');
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  // Owners may fail before the consumer starts awaiting this operation.
  void promise.catch(() => {});
  return { promise, resolve, reject };
}

/** Bound the standard Yamux decoder's unfinished DATA frame before it buffers
 * attacker-selected uint32 lengths. This is admission only, not another mux. */
class FrameAdmission {
  private readonly header = new Uint8Array(12);
  private used = 0;
  private body = 0;
  inspect(bytes: Uint8Array): void {
    let offset = 0;
    while (offset < bytes.length) {
      if (this.body > 0) {
        const size = Math.min(this.body, bytes.length - offset);
        this.body -= size; offset += size;
        continue;
      }
      const size = Math.min(12 - this.used, bytes.length - offset);
      this.header.set(bytes.subarray(offset, offset + size), this.used);
      this.used += size; offset += size;
      if (this.used !== 12) continue;
      this.used = 0;
      if (this.header[1] === 0) {
        this.body = new DataView(this.header.buffer).getUint32(8);
        if (this.body > 64 * 1024) throw resource();
      }
    }
  }
}

class Carrier extends AbstractMessageStream {
  sent = 0;
  received = 0;
  private writing: Promise<void> = Promise.resolve();
  private closeRequested: Promise<void> | undefined;
  private readonly admission = new FrameAdmission();
  constructor(readonly duplex: ByteDuplex, options: LogicalConnectionOptions, readonly limit: number) {
    super({ log: logger('p2prpc:logical-carrier'), direction: options.side === 'client' ? 'outbound' : 'inbound',
      maxMessageSize: FRAME_BYTES, maxReadBufferLength: limit, maxWriteBufferLength: limit });
  }
  async pump(check: () => void): Promise<void> {
    for await (const bytes of this.duplex.readable) {
      if (!(bytes instanceof Uint8Array) || bytes.length > this.limit) throw resource();
      this.admission.inspect(bytes);
      this.received += bytes.length;
      this.onData(bytes);
      check();
      if (this.status !== 'open') break;
    }
  }
  sendData(data: Bytes) {
    const bytes = data.subarray().slice();
    this.writing = this.duplex.write(bytes);
    void this.writing.then(() => {
      this.sent += bytes.length;
      this.safeDispatchEvent('drain');
    }, (error: unknown) => { this.abort(error instanceof Error ? error : disconnected()); });
    return { sentBytes: bytes.length, canSendMore: false };
  }
  requestClose(error?: Error): Promise<void> {
    this.closeRequested ??= Promise.resolve().then(() => this.duplex.close(error));
    void this.closeRequested.catch(() => {});
    return this.closeRequested;
  }
  sendReset(error: Error): void { void this.requestClose(error); }
  sendPause(): void { /* The owned duplex already backpressures individual writes. */ }
  sendResume(): void {}
  async close(): Promise<void> { await this.writing; await this.requestClose(); await this.duplex.closed; }
}

/** One physical Yamux stream carries only one logical direction. Yamux RST
 * otherwise destroys both halves, and Yamux has no STOP_SENDING operation. */
class Direction implements QuicSendStream, QuicRecvStream {
  private chunks: Uint8Array[] = [];
  private offset = 0;
  queued = 0;
  reservedRead = 0;
  private waiter: ReturnType<typeof deferred<void>> | undefined;
  private reading = false;
  private writing = false;
  private error: Error | undefined;
  private ended = false;
  constructor(readonly raw: Stream, readonly maxRead: number, readonly check: () => void) {
    raw.addEventListener('message', (event) => {
      const bytes = event.data instanceof Uint8Array ? event.data : event.data.subarray();
      this.chunks.push(bytes); this.queued += bytes.length;
      if (raw.readStatus === 'readable') raw.pause();
      this.wake();
      check();
    });
    raw.addEventListener('end', () => { this.ended = true; this.wake(); });
    raw.addEventListener('close', (event) => {
      this.error = event.error;
      if (this.error) { this.chunks = []; this.queued = 0; }
      this.ended = true; this.wake();
    });
  }
  retire(error: Error): void {
    this.error = error; this.chunks = []; this.offset = 0; this.queued = 0; this.ended = true;
    this.wake(); this.raw.abort(error);
  }
  private wake(): void { this.waiter?.resolve(); this.waiter = undefined; }
  private async available(): Promise<void> {
    while (this.queued === 0) {
      if (this.error) throw this.error;
      if (this.raw.readBufferLength > 0 && this.raw.readStatus === 'paused') this.raw.resume();
      if (this.queued > 0) break;
      if (this.ended || this.raw.remoteWriteStatus === 'closed') return;
      this.waiter = deferred<void>();
      if (this.raw.readStatus === 'paused') this.raw.resume();
      if (this.queued > 0 || this.ended || this.error) this.wake();
      await this.waiter?.promise;
    }
    if (this.error) throw this.error;
  }
  async readExact(size: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.maxRead) throw resource();
    if (this.reading) throw new P2PError('REJECTED', 'Concurrent stream read');
    this.reading = true; this.reservedRead = size;
    try {
      this.check();
      if (this.error) throw this.error;
      const result = new Uint8Array(size);
      let done = 0;
      while (done < size) {
        await this.available();
        const chunk = this.chunks[0];
        // Match native exact-read EOF; no complete frame exists to classify as malformed.
        if (!chunk) throw new P2PError('DISCONNECTED', 'Unexpected end of stream');
        const count = Math.min(size - done, chunk.length - this.offset);
        result.set(chunk.subarray(this.offset, this.offset + count), done);
        this.offset += count; this.queued -= count; done += count;
        if (this.offset === chunk.length) { this.chunks.shift(); this.offset = 0; }
        this.check();
      }
      return result;
    } finally { this.reading = false; this.reservedRead = 0; }
  }
  async expectEnd(): Promise<void> {
    if (this.reading) throw new P2PError('REJECTED', 'Concurrent stream read');
    this.reading = true;
    try { await this.available(); if (this.queued !== 0) throw new P2PError('INVALID_FRAME', 'Trailing stream bytes'); }
    finally { this.reading = false; }
  }
  async writeAll(bytes: Uint8Array): Promise<void> {
    if (this.writing) throw new P2PError('REJECTED', 'Concurrent stream write');
    this.writing = true;
    try {
      for (let offset = 0; offset < bytes.length; offset += FRAME_BYTES) {
        if (this.error) throw this.error;
        this.raw.send(bytes.subarray(offset, offset + FRAME_BYTES));
        await this.flush();
        this.check();
      }
    } finally { this.writing = false; }
  }
  private async flush(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        this.raw.removeEventListener('idle', sample);
        this.raw.removeEventListener('drain', sample);
        this.raw.removeEventListener('close', sample);
      };
      const sample = () => {
        // The upstream drain listener first schedules its send-queue processing.
        // Observe the resulting queue, not merely the generic mux drain event.
        queueMicrotask(() => {
          if (this.error || this.raw.status === 'reset' || this.raw.status === 'aborted' || this.raw.status === 'closed') {
            cleanup(); reject(this.error ?? disconnected());
          } else if (this.raw.writeBufferLength === 0 && !this.raw.writableNeedsDrain) {
            cleanup(); resolve();
          }
        });
      };
      this.raw.addEventListener('idle', sample);
      this.raw.addEventListener('drain', sample);
      this.raw.addEventListener('close', sample);
      sample();
    });
  }
  async finish(): Promise<void> { if (this.error) throw this.error; if (this.writing) throw new P2PError('REJECTED', 'Stream write pending'); await this.raw.close(); }
  async reset(code: bigint): Promise<void> { void code; this.raw.abort(new P2PError('CANCELLED', 'Stream reset')); }
  async stop(code: bigint): Promise<void> { void code; this.raw.abort(new P2PError('CANCELLED', 'Stream stopped')); }
  async setPriority(priority: number): Promise<void> {
    if (!Number.isFinite(priority)) throw new P2PError('REJECTED', 'Invalid stream priority');
    // Advisory only: Yamux provides flow control and bounded frames, no priority API.
  }
}

class Incoming<T> {
  private values: T[] = [];
  private waiting: ReturnType<typeof deferred<T>> | undefined;
  private error: Error | undefined;
  constructor(private readonly limit: number) {}
  push(value: T): void {
    if (this.error) throw this.error;
    if (this.waiting) { this.waiting.resolve(value); this.waiting = undefined; return; }
    if (this.values.length >= this.limit) throw resource();
    this.values.push(value);
  }
  take(): Promise<T> {
    if (this.error) return Promise.reject(this.error);
    const value = this.values.shift();
    if (value) return Promise.resolve(value);
    if (this.waiting) return Promise.reject(new P2PError('REJECTED', 'Concurrent stream accept'));
    this.waiting = deferred<T>(); return this.waiting.promise;
  }
  close(error: Error): void { this.error = error; this.values = []; this.waiting?.reject(error); this.waiting = undefined; }
}

function header(kind: number, pair = 0): Uint8Array {
  const bytes = new Uint8Array(5); bytes[0] = kind;
  new DataView(bytes.buffer).setUint32(1, pair); return bytes;
}

export function fromByteDuplex(duplex: ByteDuplex, options: LogicalConnectionOptions): LogicalConnection {
  if (typeof Reflect.get(Promise, 'withResolvers') !== 'function') {
    throw new P2PError('REJECTED', 'Bridge stream transport requires Promise.withResolvers (Node.js 22+ or a modern browser)');
  }
  const limits = { ...DEFAULTS, ...options.limits };
  for (const value of Object.values(limits)) if (!Number.isSafeInteger(value) || value <= 0) throw resource();
  if (!options.remoteId || limits.maxBufferedBytes < WINDOW_BYTES || limits.maxPendingIncoming > limits.maxStreams) throw resource();
  const carrier = new Carrier(duplex, options, limits.maxBufferedBytes);
  const mux = yamux({ enableKeepAlive: false, maxMessageSize: FRAME_BYTES,
    maxInboundStreams: limits.maxStreams * 2, maxOutboundStreams: limits.maxStreams * 2,
    maxEarlyStreams: limits.maxPendingIncoming * 2,
    streamOptions: { initialStreamWindowSize: WINDOW_BYTES, maxStreamWindowSize: WINDOW_BYTES,
      maxReadBufferLength: WINDOW_BYTES, maxWriteBufferLength: FRAME_BYTES * 2, inactivityTimeout: 0 }
  })().createStreamMuxer(carrier);
  const bi = new Incoming<QuicBiStream>(limits.maxPendingIncoming);
  const uni = new Incoming<QuicRecvStream>(limits.maxPendingIncoming);
  const directions = new Map<Stream, Direction>();
  const pairs = new Map<number, { result: ReturnType<typeof deferred<QuicBiStream>>; send: Direction; timer: ReturnType<typeof setTimeout> }>();
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const tasks = new Set<Promise<void>>();
  const terminal = deferred<string>();
  let closing: Error | undefined;
  let active = 0;
  let incomingHeaders = 0;
  const fail = (error: Error): void => {
    if (closing) return;
    closing = error;
    // Own the channel close directly: an upstream abort can throw or return
    // early after its status changed. Neither is terminal carrier evidence.
    void carrier.requestClose(error);
    bi.close(error); uni.close(error);
    for (const timer of timers) clearTimeout(timer);
    timers.clear();
    for (const pair of pairs.values()) { clearTimeout(pair.timer); pair.result.reject(error); }
    pairs.clear();
    // Upstream abort notifications are best effort. Their exceptions cannot
    // veto channel closure or strand pump settlement; duplex.closed is proof.
    for (const direction of directions.values()) { try { direction.retire(error); } catch { /* channel close remains owned */ } }
    directions.clear();
    try { mux.abort(error); } catch { /* channel close remains owned */ }
    try { carrier.abort(error); } catch { /* channel close remains owned */ }
  };
  const check = (): void => {
    let bytes = carrier.writeBufferLength;
    for (const [stream, direction] of directions) {
      bytes += direction.queued + direction.reservedRead + stream.readBufferLength + stream.writeBufferLength;
      if (stream.status !== 'open' && stream.status !== 'closing' && direction.queued === 0 && direction.reservedRead === 0 && stream.readBufferLength === 0) directions.delete(stream);
    }
    if (bytes > limits.maxBufferedBytes) fail(resource());
    if (mux.status === 'closed' && !closing) fail(disconnected());
  };
  const wrap = (raw: Stream): Direction => {
    const direction = new Direction(raw, limits.maxReadBytes, check);
    directions.set(raw, direction);
    raw.addEventListener('close', check, { once: true });
    return direction;
  };
  const create = async (): Promise<Direction> => {
    if (closing) throw closing;
    const raw = await mux.createStream();
    if (closing) { raw.abort(closing); throw closing; }
    if (mux.streams.length > limits.maxStreams * 2) { fail(resource()); throw resource(); }
    const direction = wrap(raw);
    // Each physical stream's reverse direction is reserved to carry only FIN.
    raw.addEventListener('message', () => fail(invalid()));
    return direction;
  };
  const reserve = (): (() => void) => {
    if (closing) throw closing;
    if (active >= limits.maxStreams) throw resource();
    active++;
    let released = false;
    return () => { if (!released) { released = true; active--; } };
  };
  const releaseWhenClosed = (release: () => void, ...raw: Stream[]): void => {
    const sample = () => { if (raw.every(stream => stream.status !== 'open' && stream.status !== 'closing')) release(); };
    for (const stream of raw) stream.addEventListener('close', sample, { once: true });
    sample();
  };
  const track = (task: Promise<void>): void => {
    tasks.add(task); void task.catch((error: unknown) => fail(error instanceof Error ? error : invalid())).finally(() => tasks.delete(task));
  };
  const incoming = async (raw: Stream): Promise<void> => {
    const receive = wrap(raw);
    const timer = setTimeout(() => fail(new P2PError('TIMEOUT', 'Logical stream header timed out')), limits.pairTimeoutMs);
    timers.add(timer);
    let bytes: Uint8Array;
    try { bytes = await receive.readExact(5); }
    finally { clearTimeout(timer); timers.delete(timer); }
    if (closing) throw closing;
    const kind = bytes[0];
    const pairId = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(1);
    // The reverse half of this physical stream is intentionally unused.
    await raw.close();
    if (closing) throw closing;
    if (kind === 2) {
      const pair = pairs.get(pairId);
      if (!pair) throw invalid();
      pairs.delete(pairId); clearTimeout(pair.timer);
      pair.result.resolve({ send: pair.send, recv: receive });
      return;
    }
    if (kind !== 1 && kind !== 3 || kind === 3 && pairId !== 0 || kind === 1 && pairId !== raw.streamId) throw invalid();
    const release = reserve();
    try {
      if (kind === 3) { releaseWhenClosed(release, raw); uni.push(receive); return; }
      const send = await create();
      releaseWhenClosed(release, raw, send.raw);
      await send.writeAll(header(2, pairId));
      bi.push({ send, recv: receive });
    } catch (error) { release(); throw error; }
  };
  mux.addEventListener('stream', event => {
    if (closing || incomingHeaders >= limits.maxPendingIncoming || mux.streams.length > limits.maxStreams * 2) { fail(resource()); return; }
    incomingHeaders++;
    track(incoming(event.detail).finally(() => { incomingHeaders--; }));
  });
  const pump = carrier.pump(check).then(() => fail(disconnected()), (error: unknown) => fail(error instanceof Error ? error : disconnected()));
  void duplex.closed.then(async () => {
    fail(disconnected());
    try { carrier.onTransportClosed(closing); } catch { /* actual carrier closure is independently proved */ }
    await pump;
    await Promise.allSettled([...tasks]);
    terminal.resolve('Logical channel closed');
  }, async () => {
    fail(disconnected());
    try { carrier.onTransportClosed(closing); } catch { /* failed carrier proof remains failed */ }
    await pump; await Promise.allSettled([...tasks]);
    terminal.reject(new P2PError('DISCONNECTED', 'Logical channel closure is unproved'));
  });
  return {
    remoteId: options.remoteId, side: options.side,
    async openBi() {
      const release = reserve();
      let send: Direction | undefined;
      try {
        send = await create();
        const result = deferred<QuicBiStream>();
        const timer = setTimeout(() => {
          pairs.delete(send!.raw.streamId); send!.raw.abort(new P2PError('TIMEOUT', 'Logical stream pair timed out'));
          result.reject(new P2PError('TIMEOUT', 'Logical stream pair timed out')); release();
        }, limits.pairTimeoutMs);
        pairs.set(send.raw.streamId, { result, send, timer });
        await send.writeAll(header(1, send.raw.streamId));
        const stream = await result.promise;
        releaseWhenClosed(release, send.raw, (stream.recv as Direction).raw);
        return stream;
      } catch (error) { send?.raw.abort(error instanceof Error ? error : disconnected()); release(); throw error; }
    },
    acceptBi: () => bi.take(),
    async openUni() {
      const release = reserve();
      let send: Direction | undefined;
      try {
        send = await create(); releaseWhenClosed(release, send.raw);
        await send.writeAll(header(3)); return send;
      } catch (error) { send?.raw.abort(error instanceof Error ? error : disconnected()); release(); throw error; }
    },
    acceptUni: () => uni.take(),
    closed: () => terminal.promise,
    close: () => fail(new P2PError('CANCELLED', 'Logical channel closed locally')),
    async stats() { const rtt = mux.getRTT(); return { rttMs: rtt < 0 ? null : rtt, sentBytes: carrier.sent, receivedBytes: carrier.received, lostPackets: 0 }; }
  };
}
