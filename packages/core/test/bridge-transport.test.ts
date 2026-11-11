import { describe, expect, it, vi } from 'vitest';
import { AbstractStreamMuxer } from '@libp2p/utils';
import { ManagedConnection } from '../src/runtime/managed-connection.js';
import { DEFAULT_RESOURCE_LIMITS, ResourceScheduler } from '../src/runtime/resources.js';
import { fromByteDuplex } from '../src/bridge/transport/connection.js';
import { webSocketDuplex } from '../src/bridge/transport/websocket.js';
import type { BinaryWebSocket, ByteDuplex } from '../src/bridge/transport/contracts.js';

function carrierPair(): [ByteDuplex, ByteDuplex] {
  const queues: Uint8Array[][] = [[], []];
  const wakes: Array<(() => void) | undefined> = [undefined, undefined];
  const ends: Array<() => void> = [];
  let closed = false;
  const terminal = new Promise<void>(resolve => ends.push(resolve));
  const close = () => { closed = true; for (const wake of wakes) wake?.(); for (const end of ends) end(); };
  const make = (side: number): ByteDuplex => ({
    readable: {
      async *[Symbol.asyncIterator]() {
        while (!closed) {
          const bytes = queues[side]!.shift();
          if (bytes) { yield bytes; continue; }
          await new Promise<void>(resolve => { wakes[side] = resolve; });
        }
      }
    },
    async write(bytes: Uint8Array) {
      if (closed) throw new Error('closed');
      // Real byte carriers may split or coalesce Yamux headers arbitrarily.
      const next = 1 - side;
      for (let offset = 0; offset < bytes.length; offset += 4093) queues[next]!.push(bytes.slice(offset, offset + 4093));
      wakes[next]?.(); wakes[next] = undefined;
    }, close, closed: terminal
  });
  return [make(0), make(1)];
}

function connections() {
  const [a, b] = carrierPair();
  return [fromByteDuplex(a, { remoteId: 'authorized-b', side: 'client' }),
    fromByteDuplex(b, { remoteId: 'authorized-a', side: 'server' })] as const;
}
const text = new TextEncoder();

// Yamux8 uses Promise.withResolvers. The optional bridge requires Node22+;
// the existing native entry keeps its separately qualified Node20.3 floor.
const yamuxAvailable = typeof Reflect.get(Promise, 'withResolvers') === 'function';

describe.skipIf(!yamuxAvailable)('logical Yamux carrier', () => {
  it('preserves independent bidi reset/stop, FIN and unrelated uni streams', async () => {
    const [a, b] = connections();
    try {
      const outgoing = await a.openBi();
      const incoming = await b.acceptBi();
      await outgoing.send.writeAll(text.encode('request'));
      expect(await incoming.recv.readExact(7)).toEqual(text.encode('request'));
      await incoming.recv.stop(1n);
      await new Promise(resolve => setTimeout(resolve, 0));
      await expect(outgoing.send.writeAll(text.encode('rejected'))).rejects.toBeDefined();
      // STOP_SENDING for request direction must not reset the response direction.
      await incoming.send.writeAll(text.encode('response'));
      await incoming.send.finish();
      expect(await outgoing.recv.readExact(8)).toEqual(text.encode('response'));
      await outgoing.recv.expectEnd();
      const send = await b.openUni();
      const receive = await a.acceptUni();
      await send.writeAll(text.encode('independent'));
      await send.finish();
      expect(await receive.readExact(11)).toEqual(text.encode('independent'));
      await receive.expectEnd();
    } finally { a.close(0n, new Uint8Array()); await Promise.all([a.closed(), b.closed()]); }
  });

  it.each(['readExact', 'expectEnd'] as const)('preserves carrier failure between %s readiness and consumption', async method => {
    const [client, server] = connections();
    try {
      const outgoing = await client.openBi();
      const incoming = await server.acceptBi();
      await outgoing.send.writeAll(Uint8Array.of(1, 2));
      expect(await incoming.recv.readExact(1)).toEqual(Uint8Array.of(1));
      // Readiness is already fulfilled; the continuation has not consumed it.
      const pending = method === 'readExact' ? incoming.recv.readExact(1) : incoming.recv.expectEnd();
      server.close(0n, new Uint8Array());
      await expect(pending).rejects.toMatchObject({ code: 'CANCELLED', message: 'Logical channel closed locally' });
    } finally { server.close(0n, new Uint8Array()); await Promise.all([client.closed(), server.closed()]); }
  });

  it('pairs a full concurrent opening burst without an extra header or accept-queue ceiling', async () => {
    const [a, b] = connections();
    try {
      const outgoing = await Promise.all(Array.from({ length: 64 }, () => a.openBi()));
      const incoming = [];
      for (let index = 0; index < outgoing.length; index++) incoming.push(await b.acceptBi());
      await expect(a.openBi()).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
      await Promise.all(outgoing.map((stream, index) => stream.send.writeAll(Uint8Array.of(index))));
      await Promise.all(incoming.map(async stream => stream.send.writeAll(await stream.recv.readExact(1))));
      expect(await Promise.all(outgoing.map(async stream => (await stream.recv.readExact(1))[0])))
        .toEqual(Array.from({ length: 64 }, (_, index) => index));
    } finally { a.close(0n, new Uint8Array()); await Promise.all([a.closed(), b.closed()]); }
  });

  it('refuses only an excess opening, preserves an established managed stream and reuses the released slot', async () => {
    const [clientRaw, serverRaw] = carrierPair();
    const raw = fromByteDuplex(clientRaw, { remoteId: 'server', side: 'client', limits: { maxStreams: 4, pairTimeoutMs: 2000 } });
    const server = fromByteDuplex(serverRaw, { remoteId: 'client', side: 'server', limits: { maxStreams: 1 } });
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const client = new ManagedConnection(raw, scheduler, { peerId: 'server' }, new AbortController().signal, 1024, 1024);
    try {
      const first = await client.openBi();
      const accepted = await server.acceptBi();
      await expect(client.openBi()).rejects.toMatchObject({ code: 'REJECTED' });
      expect(scheduler.snapshot().active.streams).toBe(1);
      await first.send.writeAll(text.encode('still open'));
      expect(await accepted.recv.readExact(10)).toEqual(text.encode('still open'));
      await first.send.finish(); await accepted.recv.expectEnd();
      await accepted.send.finish(); await first.recv.expectEnd();
      await scheduler.whenIdle();
      const next = await client.openBi();
      const nextAccepted = await server.acceptBi();
      await nextAccepted.send.writeAll(text.encode('reused'));
      expect(await next.recv.readExact(6)).toEqual(text.encode('reused'));
    } finally { client.close(0n, new Uint8Array()); await Promise.all([client.closed(), server.closed()]); await scheduler.whenIdle(); }
  });

  it('keeps closed-but-unconsumed entries charged until accept transfers their ownership', async () => {
    const [clientRaw, serverRaw] = carrierPair();
    const client = fromByteDuplex(clientRaw, { remoteId: 'server', side: 'client', limits: { maxStreams: 4 } });
    const server = fromByteDuplex(serverRaw, { remoteId: 'client', side: 'server', limits: { maxStreams: 1 } });
    try {
      const first = await client.openUni();
      await first.finish();
      await expect(client.openBi()).rejects.toMatchObject({ code: 'REJECTED' });
      const queued = await server.acceptUni();
      await queued.expectEnd();
      const next = await client.openBi();
      const incoming = await server.acceptBi();
      await next.send.writeAll(text.encode('ok'));
      expect(await incoming.recv.readExact(2)).toEqual(text.encode('ok'));
    } finally { client.close(0n, new Uint8Array()); await Promise.all([client.closed(), server.closed()]); }
  });

  it('backpressures an unread bulk direction while a separate stream progresses, then reaps quiet waiters', async () => {
    const [a, b] = connections();
    try {
      const bulk = await a.openUni();
      const sink = await b.acceptUni();
      const payload = new Uint8Array(512 * 1024).fill(9);
      let completed = false;
      const writing = bulk.writeAll(payload).then(() => { completed = true; });
      void writing.catch(() => {});
      await new Promise(resolve => setTimeout(resolve, 20));
      expect(completed).toBe(false);
      const control = await a.openBi();
      const peerControl = await b.acceptBi();
      await control.send.writeAll(text.encode('ok'));
      expect(await peerControl.recv.readExact(2)).toEqual(text.encode('ok'));
      expect(await sink.readExact(payload.length)).toEqual(payload);
      await writing;
      await bulk.finish(); await sink.expectEnd();
      const quietRead = peerControl.recv.readExact(1);
      const quietAccept = b.acceptUni();
      a.close(0n, new Uint8Array());
      await expect(quietRead).rejects.toBeDefined();
      await expect(quietAccept).rejects.toBeDefined();
      await Promise.all([a.closed(), b.closed()]);
    } finally { a.close(0n, new Uint8Array()); await Promise.all([a.closed(), b.closed()]); }
  });

  it('rejects oversized standard frames and finite unpaired header reservations', async () => {
    const [raw, hostile] = carrierPair();
    const connection = fromByteDuplex(raw, { remoteId: 'verified', side: 'server', limits: { pairTimeoutMs: 25 } });
    const pending = connection.acceptBi();
    const header = new Uint8Array(12);
    new DataView(header.buffer).setUint32(8, 0xffff_ffff);
    await hostile.write(header);
    await expect(pending).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await connection.closed();

    const [aRaw, bRaw] = carrierPair();
    const waiting = fromByteDuplex(aRaw, { remoteId: 'verified', side: 'client', limits: { pairTimeoutMs: 25 } });
    // Peer deliberately never constructs its mux or returns the BI pair.
    const unopened = waiting.openBi();
    await expect(unopened).rejects.toMatchObject({ code: 'TIMEOUT' });
    waiting.close(0n, new Uint8Array()); await bRaw.close(); await waiting.closed();
  });
});

it.skipIf(!yamuxAvailable)('closes its owned carrier even if upstream teardown throws, without inventing closure proof', async () => {
  let finish!: () => void;
  let finishRead!: () => void;
  let closeRequests = 0;
  const reading = new Promise<void>(resolve => { finishRead = resolve; });
  const carrier: ByteDuplex = {
    readable: { async *[Symbol.asyncIterator]() { await reading; yield* []; } },
    async write() {}, close() { closeRequests++; },
    closed: new Promise<void>(resolve => { finish = resolve; })
  };
  const connection = fromByteDuplex(carrier, { remoteId: 'verified', side: 'client' });
  const brokenAbort = vi.spyOn(AbstractStreamMuxer.prototype, 'abort').mockImplementationOnce(() => {
    throw new Error('upstream teardown failed');
  });
  let proved = false;
  void connection.closed().then(() => { proved = true; });
  try {
    expect(() => connection.close(0n, new Uint8Array())).not.toThrow();
    await Promise.resolve();
    expect(closeRequests).toBe(1);
    expect(proved).toBe(false);
  } finally {
    brokenAbort.mockRestore();
    finishRead(); finish();
    await connection.closed();
  }
});

it.skipIf(!yamuxAvailable)('does not turn a rejected carrier cleanup proof into positive logical closure', async () => {
  let reject!: (reason: Error) => void;
  const carrier: ByteDuplex = {
    readable: { async *[Symbol.asyncIterator]() { /* no remaining captured bytes */ } },
    async write() {}, close() {},
    closed: new Promise<void>((_resolve, no) => { reject = no; })
  };
  const connection = fromByteDuplex(carrier, { remoteId: 'verified', side: 'client' });
  reject(new Error('carrier cleanup could not be proved'));
  await expect(connection.closed()).rejects.toMatchObject({ code: 'DISCONNECTED', message: 'Logical channel closure is unproved' });
});

class Socket implements BinaryWebSocket {
  readyState = 1;
  bufferedAmount = 0;
  binaryType = '';
  sent: Uint8Array[] = [];
  private messages = new Set<(event: { data: unknown }) => void>();
  private events = new Map<string, Set<() => void>>();
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
  addEventListener(type: string, listener: ((event: { data: unknown }) => void) | (() => void)): void {
    if (type === 'message') this.messages.add(listener);
    else {
      const events = this.events.get(type) ?? new Set();
      events.add(listener as () => void); this.events.set(type, events);
    }
  }
  removeEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
  removeEventListener(type: string, listener: ((event: { data: unknown }) => void) | (() => void)): void {
    if (type === 'message') this.messages.delete(listener);
    else this.events.get(type)?.delete(listener as () => void);
  }
  send(bytes: Uint8Array): void { this.sent.push(bytes.slice()); }
  close(code = 1000): void {
    // Browser WebSocket.close permits only1000 or application codes3000–4999.
    if (code !== 1000 && (code < 3000 || code > 4999)) throw new Error('Invalid WebSocket close code');
    this.readyState = 3; for (const listener of this.events.get('close') ?? []) listener();
  }
  message(data: unknown): void { for (const listener of this.messages) listener({ data }); }
}

it('WebSocket binary carrier bounds admission and closes from actual socket evidence', async () => {
  const socket = new Socket();
  const carrier = webSocketDuplex(socket, { maxBufferedBytes: 16, maxMessageBytes: 8 });
  const reader = carrier.readable[Symbol.asyncIterator]();
  socket.message(Uint8Array.of(1, 2).buffer);
  expect((await reader.next()).value).toEqual(Uint8Array.of(1, 2));
  await carrier.write(Uint8Array.of(3));
  expect(socket.sent).toEqual([Uint8Array.of(3)]);
  await expect(carrier.write(new Uint8Array(9))).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
  socket.message('text is not a byte frame');
  await expect(reader.next()).rejects.toMatchObject({ code: 'INVALID_FRAME' });
  await carrier.closed;
  expect(socket.readyState).toBe(3);
});


it('fills only the bounded WebSocket buffer without polling after every accepted frame', async () => {
  vi.useFakeTimers();
  const frameBytes = 16 * 1024;
  const capacity = 8 * frameBytes;
  const socket = new Socket();
  let peak = 0;
  socket.send = bytes => {
    socket.bufferedAmount += bytes.length;
    peak = Math.max(peak, socket.bufferedAmount);
  };
  const carrier = webSocketDuplex(socket, { maxBufferedBytes: capacity, maxMessageBytes: frameBytes });
  let pending: Promise<void> | undefined;
  try {
    const start = Date.now();
    for (let index = 0; index < 8; index++) await carrier.write(new Uint8Array(frameBytes));
    expect(Date.now()).toBe(start);
    expect(socket.bufferedAmount).toBe(capacity);
    let accepted = false;
    pending = carrier.write(new Uint8Array(frameBytes)).then(() => { accepted = true; });
    await vi.advanceTimersByTimeAsync(8);
    expect(accepted).toBe(false);
    expect(peak).toBe(capacity);
    socket.bufferedAmount -= frameBytes;
    await vi.advanceTimersByTimeAsync(8);
    await pending;
    expect(accepted).toBe(true);
    expect(peak).toBe(capacity);
    pending = carrier.write(new Uint8Array(frameBytes));
    const cancelled = expect(pending).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await Promise.resolve();
    carrier.close();
    await vi.advanceTimersByTimeAsync(8);
    await cancelled;
    await carrier.closed;
  } finally {
    carrier.close();
    await vi.runAllTimersAsync();
    await pending?.catch(() => {});
    vi.useRealTimers();
  }
});
