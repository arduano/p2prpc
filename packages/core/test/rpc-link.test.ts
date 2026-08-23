import { createTRPCProxyClient } from '@trpc/client';
import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import { RpcFrameKind, readFrame, writeFrame } from '../src/protocol.js';
import { irohLink } from '../src/rpc/link.js';
import { serializeValue, type RpcRequest } from '../src/rpc/wire.js';
import type {
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicRecvStream,
  QuicSendStream
} from '../src/transport/types.js';

const t = initTRPC.create();
const router = t.router({
  ping: t.procedure.query(() => 'unused')
});
void router;

describe('RPC link flow-control boundaries', () => {
  it('rejects invalid I/O deadlines at link construction', () => {
    for (const ioTimeoutMs of [0, 0.5, 10 * 60_000 + 1, Number.NaN]) {
      expect(() => irohLink({ connection: pending, ioTimeoutMs })).toThrow(/I\/O timeout/);
    }
  });

  it('does not invoke deferred header or connection work after synchronous cancellation', async () => {
    let headerCalls = 0;
    let connectionCalls = 0;
    const controller = new AbortController();
    const client = testClient({
      connection: async () => {
        connectionCalls += 1;
        return testConnection(pending);
      },
      getRequestHeaders: () => {
        headerCalls += 1;
        return {};
      }
    });
    const result = client.ping.query(undefined, { signal: controller.signal });
    controller.abort();

    await expect(result).rejects.toBeDefined();
    expect(headerCalls).toBe(0);
    expect(connectionCalls).toBe(0);
  });

  it('times out header generation before acquiring a connection and aborts its signal', async () => {
    let connectionCalls = 0;
    let headerSignal: AbortSignal | undefined;
    let headerRequestFrozen = false;
    const client = testClient({
      connection: async () => {
        connectionCalls += 1;
        throw new Error('must not connect');
      },
      getRequestHeaders: (request) => {
        headerSignal = request.signal;
        headerRequestFrozen = Object.isFrozen(request);
        return pending();
      }
    });

    await expect(client.ping.query()).rejects.toThrow('RPC request headers timed out');
    expect(headerSignal?.aborted).toBe(true);
    expect(headerRequestFrozen).toBe(true);
    expect(connectionCalls).toBe(0);
  });

  it('snapshots manually supplied per-call headers before awaiting defaults', async () => {
    const defaults = deferred<Record<string, string>>();
    const stream = testStream();
    let receivedHeaders: RpcRequest['headers'] | undefined;
    stream.send.afterWrite = async (index, bytes) => {
      if (index !== 3) return;
      const requestFrame = await readFrame<RpcRequest>(new BufferedRecv(bytes.slice(1)));
      receivedHeaders = requestFrame.value.headers;
      await writeFrame(stream.recv, RpcFrameKind.Data, {
        id: requestFrame.value.id,
        data: serializeValue('pong')
      });
      await writeFrame(stream.recv, RpcFrameKind.Complete, { id: requestFrame.value.id });
    };
    const client = testClient({
      connection: async () => testConnection(async () => stream),
      getRequestHeaders: () => defaults.promise
    });
    const headers: Record<string, string> = { 'X-Tenant': 'tenant-a' };
    const result = client.ping.query(undefined, { context: { p2prpc: { headers } } });

    headers['X-Tenant'] = 'tenant-b';
    defaults.resolve({});

    await expect(result).resolves.toBe('pong');
    expect(receivedHeaders).toEqual({ 'x-tenant': 'tenant-a' });
  });

  it('bounds stalled connection acquisition', async () => {
    const client = testClient({ connection: pending });
    await expect(client.ping.query()).rejects.toThrow('RPC connection acquisition timed out');
  });

  it('cleans up a stream that arrives after openBi timed out', async () => {
    const opened = deferred<QuicBiStream>();
    const stream = testStream();
    const client = testClient({ connection: async () => testConnection(() => opened.promise) });

    await expect(client.ping.query()).rejects.toThrow('RPC stream opening timed out');
    opened.resolve(stream);
    await waitUntil(() => stream.send.resetCalls === 1 && stream.recv.stopCalls === 1);
  });

  it('bounds stalled stream-priority setup and closes both stream halves', async () => {
    const stream = testStream({ priority: pending });
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).rejects.toThrow('RPC stream priority timed out');
    expect(stream.send.writeCalls).toBe(0);
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('bounds a flow-control-stalled request write', async () => {
    const stalled = deferred<void>();
    const stream = testStream({
      write: (index) => index === 2 ? stalled.promise : Promise.resolve(),
      reset: () => stalled.resolve()
    });
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).rejects.toThrow('RPC request write timed out');
    expect(stream.send.writeCalls).toBe(2);
    expect(stream.send.maximumConcurrentWrites).toBe(1);
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('never interleaves Cancel with a request write that is still in progress', async () => {
    const stalled = deferred<void>();
    const writeStarted = deferred<void>();
    const stream = testStream({
      write: (index) => {
        if (index !== 2) return Promise.resolve();
        writeStarted.resolve();
        return stalled.promise;
      },
      reset: () => stalled.resolve()
    });
    const controller = new AbortController();
    const client = testClient({
      connection: async () => testConnection(async () => stream),
      ioTimeoutMs: 1_000
    });
    const result = client.ping.query(undefined, { signal: controller.signal });

    await writeStarted.promise;
    controller.abort();
    await expect(result).rejects.toBeDefined();
    await waitUntil(() => stream.send.resetCalls === 1 && stream.recv.stopCalls === 1);
    expect(stream.send.writeCalls).toBe(2);
    expect(stream.send.maximumConcurrentWrites).toBe(1);
  });

  it('sends Cancel only after the complete request and then resets the stream', async () => {
    const stream = testStream();
    const controller = new AbortController();
    const client = testClient({ connection: async () => testConnection(async () => stream) });
    const result = client.ping.query(undefined, { signal: controller.signal });

    await waitUntil(() => stream.send.writeCalls === 3);
    controller.abort();
    await expect(result).rejects.toBeDefined();
    expect(stream.send.writeCalls).toBe(5);
    expect(stream.send.maximumConcurrentWrites).toBe(1);
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('resets a stalled cancellation write without attempting its frame body afterward', async () => {
    const stalled = deferred<void>();
    const stream = testStream({
      write: (index) => index === 4 ? stalled.promise : Promise.resolve(),
      reset: () => stalled.resolve()
    });
    const controller = new AbortController();
    const client = testClient({ connection: async () => testConnection(async () => stream) });
    const result = client.ping.query(undefined, { signal: controller.signal });

    await waitUntil(() => stream.send.writeCalls === 3);
    controller.abort();
    await expect(result).rejects.toBeDefined();
    await waitUntil(() => stream.send.resetCalls === 1);
    expect(stream.send.writeCalls).toBe(4);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('bounds a stalled response read and releases both stream halves', async () => {
    const stream = testStream();
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).rejects.toThrow('RPC response frame timed out');
    expect(stream.send.writeCalls).toBe(3);
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('finishes normally without emitting a cancellation frame', async () => {
    const stream = testStream();
    respondWithPong(stream);
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).resolves.toBe('pong');
    expect(stream.send.writeCalls).toBe(3);
    expect(stream.send.finishCalls).toBe(1);
    expect(stream.send.resetCalls).toBe(0);
    expect(stream.recv.expectEndCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('rejects trailing bytes after an RPC completion frame', async () => {
    const stream = testStream();
    stream.send.afterWrite = async (index, bytes) => {
      if (index !== 3) return;
      const requestFrame = await readFrame<RpcRequest>(new BufferedRecv(bytes.slice(1)));
      await writeFrame(stream.recv, RpcFrameKind.Data, {
        id: requestFrame.value.id,
        data: serializeValue('pong')
      });
      await writeFrame(stream.recv, RpcFrameKind.Complete, { id: requestFrame.value.id });
      await stream.recv.writeAll(Uint8Array.of(0xff));
    };
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).rejects.toThrow('Trailing bytes');
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.expectEndCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('rejects a unary completion without a result frame', async () => {
    const stream = testStream();
    stream.send.afterWrite = async (index, bytes) => {
      if (index !== 3) return;
      const requestFrame = await readFrame<RpcRequest>(new BufferedRecv(bytes.slice(1)));
      await writeFrame(stream.recv, RpcFrameKind.Complete, { id: requestFrame.value.id });
    };
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).rejects.toThrow('Unary RPC completed without a result');
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('bounds and sanitizes an authenticated peer\'s error message', async () => {
    const stream = testStream();
    stream.send.afterWrite = async (index, bytes) => {
      if (index !== 3) return;
      const requestFrame = await readFrame<RpcRequest>(new BufferedRecv(bytes.slice(1)));
      await writeFrame(stream.recv, RpcFrameKind.Error, {
        id: requestFrame.value.id,
        shape: { message: `bad\r\n\u0085\u202e${'é'.repeat(8_192)}` }
      });
    };
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    const outcome: unknown = await client.ping.query().catch((cause: unknown) => cause);
    expect(outcome).toBeInstanceOf(Error);
    if (!(outcome instanceof Error)) throw new Error('Expected the remote RPC to fail');
    expect(outcome.message).not.toMatch(/[\r\n\u0085\u202e]/u);
    expect(outcome.message).toContain('bad????');
    expect(Buffer.byteLength(outcome.message)).toBeLessThanOrEqual(8 * 1024);
  });

  it('bounds terminal finish cleanup and falls back to reset', async () => {
    const stalled = deferred<void>();
    const stream = testStream({
      finish: () => stalled.promise,
      reset: () => stalled.resolve()
    });
    respondWithPong(stream);
    const client = testClient({ connection: async () => testConnection(async () => stream) });

    await expect(client.ping.query()).resolves.toBe('pong');
    expect(stream.send.finishCalls).toBe(1);
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });
});

function testClient(options: {
  connection: () => Promise<QuicConnection>;
  ioTimeoutMs?: number;
  getRequestHeaders?: Parameters<typeof irohLink>[0]['getRequestHeaders'];
}) {
  return createTRPCProxyClient<typeof router>({
    links: [irohLink({
      connection: options.connection,
      ioTimeoutMs: options.ioTimeoutMs ?? 20,
      ...(options.getRequestHeaders ? { getRequestHeaders: options.getRequestHeaders } : {})
    })]
  });
}

function testConnection(openBi: () => Promise<QuicBiStream>): QuicConnection {
  return {
    remoteId: 'remote',
    side: 'client',
    openBi,
    acceptBi: pending,
    openUni: pending,
    acceptUni: pending,
    closed: pending,
    close: () => undefined,
    stats: async (): Promise<ConnectionStats> => ({
      rttMs: null,
      sentBytes: 0,
      receivedBytes: 0,
      lostPackets: 0
    }),
    configure: () => undefined
  };
}

function testStream(options: {
  priority?: () => Promise<void>;
  write?: (index: number, data: Uint8Array) => Promise<void>;
  finish?: () => Promise<void>;
  reset?: () => void;
} = {}): { send: RecordingSend; recv: BufferedRecv } {
  return {
    send: new RecordingSend(options),
    recv: new BufferedRecv()
  };
}

function respondWithPong(stream: { send: RecordingSend; recv: BufferedRecv }): void {
  stream.send.afterWrite = async (index, bytes) => {
    if (index !== 3) return;
    const requestFrame = await readFrame<RpcRequest>(new BufferedRecv(bytes.slice(1)));
    await writeFrame(stream.recv, RpcFrameKind.Data, {
      id: requestFrame.value.id,
      data: serializeValue('pong')
    });
    await writeFrame(stream.recv, RpcFrameKind.Complete, { id: requestFrame.value.id });
  };
}

class RecordingSend implements QuicSendStream {
  readonly bytes: number[] = [];
  writeCalls = 0;
  finishCalls = 0;
  resetCalls = 0;
  maximumConcurrentWrites = 0;
  afterWrite?: (index: number, bytes: readonly number[]) => Promise<void>;
  private concurrentWrites = 0;

  constructor(private readonly options: {
    priority?: () => Promise<void>;
    write?: (index: number, data: Uint8Array) => Promise<void>;
    finish?: () => Promise<void>;
    reset?: () => void;
  }) {}

  async writeAll(data: Uint8Array): Promise<void> {
    this.writeCalls += 1;
    const index = this.writeCalls;
    this.concurrentWrites += 1;
    this.maximumConcurrentWrites = Math.max(this.maximumConcurrentWrites, this.concurrentWrites);
    this.bytes.push(...data);
    try {
      await this.options.write?.(index, data);
      await this.afterWrite?.(index, this.bytes);
    } finally {
      this.concurrentWrites -= 1;
    }
  }

  async finish(): Promise<void> {
    this.finishCalls += 1;
    await this.options.finish?.();
  }

  async reset(): Promise<void> {
    this.resetCalls += 1;
    this.options.reset?.();
  }

  async setPriority(): Promise<void> {
    await this.options.priority?.();
  }
}

class BufferedRecv implements QuicRecvStream, QuicSendStream {
  stopCalls = 0;
  expectEndCalls = 0;
  private readonly bytes: number[];
  private readonly waiters: Array<{
    readonly size: number;
    readonly resolve: (data: Uint8Array) => void;
    readonly reject: (cause: unknown) => void;
  }> = [];

  constructor(bytes: Iterable<number> = []) {
    this.bytes = [...bytes];
  }

  async readExact(size: number): Promise<Uint8Array> {
    if (this.bytes.length >= size) return Uint8Array.from(this.bytes.splice(0, size));
    return new Promise<Uint8Array>((resolve, reject) => this.waiters.push({ size, resolve, reject }));
  }

  async writeAll(data: Uint8Array): Promise<void> {
    this.bytes.push(...data);
    this.flush();
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    for (const waiter of this.waiters.splice(0)) waiter.reject(new Error('Stopped'));
  }

  async expectEnd(): Promise<void> {
    this.expectEndCalls += 1;
    if (this.bytes.length !== 0) throw new Error('Trailing bytes');
  }

  async finish(): Promise<void> {}
  async reset(): Promise<void> { await this.stop(); }
  async setPriority(): Promise<void> {}

  private flush(): void {
    for (let index = 0; index < this.waiters.length;) {
      const waiter = this.waiters[index]!;
      if (this.bytes.length < waiter.size) {
        index += 1;
        continue;
      }
      this.waiters.splice(index, 1);
      waiter.resolve(Uint8Array.from(this.bytes.splice(0, waiter.size)));
    }
  }
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => {
    resolve = accept;
  });
  return { promise, resolve };
}

function pending<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  const deadline = Date.now() + 1_000;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('Timed out waiting for cleanup');
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}
