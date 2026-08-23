import { initTRPC, TRPCError } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import { RpcFrameKind, readFrame, writeFrame } from '../src/protocol.js';
import { RpcServer, safeErrorShape } from '../src/rpc/server.js';
import { serializeValue, type RpcFailure, type RpcRequest } from '../src/rpc/wire.js';
import type { QuicRecvStream, QuicSendStream } from '../src/transport/types.js';

class RecordingSend implements QuicSendStream {
  readonly bytes: number[] = [];
  priorityCalls = 0;
  finishCalls = 0;
  resetCalls = 0;
  async writeAll(data: Uint8Array): Promise<void> { this.bytes.push(...data); }
  async finish(): Promise<void> { this.finishCalls += 1; }
  async reset(): Promise<void> { this.resetCalls += 1; }
  async setPriority(): Promise<void> { this.priorityCalls += 1; }
}

class BufferedRecv implements QuicRecvStream {
  private readonly bytes: number[];
  stopCalls = 0;
  constructor(bytes: Iterable<number>, private readonly waitAtEof = false) {
    this.bytes = [...bytes];
  }
  async readExact(size: number): Promise<Uint8Array> {
    if (this.bytes.length >= size) return Uint8Array.from(this.bytes.splice(0, size));
    if (this.waitAtEof) return new Promise(() => undefined);
    throw new Error('EOF');
  }
  async expectEnd(): Promise<void> {
    if (this.bytes.length !== 0) throw new Error('Trailing bytes');
  }
  async stop(): Promise<void> { this.stopCalls += 1; }
}

class StalledPrioritySend extends RecordingSend {
  override async setPriority(): Promise<void> {
    this.priorityCalls += 1;
    return new Promise(() => undefined);
  }
}

class StalledWriteSend extends RecordingSend {
  override async writeAll(): Promise<void> {
    return new Promise(() => undefined);
  }
}

class StalledFinishSend extends RecordingSend {
  override async finish(): Promise<void> {
    this.finishCalls += 1;
    return new Promise(() => undefined);
  }
}

class StalledRecv implements QuicRecvStream {
  stopCalls = 0;
  async readExact(): Promise<Uint8Array> { return new Promise(() => undefined); }
  async expectEnd(): Promise<void> { return new Promise(() => undefined); }
  async stop(): Promise<void> { this.stopCalls += 1; }
}

class AsyncByteRecv implements QuicRecvStream {
  private readonly bytes: number[];
  private pending: {
    readonly size: number;
    readonly resolve: (value: Uint8Array) => void;
    readonly reject: (error: Error) => void;
  } | undefined;
  stopCalls = 0;

  constructor(bytes: Iterable<number>) {
    this.bytes = [...bytes];
  }

  readExact(size: number): Promise<Uint8Array> {
    if (this.pending) return Promise.reject(new Error('Concurrent reads are not supported by this test stream'));
    if (this.bytes.length >= size) return Promise.resolve(Uint8Array.from(this.bytes.splice(0, size)));
    return new Promise<Uint8Array>((resolve, reject) => {
      this.pending = { size, resolve, reject };
    });
  }

  push(bytes: Iterable<number>): void {
    this.bytes.push(...bytes);
    const pending = this.pending;
    if (!pending || this.bytes.length < pending.size) return;
    this.pending = undefined;
    pending.resolve(Uint8Array.from(this.bytes.splice(0, pending.size)));
  }

  async expectEnd(): Promise<void> {
    if (this.bytes.length !== 0 || this.pending) throw new Error('Trailing or pending bytes');
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    const pending = this.pending;
    this.pending = undefined;
    pending?.reject(new Error('Stream stopped'));
  }

  get hasPendingRead(): boolean {
    return this.pending !== undefined;
  }
}

async function requestBytes(request: RpcRequest): Promise<number[]> {
  return frameBytes(RpcFrameKind.Request, request);
}

async function frameBytes(kind: RpcFrameKind, value: unknown): Promise<number[]> {
  const send = new RecordingSend();
  await writeFrame(send, kind, value);
  return send.bytes;
}

describe('RPC server security boundaries', () => {
  it('rejects invalid setup and I/O deadlines at server construction', () => {
    const t = initTRPC.create();
    const router = t.router({ ok: t.procedure.query(() => 'ok') });
    const options = {
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256
    };
    expect(() => new RpcServer({ ...options, setupTimeoutMs: 0 })).toThrow(/setup timeout/);
    expect(() => new RpcServer({ ...options, setupTimeoutMs: 10, ioTimeoutMs: Number.NaN })).toThrow(/I\/O timeout/);
  });

  it('bounds and sanitizes public tRPC error messages', () => {
    const shape = safeErrorShape(
      new TRPCError({ code: 'BAD_REQUEST', message: `bad\r\n\u0085\u202e${'é'.repeat(8_192)}` }),
      'input.validate'
    ) as { message: string };
    expect(shape.message).not.toMatch(/[\r\n\u0085\u202e]/u);
    expect(shape.message).toContain('bad????');
    expect(Buffer.byteLength(shape.message)).toBeLessThanOrEqual(8 * 1024);
  });

  it('fails closed when a malformed tRPC error carries an untrusted code', () => {
    const secret = 'mutated-error-code-secret';
    const error = new TRPCError({ code: 'BAD_REQUEST', message: secret });
    (error as unknown as { code: string }).code = secret;
    expect(JSON.stringify(safeErrorShape(error, 'input.validate'))).not.toContain(secret);
    expect(safeErrorShape(error, 'input.validate')).toMatchObject({
      message: 'Internal server error',
      data: { code: 'INTERNAL_SERVER_ERROR', httpStatus: 500 }
    });
  });

  it('does not expose values injected by a router error formatter', async () => {
    const secret = 'formatter-secret-must-not-cross-the-wire';
    const t = initTRPC.create({
      errorFormatter() {
        return {
          code: secret,
          message: secret,
          data: { code: secret, httpStatus: secret, path: secret },
          custom: secret
        } as never;
      }
    });
    const router = t.router({
      fail: t.procedure.query(() => {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Public validation failure' });
      })
    });
    const output = new RecordingSend();
    const input = new BufferedRecv(await requestBytes({
      id: 7,
      path: 'fail',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    }), true);
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 1_000,
      onError(error) {
        error.message = secret;
        throw new Error(secret);
      }
    });

    await server.handle({ send: output, recv: input });

    const frame = await readFrame<RpcFailure>(new BufferedRecv(output.bytes));
    expect(frame.kind).toBe(RpcFrameKind.Error);
    expect(JSON.stringify(frame.value)).not.toContain(secret);
    expect(frame.value).toEqual({
      id: 7,
      shape: {
        code: -32600,
        message: 'Public validation failure',
        data: { code: 'BAD_REQUEST', httpStatus: 400, path: 'fail' }
      }
    });
  });

  it('aborts the authorization signal when RPC setup exceeds its deadline', async () => {
    const t = initTRPC.create();
    const router = t.router({ ok: t.procedure.query(() => 'ok') });
    let observedAbort = false;
    const output = new RecordingSend();
    const input = new BufferedRecv(await requestBytes({
      id: 8,
      path: 'ok',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    }), true);
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: (_request, signal) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          observedAbort = true;
          reject(signal.reason);
        }, { once: true });
      }),
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 10
    });

    await server.handle({ send: output, recv: input });

    expect(observedAbort).toBe(true);
    expect(output.bytes).toEqual([]);
  });

  it('aborts an active RPC when its authenticated physical session ends', async () => {
    const t = initTRPC.create();
    let markStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    let procedureSignal: AbortSignal | undefined;
    const router = t.router({
      hang: t.procedure.query(({ signal }) => {
        procedureSignal = signal;
        markStarted?.();
        return new Promise(() => undefined);
      })
    });
    const input = new AsyncByteRecv(await requestBytes({
      id: 81,
      path: 'hang',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    }));
    const output = new RecordingSend();
    const session = new AbortController();
    const handling = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 1_000,
      sessionSignal: session.signal
    }).handle({ send: output, recv: input });

    await started;
    session.abort(new Error('authenticated session ended'));
    await handling;

    expect(procedureSignal?.aborted).toBe(true);
    expect(output.bytes).toEqual([]);
    expect(output.resetCalls).toBe(1);
    expect(input.stopCalls).toBe(1);
  });

  it('bounds stalled priority and request reads and cleans both stream halves', async () => {
    const t = initTRPC.create();
    const router = t.router({ ok: t.procedure.query(() => 'ok') });
    const stalledPriority = new StalledPrioritySend();
    const unread = new StalledRecv();
    const priorityServer = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 20,
      ioTimeoutMs: 20
    });
    await priorityServer.handle({ send: stalledPriority, recv: unread });
    expect(stalledPriority.resetCalls).toBe(1);
    expect(unread.stopCalls).toBe(1);

    const output = new RecordingSend();
    const stalledRequest = new StalledRecv();
    await priorityServer.handle({ send: output, recv: stalledRequest });
    expect(output.resetCalls).toBe(1);
    expect(stalledRequest.stopCalls).toBe(1);
  });

  it('bounds stalled response writes and finish operations', async () => {
    const t = initTRPC.create();
    const router = t.router({ ok: t.procedure.query(() => 'ok') });
    const options = {
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 20,
      ioTimeoutMs: 20
    } as const;
    const request = await requestBytes({
      id: 9,
      path: 'ok',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    });

    const stalledWrite = new StalledWriteSend();
    const writeInput = new BufferedRecv(request, true);
    await new RpcServer(options).handle({ send: stalledWrite, recv: writeInput });
    expect(stalledWrite.resetCalls).toBe(1);
    expect(writeInput.stopCalls).toBe(1);

    const stalledFinish = new StalledFinishSend();
    const finishInput = new BufferedRecv(request, true);
    await new RpcServer(options).handle({ send: stalledFinish, recv: finishInput });
    expect(stalledFinish.finishCalls).toBe(1);
    expect(stalledFinish.resetCalls).toBe(1);
    expect(finishInput.stopCalls).toBe(1);
  });

  it('bounds a stalled error response instead of attempting unbounded recovery writes', async () => {
    const t = initTRPC.create();
    const router = t.router({ fail: t.procedure.query(() => { throw new Error('failure'); }) });
    const output = new StalledWriteSend();
    const input = new BufferedRecv(await requestBytes({
      id: 10,
      path: 'fail',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    }), true);
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 20,
      ioTimeoutMs: 20
    });

    await expect(server.handle({ send: output, recv: input })).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(output.resetCalls).toBe(1);
    expect(input.stopCalls).toBe(1);
  });

  it('stops the cancellation reader after a successful RPC', async () => {
    const t = initTRPC.create();
    const router = t.router({ ok: t.procedure.query(() => 'ok') });
    const output = new RecordingSend();
    const input = new AsyncByteRecv(await requestBytes({
      id: 11,
      path: 'ok',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    }));
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 100,
      ioTimeoutMs: 100
    });

    await server.handle({ send: output, recv: input });

    expect(input.stopCalls).toBe(1);
    expect(input.hasPendingRead).toBe(false);
    expect(output.finishCalls).toBe(1);
    expect(output.resetCalls).toBe(0);
  });

  it('cancels a non-cooperative procedure and rejects an invalid cancellation frame', async () => {
    const t = initTRPC.create();
    let markStarted: (() => void) | undefined;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const router = t.router({
      hang: t.procedure.query(() => {
        markStarted?.();
        return new Promise(() => undefined);
      })
    });
    const request = await requestBytes({
      id: 12,
      path: 'hang',
      type: 'query',
      headers: {},
      input: serializeValue(undefined)
    });
    const input = new AsyncByteRecv(request);
    const output = new RecordingSend();
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 100,
      ioTimeoutMs: 100
    });
    const handling = server.handle({ send: output, recv: input });
    await started;
    input.push(await frameBytes(RpcFrameKind.Cancel, { id: 12 }));
    await handling;
    expect(output.bytes).toEqual([]);
    expect(output.resetCalls).toBe(1);
    expect(input.stopCalls).toBe(1);

    const invalidInput = new AsyncByteRecv(request);
    const invalidOutput = new RecordingSend();
    const invalidHandling = server.handle({ send: invalidOutput, recv: invalidInput });
    invalidInput.push(await frameBytes(RpcFrameKind.Cancel, { id: 999 }));
    await invalidHandling;
    expect(invalidOutput.resetCalls).toBe(1);
    expect(invalidInput.stopCalls).toBe(1);
  });

  it('cancels while a subscription iterator is stuck in next()', async () => {
    const t = initTRPC.create();
    let markIteratorStarted: (() => void) | undefined;
    const iteratorStarted = new Promise<void>((resolve) => { markIteratorStarted = resolve; });
    const router = t.router({
      hang: t.procedure.subscription(async function *() {
        markIteratorStarted?.();
        await new Promise(() => undefined);
        yield 'unreachable';
      })
    });
    const input = new AsyncByteRecv(await requestBytes({
      id: 13,
      path: 'hang',
      type: 'subscription',
      headers: {},
      input: serializeValue(undefined)
    }));
    const output = new RecordingSend();
    const server = new RpcServer({
      router,
      createContext: () => ({}),
      authorize: () => undefined,
      headerLimits: { maxCount: 8, maxBytes: 1024 },
      maxPathBytes: 256,
      setupTimeoutMs: 100,
      ioTimeoutMs: 100
    });
    const handling = server.handle({ send: output, recv: input });
    await iteratorStarted;
    input.push(await frameBytes(RpcFrameKind.Cancel, { id: 13 }));

    await handling;

    expect(output.bytes).toEqual([]);
    expect(output.resetCalls).toBe(1);
    expect(input.stopCalls).toBe(1);
  });
});
