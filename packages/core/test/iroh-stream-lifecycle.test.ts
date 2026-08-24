import { describe, expect, it } from 'vitest';
import {
  StreamLifecycle,
  WebRecvStream,
  WebSendStream,
  WebSessionConnection
} from '../src/transport/iroh.js';
import { hardenIrohWriterCleanup } from '../src/transport/iroh-writer-cleanup.js';
import type { IrohAdapter } from '@momics/iroh-http-shared';

describe('Iroh stream lifecycle diagnostics', () => {
  it('keeps a rejected native send close active until physical connection closure', async () => {
    const lifecycle = new StreamLifecycle();
    const send = new WebSendStream(new WritableStream<Uint8Array>({
      close: () => { throw new Error('native finish failed'); }
    }), lifecycle);

    await expect(send.finish()).rejects.toThrow('native finish failed');
    expect(lifecycle.snapshot()).toMatchObject({
      activeSend: 1,
      sendFinished: 0,
      sendReset: 0
    });

    lifecycle.closePhysical();
    expect(lifecycle.snapshot()).toMatchObject({
      activeSend: 0,
      sendFinished: 0,
      sendReset: 1
    });
  });

  it('does not mistake an errored WHATWG writer abort for native cleanup', async () => {
    const lifecycle = new StreamLifecycle();
    let abortCalls = 0;
    const send = new WebSendStream(new WritableStream<Uint8Array>({
      write: () => { throw new Error('native write failed'); },
      abort: () => { abortCalls += 1; }
    }), lifecycle);

    await expect(send.writeAll(new Uint8Array([1]))).rejects.toThrow('native write failed');
    // WHATWG abort on an already-errored stream can fulfill without invoking
    // the sink abort callback, so that fulfillment is not native proof.
    await expect(send.reset()).rejects.toMatchObject({ code: 'INTERNAL' });
    expect(abortCalls).toBe(0);
    expect(lifecycle.snapshot()).toMatchObject({ activeSend: 1, sendReset: 0 });

    lifecycle.closePhysical();
    expect(lifecycle.snapshot()).toMatchObject({ activeSend: 0, sendReset: 1 });
  });

  it('accepts exact adapter finalization as terminal proof after a failed native write', async () => {
    const lifecycle = new StreamLifecycle();
    const writeError = new Error('native write failed after peer stop');
    let finishes = 0;
    const adapter: Pick<IrohAdapter, 'sendChunk' | 'finishBody'> = {
      async sendChunk() { throw writeError; },
      async finishBody() { finishes += 1; }
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);
    const handle = 41n;
    const send = new WebSendStream(new WritableStream<Uint8Array>({
      write: (chunk) => adapter.sendChunk(handle, chunk),
      close: () => adapter.finishBody(handle),
      abort: () => adapter.finishBody(handle)
    }), lifecycle);

    await expect(send.writeAll(Uint8Array.of(1))).rejects.toBe(writeError);
    expect(finishes).toBe(1);
    expect(lifecycle.snapshot()).toMatchObject({ activeSend: 0, sendReset: 1 });
    // WHATWG abort would skip the errored sink. The adapter proof makes this a
    // successful idempotent cleanup instead of quarantining the connection.
    await expect(send.reset()).resolves.toBeUndefined();
    expect(finishes).toBe(1);
    await expect(send.finish()).rejects.toBe(writeError);
  });

  it('uses adapter terminal proof when reset races an in-flight failed write', async () => {
    const lifecycle = new StreamLifecycle();
    const writeStarted = deferred<void>();
    const failWrite = deferred<void>();
    const writeError = new Error('peer stopped in-flight write');
    let finishes = 0;
    const adapter: Pick<IrohAdapter, 'sendChunk' | 'finishBody'> = {
      async sendChunk() {
        writeStarted.resolve();
        await failWrite.promise;
        throw writeError;
      },
      async finishBody() { finishes += 1; }
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);
    const handle = 42n;
    const send = new WebSendStream(new WritableStream<Uint8Array>({
      write: (chunk) => adapter.sendChunk(handle, chunk),
      close: () => adapter.finishBody(handle),
      abort: () => adapter.finishBody(handle)
    }), lifecycle);

    const writing = send.writeAll(Uint8Array.of(1));
    await writeStarted.promise;
    const resetting = send.reset();
    failWrite.resolve();

    await expect(writing).rejects.toBe(writeError);
    await expect(resetting).resolves.toBeUndefined();
    expect(finishes).toBe(1);
    expect(lifecycle.snapshot()).toMatchObject({ activeSend: 0, sendReset: 1 });
  });

  it('accepts exact native handle absence when a peer already retired the writer', async () => {
    const lifecycle = new StreamLifecycle();
    const handle = 43n;
    const adapter: Pick<IrohAdapter, 'sendChunk' | 'finishBody'> = {
      async sendChunk() {},
      async finishBody() {
        throw new Error(JSON.stringify({
          code: 'INVALID_INPUT',
          message: `unknown handle: ${handle}`
        }));
      }
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);
    const send = new WebSendStream(new WritableStream<Uint8Array>({
      write: (chunk) => adapter.sendChunk(handle, chunk),
      close: () => adapter.finishBody(handle),
      abort: () => adapter.finishBody(handle)
    }), lifecycle);

    await expect(send.reset()).resolves.toBeUndefined();
    expect(lifecycle.snapshot()).toMatchObject({ activeSend: 0, sendReset: 1 });
  });

  it('keeps a rejected native receive cancellation active until connection closure', async () => {
    const lifecycle = new StreamLifecycle();
    const recv = new WebRecvStream(new ReadableStream<Uint8Array>({
      cancel: () => { throw new Error('native cancel failed'); }
    }), lifecycle);

    await expect(recv.stop()).rejects.toThrow('native cancel failed');
    expect(lifecycle.snapshot()).toMatchObject({
      activeRecv: 1,
      recvEof: 0,
      recvStopped: 0
    });

    lifecycle.closePhysical();
    expect(lifecycle.snapshot()).toMatchObject({ activeRecv: 0, recvStopped: 1 });
  });

  it('does not retain an exhausted native receive chunk backing allocation', async () => {
    const lifecycle = new StreamLifecycle();
    const nativeChunk = new Uint8Array(8 * 1024 * 1024);
    const recv = new WebRecvStream(new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(nativeChunk);
        controller.close();
      }
    }), lifecycle);

    await expect(recv.readExact(nativeChunk.byteLength)).resolves.toHaveLength(nativeChunk.byteLength);
    const buffered = (recv as unknown as { buffered: Uint8Array }).buffered;
    expect(buffered.byteLength).toBe(0);
    expect(buffered.buffer).not.toBe(nativeChunk.buffer);
    await expect(recv.expectEnd()).resolves.toBeUndefined();
  });

  it('preserves a framing failure when its defensive native cancel also fails', async () => {
    const lifecycle = new StreamLifecycle();
    const recv = new WebRecvStream(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array([1])); },
      cancel: () => { throw new Error('secondary native cancel failure'); }
    }), lifecycle);

    await expect(recv.expectEnd()).rejects.toMatchObject({
      code: 'INVALID_FRAME',
      message: 'Stream contains trailing bytes'
    });
    expect(lifecycle.snapshot()).toMatchObject({ activeRecv: 1, recvStopped: 0 });
  });

  it('settles failed stream terminals when the session physically closes', async () => {
    const physicallyClosed = deferred<{ readonly closeCode: number; readonly reason: string }>();
    const session = {
      remoteId: { toString: () => 'remote' },
      ready: Promise.resolve(),
      closed: physicallyClosed.promise,
      close: () => undefined,
      incomingBidirectionalStreams: new ReadableStream(),
      incomingUnidirectionalStreams: new ReadableStream(),
      createBidirectionalStream: () => Promise.reject(new Error('unused')),
      createUnidirectionalStream: () => Promise.resolve(new WritableStream<Uint8Array>({
        close: () => { throw new Error('native finish failed'); }
      }))
    };
    const connection = new WebSessionConnection(
      session as never,
      { peerStats: async () => undefined } as never,
      'client'
    );
    const send = await connection.openUni();

    await expect(send.finish()).rejects.toThrow('native finish failed');
    await expect(connection.stats()).resolves.toMatchObject({
      streams: { activeSend: 1, sendFinished: 0, sendReset: 0 }
    });

    physicallyClosed.resolve({ closeCode: 4, reason: 'closed' });
    await expect(connection.closed()).resolves.toBe('closed');
    await expect(connection.stats()).resolves.toMatchObject({
      streams: { activeSend: 0, sendFinished: 0, sendReset: 1 }
    });
  });
});

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}
