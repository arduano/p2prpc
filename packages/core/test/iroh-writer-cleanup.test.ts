import { describe, expect, it, vi } from 'vitest';
import type { IrohAdapter } from '@momics/iroh-http-shared';
import {
  consumeIrohWriterCleanupProof,
  hardenIrohWriterCleanup
} from '../src/transport/iroh-writer-cleanup.js';

type WriterAdapter = Pick<IrohAdapter, 'sendChunk' | 'finishBody'>;

describe('Iroh writer cleanup compatibility seam', () => {
  it('finalizes an opaque writer exactly once when a sink write rejects', async () => {
    const writeError = new Error('body reader dropped');
    const finishBody = vi.fn(async () => undefined);
    const adapter: WriterAdapter = {
      async sendChunk() {
        throw writeError;
      },
      finishBody
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);

    const handle = 17n;
    const stream = new WritableStream<Uint8Array>({
      write: (chunk) => adapter.sendChunk(handle, chunk),
      close: () => adapter.finishBody(handle),
      abort: () => adapter.finishBody(handle)
    });
    const writer = stream.getWriter();
    void writer.closed.catch(() => undefined);

    const failure = await writer.write(Uint8Array.of(1)).catch((cause: unknown) => cause);
    expect(consumeIrohWriterCleanupProof(failure)).toEqual({
      cause: writeError,
      terminal: true
    });
    // WHATWG abort resolves after a stream is already errored without invoking
    // the sink abort callback. The adapter seam must already have finalized it.
    await expect(writer.abort(writeError)).resolves.toBeUndefined();

    expect(finishBody).toHaveBeenCalledTimes(1);
    expect(finishBody).toHaveBeenCalledWith(handle);
  });

  it('correlates terminal proof to one exact writer when an error object is reused', async () => {
    const shared = new Error('shared native failure');
    let finishes = 0;
    const adapter: WriterAdapter = {
      async sendChunk() { throw shared; },
      async finishBody() {
        finishes += 1;
        if (finishes === 2) throw new Error('second cleanup failed');
      }
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);

    const proven = await adapter.sendChunk(1n, new Uint8Array()).catch((cause: unknown) => cause);
    const unproven = await adapter.sendChunk(2n, new Uint8Array()).catch((cause: unknown) => cause);
    expect(consumeIrohWriterCleanupProof(proven)).toEqual({ cause: shared, terminal: true });
    expect(consumeIrohWriterCleanupProof(unproven)).toEqual({ cause: shared, terminal: false });
  });

  it('is idempotent and preserves adapter this binding', async () => {
    const adapter = {
      calls: 0,
      async sendChunk(this: { calls: number }, handle: bigint, chunk: Uint8Array) {
        void handle;
        void chunk;
        this.calls += 1;
      },
      async finishBody() {}
    };

    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);
    const wrapped = adapter.sendChunk;
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);

    expect(adapter.sendChunk).toBe(wrapped);
    await adapter.sendChunk(1n, Uint8Array.of(1));
    expect(adapter.calls).toBe(1);
  });

  it('preserves the write error if native finalization also rejects', async () => {
    const writeError = new Error('send failed');
    const adapter: WriterAdapter = {
      async sendChunk() {
        throw writeError;
      },
      async finishBody() {
        throw new Error('handle already gone');
      }
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);

    const failure = await adapter.sendChunk(9n, new Uint8Array()).catch((cause: unknown) => cause);
    expect(failure).toBe(writeError);
    expect(consumeIrohWriterCleanupProof(failure).terminal).toBe(false);
  });

  it('treats only an exact native unknown-handle result as idempotent terminal proof', async () => {
    const finishBody = vi.fn(async (handle: bigint) => {
      throw new Error(JSON.stringify({
        code: 'INVALID_INPUT',
        message: `unknown handle: ${handle}`
      }));
    });
    const adapter: WriterAdapter = {
      async sendChunk() {},
      finishBody
    };
    hardenIrohWriterCleanup(adapter as unknown as IrohAdapter);

    await expect(adapter.finishBody(73n)).resolves.toBeUndefined();
    expect(finishBody).toHaveBeenCalledWith(73n);

    const mismatched: WriterAdapter = {
      async sendChunk() {},
      async finishBody() {
        throw new Error(JSON.stringify({
          code: 'INVALID_INPUT',
          message: 'unknown handle: 74',
          extra: true
        }));
      }
    };
    hardenIrohWriterCleanup(mismatched as unknown as IrohAdapter);
    await expect(mismatched.finishBody(74n)).rejects.toThrow('extra');
  });
});
