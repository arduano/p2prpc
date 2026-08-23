import { describe, expect, it, vi } from 'vitest';
import type { IrohAdapter } from '@momics/iroh-http-shared';
import { hardenIrohWriterCleanup } from '../src/transport/iroh-writer-cleanup.js';

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

    await expect(writer.write(Uint8Array.of(1))).rejects.toBe(writeError);
    // WHATWG abort resolves after a stream is already errored without invoking
    // the sink abort callback. The adapter seam must already have finalized it.
    await expect(writer.abort(writeError)).resolves.toBeUndefined();

    expect(finishBody).toHaveBeenCalledTimes(1);
    expect(finishBody).toHaveBeenCalledWith(handle);
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

    await expect(adapter.sendChunk(9n, new Uint8Array())).rejects.toBe(writeError);
  });
});
