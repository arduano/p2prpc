import { expect, it, vi } from 'vitest';
import { RpcMessageBudget, readRpcFrame, writeRpcFrame } from '../src/rpc/messages.js';
import { encodeVarint, RpcFrameKind } from '../src/protocol.js';
import type { QuicRecvStream, QuicSendStream } from '../src/transport/types.js';

const MiB = 1024 * 1024;
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(yes => { resolve = yes; });
  return { promise, resolve };
}
function buffer() {
  const chunks: Uint8Array[] = [];
  let offset = 0;
  const pipe: QuicSendStream & QuicRecvStream = {
    async writeAll(bytes) { chunks.push(bytes.slice()); },
    async readExact(size) {
      const out = new Uint8Array(size);
      let copied = 0;
      while (copied < size) {
        const chunk = chunks[0];
        if (!chunk) throw Error('EOF');
        const count = Math.min(size - copied, chunk.length - offset);
        out.set(chunk.subarray(offset, offset + count), copied);
        copied += count; offset += count;
        if (offset === chunk.length) { chunks.shift(); offset = 0; }
      }
      return out;
    },
    async finish() {}, async expectEnd() {}, async reset() {}, async stop() {}, async setPriority() {}
  };
  return pipe;
}

it('round trips near-32MiB native data inside its RPC envelope with bounded carrier reads', async () => {
  const messages = new RpcMessageBudget();
  const pipe = buffer();
  const read = vi.spyOn(pipe, 'readExact');
  const value = { id: 1, data: { turn: { items: [{ type: 'agentMessage', text: 'x'.repeat(32 * MiB - 1024) }] } } };
  await writeRpcFrame(pipe, RpcFrameKind.Data, value, messages);
  expect(await readRpcFrame(pipe, messages)).toEqual({ kind: RpcFrameKind.Data, value });
  expect(Math.max(...read.mock.calls.map(([size]) => size))).toBeLessThanOrEqual(16 * 1024);
  expect(Object.values(messages.diagnostics()).every(pool => pool.active.bufferedBytes === 0)).toBe(true);
});

it('shares directional budgets across streams, keeps small controls moving, and rejects changed queued input', async () => {
  const messages = new RpcMessageBudget();
  const occupied = await messages.acquire('outbound', 64 * MiB);
  const value = { id: 1, data: { text: 'a'.repeat(100_000) } };
  const sink = buffer();
  const writes = vi.spyOn(sink, 'writeAll');
  const queued = writeRpcFrame(sink, RpcFrameKind.Data, value, messages);
  const outcome = queued.catch(error => error);
  expect(messages.diagnostics().outboundBulk!.queued).toBe(1);
  // The opposite direction and small control are independent of blocked bulk.
  const incoming = await messages.acquire('inbound', 64 * MiB);
  await writeRpcFrame(buffer(), RpcFrameKind.Complete, { id: 2 }, messages);
  value.data.text += 'changed';
  occupied.release(); incoming.release();
  expect(await outcome).toMatchObject({ code: 'RESOURCE_LIMIT', message: 'RPC value grew during message admission' });
  expect(writes).not.toHaveBeenCalled();
  await messages.whenIdle();
});

it('retains an admitted encoded body until the actual write settles after caller cancellation', async () => {
  const messages = new RpcMessageBudget();
  const entered = deferred(), release = deferred();
  const controller = new AbortController();
  const sink = buffer();
  sink.writeAll = async () => { entered.resolve(); await release.promise; };
  const writing = writeRpcFrame(sink, RpcFrameKind.Data, { id: 1, data: 'x'.repeat(100_000) }, messages, undefined, controller.signal);
  await entered.promise;
  controller.abort();
  expect(messages.diagnostics().outboundBulk!.active.bufferedBytes).toBeGreaterThan(100_000);
  release.resolve();
  await writing;
  expect(messages.diagnostics().outboundBulk!.active.bufferedBytes).toBe(0);
});

it('rejects an oversized declared body before reading or allocating it', async () => {
  const messages = new RpcMessageBudget();
  const pipe = buffer();
  await pipe.writeAll(Uint8Array.of(RpcFrameKind.Data, ...encodeVarint(64 * MiB + 1)));
  const read = vi.spyOn(pipe, 'readExact');
  await expect(readRpcFrame(pipe, messages)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
  expect(read.mock.calls.every(([size]) => size === 1)).toBe(true);
  expect(Object.values(messages.diagnostics()).every(pool => pool.active.bufferedBytes === 0)).toBe(true);
});
