import { describe, expect, it } from 'vitest';
import { encodeVarint, readFrame, readVarint, writeFrame } from '../src/protocol.js';
import type { QuicRecvStream, QuicSendStream } from '../src/transport/types.js';

class BufferPipe implements QuicSendStream, QuicRecvStream {
  private bytes: number[] = [];
  async writeAll(data: Uint8Array): Promise<void> { this.bytes.push(...data); }
  async readExact(size: number): Promise<Uint8Array> {
    if (this.bytes.length < size) throw new Error('EOF');
    return Uint8Array.from(this.bytes.splice(0, size));
  }
  async finish(): Promise<void> {}
  async expectEnd(): Promise<void> {
    if (this.bytes.length !== 0) throw new Error('Trailing bytes');
  }
  async reset(): Promise<void> {}
  async setPriority(): Promise<void> {}
  async stop(): Promise<void> {}
}

describe('protocol framing', () => {
  it.each([0, 1, 127, 128, 16_384, 1_000_000])('round trips varint %i', async (value) => {
    const pipe = new BufferPipe();
    await pipe.writeAll(encodeVarint(value));
    await expect(readVarint(pipe)).resolves.toBe(value);
  });

  it('round trips MessagePack frames', async () => {
    const pipe = new BufferPipe();
    await writeFrame(pipe, 7, { binary: Uint8Array.of(1, 2, 3), text: 'hello' });
    await expect(readFrame(pipe)).resolves.toEqual({
      kind: 7,
      value: { binary: Uint8Array.of(1, 2, 3), text: 'hello' }
    });
  });

  it('rejects frames above the configured limit before reading the body', async () => {
    const pipe = new BufferPipe();
    await pipe.writeAll(Uint8Array.of(1, ...encodeVarint(100)));
    await expect(readFrame(pipe, { maxControlFrameBytes: 10 })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
  });

  it('rejects oversized outbound frames before writing them', async () => {
    const pipe = new BufferPipe();
    await expect(writeFrame(pipe, 1, { value: 'x'.repeat(100) }, { maxControlFrameBytes: 10 }))
      .rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await expect(pipe.readExact(1)).rejects.toThrow(/EOF/);
  });

  it('bounds MessagePack item amplification before decoding', async () => {
    const pipe = new BufferPipe();
    const body = Uint8Array.of(0x94, 0xc0, 0xc0, 0xc0, 0xc0);
    await pipe.writeAll(Uint8Array.of(1, ...encodeVarint(body.byteLength), ...body));
    await expect(readFrame(pipe, {
      maxControlFrameBytes: 1024,
      maxControlFrameItems: 4
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
  });

  it('rejects excessive nesting, extensions, and duplicate map keys', async () => {
    const outbound = new BufferPipe();
    await expect(writeFrame(outbound, 1, [[[null]]], {
      maxControlFrameBytes: 1024,
      maxControlFrameDepth: 2
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await expect(writeFrame(outbound, 1, undefined, { maxControlFrameBytes: 1024 }))
      .rejects.toMatchObject({ code: 'INVALID_FRAME' });

    const inbound = new BufferPipe();
    const duplicateMap = Uint8Array.of(0x82, 0xa1, 0x78, 0x01, 0xa1, 0x78, 0x02);
    await inbound.writeAll(Uint8Array.of(1, ...encodeVarint(duplicateMap.byteLength), ...duplicateMap));
    await expect(readFrame(inbound, { maxControlFrameBytes: 1024 }))
      .rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it.each([
    ['non-string map key', Uint8Array.of(0x81, 0x01, 0xc0)],
    ['prototype-confusing map key', Uint8Array.of(
      0x81,
      0xa9,
      ...Buffer.from('__proto__'),
      0xc0
    )],
    ['invalid UTF-8', Uint8Array.of(0xa1, 0xff)],
    ['trailing MessagePack data', Uint8Array.of(0xc0, 0xc0)]
  ])('rejects %s before decoding', async (_label, body) => {
    const pipe = new BufferPipe();
    await pipe.writeAll(Uint8Array.of(1, ...encodeVarint(body.byteLength), ...body));
    await expect(readFrame(pipe, { maxControlFrameBytes: 1024 }))
      .rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });
});
