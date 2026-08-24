import { describe, expect, it } from 'vitest';
import { encodeVarint, readFrame, readVarint, writeFrame } from '../src/protocol.js';
import type { QuicRecvStream, QuicSendStream } from '../src/transport/types.js';
import { exactRecord, exactRecordWithOptional } from '../src/wire-schema.js';

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

async function readEncodedBody(body: Uint8Array, limits = { maxControlFrameBytes: 1024 }): Promise<unknown> {
  const pipe = new BufferPipe();
  await pipe.writeAll(Uint8Array.of(1, ...encodeVarint(body.byteLength), ...body));
  return readFrame(pipe, limits);
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

  it('preflights outbound shape, cycles, and accessors before serialization', async () => {
    const pipe = new BufferPipe();
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'secret', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'must-not-run';
      }
    });
    const byteAccessor = Object.defineProperty(Uint8Array.of(1), 'byteLength', {
      get() {
        getterCalls += 1;
        return 1;
      }
    });
    const inheritedBytes = new (class extends Uint8Array {})([1]);

    await expect(writeFrame(pipe, 1, cyclic)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(writeFrame(pipe, 1, accessor)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(writeFrame(pipe, 1, byteAccessor)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(writeFrame(pipe, 1, inheritedBytes)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(writeFrame(pipe, 1, -0)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(writeFrame(pipe, 1, [null, null], {
      maxControlFrameBytes: 1024,
      maxControlFrameItems: 2
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(getterCalls).toBe(0);
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
    ['constructor map key', Uint8Array.of(
      0x81,
      0xab,
      ...Buffer.from('constructor'),
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

  it.each([
    ['uint8 for a positive fixint', Uint8Array.of(0xcc, 0x01)],
    ['uint16 for a uint8', Uint8Array.of(0xcd, 0x00, 0x80)],
    ['int8 for a negative fixint', Uint8Array.of(0xd0, 0xff)],
    ['str8 for a fixstr', Uint8Array.of(0xd9, 0x01, 0x78)],
    ['array16 for a fixarray', Uint8Array.of(0xdc, 0x00, 0x01, 0xc0)],
    ['bin16 for bin8 data', Uint8Array.of(0xc5, 0x00, 0x01, 0x00)],
    ['float32', Uint8Array.of(0xca, 0x3f, 0x80, 0x00, 0x00)],
    ['integral float64', Uint8Array.of(0xcb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)],
    ['non-canonical NaN payload', Uint8Array.of(0xcb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)],
    ['fixmap under project encoding', Uint8Array.of(0x80)],
    ['map32 under project encoding', Uint8Array.of(0xdf, 0x00, 0x01, 0x00, 0x00)]
  ])('rejects non-canonical %s', async (_label, body) => {
    await expect(readEncodedBody(body)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('rejects overlong frame-length varints', async () => {
    const pipe = new BufferPipe();
    await pipe.writeAll(Uint8Array.of(1, 0x81, 0x00, 0xc0));
    await expect(readFrame(pipe, { maxControlFrameBytes: 1024 }))
      .rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });
});

describe('exact wire records', () => {
  it('accepts only enumerable data fields on plain objects', () => {
    exactRecord({ id: 1 }, ['id'], 'Record');
    exactRecordWithOptional(Object.assign(Object.create(null), { id: 1 }), ['id'], ['tag'], 'Record');

    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'id', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 1;
      }
    });
    const hidden = {};
    Object.defineProperty(hidden, 'id', { value: 1 });
    const symbol = { id: 1, [Symbol('hidden')]: true };
    const inherited = Object.create({ id: 1 }) as Record<string, unknown>;

    for (const value of [accessor, hidden, symbol, inherited]) {
      expect(() => exactRecord(value, ['id'], 'Record'))
        .toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }
    expect(getterCalls).toBe(0);
  });
});
