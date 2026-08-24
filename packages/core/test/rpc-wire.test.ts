import SuperJSON from 'superjson';
import { describe, expect, it } from 'vitest';
import { deserializeValue, serializeValue } from '../src/rpc/wire.js';

describe('private RPC value codec', () => {
  it('round-trips the supported built-in SuperJSON data model', () => {
    const input = {
      date: new Date('2026-01-02T03:04:05.000Z'),
      map: new Map([['key', 1]]),
      set: new Set(['value']),
      regexp: /safe/gi,
      typed: new Uint16Array([1, 2, 3]),
      bigint: 123n,
      undefined
    };

    const output = deserializeValue(serializeValue(input)) as typeof input;
    expect(output).toMatchObject({ bigint: 123n, undefined: undefined });
    expect(output.date).toEqual(input.date);
    expect(output.map).toEqual(input.map);
    expect(output.set).toEqual(input.set);
    expect(output.regexp).toEqual(input.regexp);
    expect(output.typed).toEqual(input.typed);
  });

  it('does not invoke custom deserializers registered on SuperJSON globally', () => {
    let invoked = false;
    const name = 'p2prpc-test-global-transformer';
    SuperJSON.registerCustom<{ marker: true }, string>({
      isApplicable: (value): value is { marker: true } => (
        typeof value === 'object' && value !== null && 'marker' in value && value.marker === true
      ),
      serialize: () => 'serialized',
      deserialize: () => {
        invoked = true;
        return { marker: true };
      }
    }, name);

    expect(() => deserializeValue({
      json: 'peer-controlled',
      meta: { values: [['custom', name]], v: 1 }
    })).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(invoked).toBe(false);
  });

  it('rejects accessors and oversized input before SuperJSON traverses it', () => {
    let invoked = false;
    const accessor = Object.defineProperty({}, 'value', {
      enumerable: true,
      get() {
        invoked = true;
        return 'secret';
      }
    });
    expect(() => serializeValue(accessor)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(invoked).toBe(false);

    expect(() => serializeValue(new Array(20).fill(0), {
      maxControlFrameBytes: 1_024,
      maxControlFrameItems: 10,
      maxControlFrameDepth: 8
    })).toThrowError(expect.objectContaining({ code: 'RESOURCE_LIMIT' }));

    const shared = { value: 1 };
    expect(() => serializeValue([shared, shared])).toThrowError(
      expect.objectContaining({ code: 'INVALID_FRAME' })
    );

    const hidden = { visible: true };
    Object.defineProperty(hidden, 'omitted', { value: 'must-not-disappear' });
    expect(() => serializeValue(hidden)).toThrowError(
      expect.objectContaining({ code: 'INVALID_FRAME' })
    );
    expect(() => serializeValue({ visible: true, [Symbol('omitted')]: true })).toThrowError(
      expect.objectContaining({ code: 'INVALID_FRAME' })
    );
  });

  it('accepts only versioned built-in annotation metadata', () => {
    for (const value of [
      { json: null, meta: { values: ['undefined'] } },
      { json: null, meta: { values: ['unknown'], v: 1 } },
      { json: null, meta: { values: ['undefined'], v: 2 } },
      { json: null, meta: { values: ['undefined'], v: 1, extra: true } },
      { json: [{ value: 1 }, { value: 1 }], meta: { referentialEqualities: { '0': ['1'] }, v: 1 } },
      { json: 1_000_000_000, meta: { values: [['typed-array', 'Uint8Array']], v: 1 } }
    ]) {
      expect(() => deserializeValue(value)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }
  });

  it('requires a canonical, non-overlapping annotation tree', () => {
    for (const value of [
      // Two syntactically distinct branches may not resolve to the same target.
      {
        json: { value: '1' },
        meta: { values: { value: ['bigint'], 'value.': ['bigint'] }, v: 1 }
      },
      // Ancestor and descendant annotations are never siblings. SuperJSON
      // emits descendants as the second item of a composable parent node.
      {
        json: { value: ['1'] },
        meta: { values: { value: ['set'], 'value.0': ['bigint'] }, v: 1 }
      },
      // A leaf transform cannot carry children.
      {
        json: ['2026-01-02T03:04:05.000Z'],
        meta: { values: ['Date', { 0: ['Date'] }], v: 1 }
      },
      // Children of an Error may only descend through its cause payload.
      {
        json: { name: ['1'], message: 'x' },
        meta: { values: ['Error', { 'name.0': ['bigint'] }], v: 1 }
      },
      // Reusing the same metadata container is not a valid wire tree.
      (() => {
        const annotation = ['bigint'];
        return {
          json: { first: '1', second: '1' },
          meta: { values: { first: annotation, second: annotation }, v: 1 }
        };
      })()
    ]) {
      expect(() => deserializeValue(value)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }
  });

  it('validates annotation targets and canonical serialized forms', () => {
    for (const value of [
      { json: [[1]], meta: { values: ['map'], v: 1 } },
      { json: '2026-01-02', meta: { values: ['Date'], v: 1 } },
      { json: '/safe/ig', meta: { values: ['regexp'], v: 1 } },
      { json: 'HTTP://EXAMPLE.COM', meta: { values: ['URL'], v: 1 } },
      { json: [1], meta: { values: [['typed-array', 'Uint16Array'], {}], v: 1 } },
      { json: [1], meta: { values: [['typed-array', 'Uint16Array'], ['extra']], v: 1 } }
    ]) {
      expect(() => deserializeValue(value)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }

    expect(deserializeValue({
      json: [['2026-01-02T03:04:05.000Z', ['2']]],
      meta: {
        values: ['map', {
          '0.0': ['Date'],
          '0.1': ['set', { 0: ['bigint'] }]
        }],
        v: 1
      }
    })).toEqual(new Map([[new Date('2026-01-02T03:04:05.000Z'), new Set([2n])]]));
  });

  it('rejects hidden fields, accessors, exotic arrays, and pre-traversal allocation shapes', () => {
    let calls = 0;
    const envelopeAccessor = Object.defineProperty({ meta: { values: ['undefined'], v: 1 } }, 'json', {
      enumerable: true,
      get() {
        calls += 1;
        return null;
      }
    });
    const hidden = { json: null };
    Object.defineProperty(hidden, 'meta', { value: { values: ['undefined'], v: 1 } });
    const extraArray = [null] as unknown[] & { extra?: boolean };
    extraArray.extra = true;
    const hugeMap = new Map(Array.from({ length: 20 }, (_, index) => [index, index]));
    const typedAccessor = Object.defineProperty(new Uint8Array([1]), 'length', {
      get() {
        calls += 1;
        return 1;
      }
    });

    expect(() => deserializeValue(envelopeAccessor)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(() => deserializeValue(hidden)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(() => deserializeValue({ json: extraArray })).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(() => serializeValue(hugeMap, {
      maxControlFrameBytes: 1_024,
      maxControlFrameItems: 10,
      maxControlFrameDepth: 8
    })).toThrowError(expect.objectContaining({ code: 'RESOURCE_LIMIT' }));
    expect(() => serializeValue(typedAccessor)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(calls).toBe(0);
  });

  it('round-trips Errors without evaluating stack accessors', () => {
    const error = new TypeError('safe', { cause: new Date('2026-01-02T03:04:05.000Z') });
    let stackReads = 0;
    Object.defineProperty(error, 'stack', {
      configurable: true,
      get() {
        stackReads += 1;
        throw new Error('stack must not be read');
      }
    });
    const output = deserializeValue(serializeValue(error)) as Error;
    expect(output).toMatchObject({ name: 'TypeError', message: 'safe' });
    expect(output.cause).toEqual(new Date('2026-01-02T03:04:05.000Z'));
    expect(stackReads).toBe(0);
  });

  it('rejects exceptional typed-array elements instead of silently changing them', () => {
    for (const value of [
      new Float32Array([Number.NaN]),
      new Float64Array([Number.POSITIVE_INFINITY]),
      new Float64Array([-0])
    ]) {
      expect(() => serializeValue(value)).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }
    const finite = new Float64Array([1.5, -2.25]);
    expect(deserializeValue(serializeValue(finite))).toEqual(finite);
  });

  it('charges repeated flattened annotation paths before SuperJSON allocation', () => {
    const longPrefix = 'x'.repeat(2_000);
    const value = {
      [longPrefix]: Object.fromEntries(
        Array.from({ length: 100 }, (_, index) => [`field-${index}`, BigInt(index)])
      )
    };
    expect(() => serializeValue(value, {
      maxControlFrameBytes: 64 * 1024,
      maxControlFrameItems: 4_096,
      maxControlFrameDepth: 16
    })).toThrowError(expect.objectContaining({ code: 'RESOURCE_LIMIT' }));
  });
});
