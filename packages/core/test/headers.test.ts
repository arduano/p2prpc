import { describe, expect, it, vi } from 'vitest';
import { p2pRpcContext } from '../src/index.js';
import { normalizeRpcHeaders } from '../src/rpc/headers.js';

describe('RPC request headers', () => {
  it('normalizes names and returns immutable metadata', () => {
    const headers = normalizeRpcHeaders({ TraceParent: '00-abc-123-01', 'X-Tenant': 'acme' });
    expect(headers).toEqual({ traceparent: '00-abc-123-01', 'x-tenant': 'acme' });
    expect(Object.isFrozen(headers)).toBe(true);
  });

  it('snapshots per-call metadata when the tRPC context is created', () => {
    const input: Record<string, string> = { 'X-Tenant': 'tenant-a' };
    const context = p2pRpcContext(input);
    input['X-Tenant'] = 'tenant-b';
    expect(context.p2prpc.headers).toEqual({ 'x-tenant': 'tenant-a' });
    expect(Object.isFrozen(context.p2prpc.headers)).toBe(true);
  });

  it.each([
    'authorization',
    'cookie',
    'set-cookie',
    'connection',
    'forwarded',
    'host',
    'origin',
    'proxy-authenticate',
    'x-forwarded-for',
    'x-real-ip',
    'p2prpc-subject',
    'x-p2prpc-session'
  ])(
    'rejects reserved header %s',
    (name) => expect(() => normalizeRpcHeaders({ [name]: 'spoofed' })).toThrow(/reserved/)
  );

  it('rejects malformed, duplicate, and oversized metadata', () => {
    expect(() => normalizeRpcHeaders({ 'bad name': 'x' })).toThrow(/Invalid RPC header name/);
    expect(() => normalizeRpcHeaders({ traceparent: 'x\r\ny' })).toThrow(/control/);
    expect(() => normalizeRpcHeaders({ traceparent: 'safe\u0085forged' })).toThrow(/control/);
    expect(() => normalizeRpcHeaders({ traceparent: 'safe\u202eforged' })).toThrow(/formatting/);
    expect(() => normalizeRpcHeaders([['X-ID', 'one'], ['x-id', 'two']])).toThrow(/Duplicate/);
    expect(() => normalizeRpcHeaders({ value: 'x'.repeat(20) }, { maxCount: 2, maxBytes: 8 })).toThrow(/limits/);
  });

  it.each([null, false, 0, ''])('rejects a falsey non-object metadata value: %j', (value) => {
    expect(() => normalizeRpcHeaders(value as never)).toThrow(/record or iterable/);
  });

  it('stops inspecting a wide null-prototype record at the configured count bound', () => {
    const headers = Object.create(null) as Record<string, string>;
    for (let index = 0; index < 10_000; index += 1) headers[`x-${index}`] = 'value';
    const descriptor = Object.getOwnPropertyDescriptor;
    let inspected = 0;
    const inspection = vi.spyOn(Object, 'getOwnPropertyDescriptor').mockImplementation((target, key) => {
      if (target === headers && typeof key === 'string') inspected += 1;
      return descriptor(target, key);
    });
    try {
      expect(() => normalizeRpcHeaders(headers, { maxCount: 4, maxBytes: 1024 }))
        .toThrowError(expect.objectContaining({ code: 'RESOURCE_LIMIT' }));
      expect(inspected).toBe(4);
    } finally {
      inspection.mockRestore();
    }
  });

  it('rejects record accessors without executing them', () => {
    let reads = 0;
    const headers = Object.create(null) as Record<string, string>;
    Object.defineProperty(headers, 'x-tenant', {
      enumerable: true,
      get() {
        reads += 1;
        return 'tenant';
      }
    });

    expect(() => normalizeRpcHeaders(headers)).toThrow(/data properties/);
    expect(reads).toBe(0);
  });

  it('rejects proxies before invoking enumeration traps', () => {
    let traps = 0;
    const headers = new Proxy(Object.create(null) as Record<string, string>, {
      ownKeys() {
        traps += 1;
        return ['x-tenant'];
      },
      getOwnPropertyDescriptor() {
        traps += 1;
        return { configurable: true, enumerable: true, value: 'tenant' };
      },
      get() {
        traps += 1;
        return undefined;
      }
    });

    expect(() => normalizeRpcHeaders(headers)).toThrow(/Proxy/);
    expect(traps).toBe(0);
  });

  it('bounds iterable look-ahead before reading an over-limit value and closes the iterator', () => {
    let nextCalls = 0;
    let overLimitValueReads = 0;
    let returnCalls = 0;
    const iterator = {
      next() {
        nextCalls += 1;
        if (nextCalls <= 2) return { done: false, value: [`x-${nextCalls}`, 'value'] };
        const result: { done: boolean; readonly value?: readonly [string, string] } = { done: false };
        Object.defineProperty(result, 'value', {
          enumerable: true,
          get() {
            overLimitValueReads += 1;
            return ['x-over-limit', 'value'] as const;
          }
        });
        return result;
      },
      return() {
        returnCalls += 1;
        return { done: true };
      }
    };
    const headers = { [Symbol.iterator]: () => iterator };

    expect(() => normalizeRpcHeaders(headers, { maxCount: 2, maxBytes: 1024 }))
      .toThrowError(expect.objectContaining({ code: 'RESOURCE_LIMIT' }));
    expect(nextCalls).toBe(3);
    expect(overLimitValueReads).toBe(0);
    expect(returnCalls).toBe(1);
  });

  it('rejects iterable accessors and pair accessors without executing them', () => {
    let iteratorReads = 0;
    const accessorIterable = Object.create(null) as Record<PropertyKey, unknown>;
    Object.defineProperty(accessorIterable, Symbol.iterator, {
      get() {
        iteratorReads += 1;
        return function *iterator() { yield ['x-id', 'value']; };
      }
    });
    expect(() => normalizeRpcHeaders(accessorIterable as never)).toThrow(/data property/);
    expect(iteratorReads).toBe(0);

    let pairReads = 0;
    const pair = new Array<unknown>(2);
    Object.defineProperty(pair, '0', {
      configurable: true,
      enumerable: true,
      get() {
        pairReads += 1;
        return 'x-id';
      }
    });
    pair[1] = 'value';
    expect(() => normalizeRpcHeaders([pair] as never)).toThrow(/data-property pairs/);
    expect(pairReads).toBe(0);
  });
});
