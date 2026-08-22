import { describe, expect, it } from 'vitest';
import { normalizeRpcHeaders, p2pRpcContext } from '../src/index.js';

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
});
