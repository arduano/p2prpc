import type * as IrohHttpNode from '@momics/iroh-http-node';
import type { NodeOptions } from '@momics/iroh-http-node';
import { describe, expect, it, vi } from 'vitest';
import { initTRPC } from '@trpc/server';
import { createAdvancedP2PNode } from '../src/node.js';
import { dangerouslyAllowInsecureSessions } from '../src/security/shared-secret.js';

const native = vi.hoisted(() => ({
  createNode: vi.fn(),
  failure: new Error('stop after capturing native node options')
}));

vi.mock('@momics/iroh-http-node', async (importOriginal) => {
  const actual = await importOriginal<typeof IrohHttpNode>();
  return {
    ...actual,
    createNode: native.createNode
  };
});

import { IrohEndpoint } from '../src/transport/iroh.js';

describe('Iroh native node options', () => {
  it('disables native TTL sweeping for p2prpc-owned session and stream handles', async () => {
    let captured: NodeOptions | undefined;
    native.createNode.mockImplementationOnce(async (options: NodeOptions) => {
      captured = options;
      throw native.failure;
    });

    await expect(IrohEndpoint.create(
      new TextEncoder().encode('p2prpc-handle-lifetime-regression'),
      { relay: { mode: 'default' } }
    )).rejects.toBe(native.failure);

    expect(captured?.internals).toMatchObject({
      handleTtl: 0,
      maxChunkSizeBytes: 1024 * 1024
    });
  });

  it('keeps custom relay authentication across the managed P2PNode snapshot boundary', async () => {
    const token = 'synthetic-managed-node-token-for-tests';
    let captured: NodeOptions | undefined;
    native.createNode.mockImplementationOnce(async (options: NodeOptions) => {
      captured = options;
      throw native.failure;
    });
    const router = initTRPC.create().router({});
    await expect(createAdvancedP2PNode({
      router, protocol: { applicationId: 'private-relay-snapshot', contractVersion: '1' },
      createContext: context => context,
      security: dangerouslyAllowInsecureSessions(),
      iroh: { relay: { mode: 'custom', urls: ['https://relay.invalid'], authToken: token },
        discovery: { dns: false, mdns: false } },
    })).rejects.toBe(native.failure);
    expect(captured?.relay).toEqual({ urls: ['https://relay.invalid/'], authToken: token });
  });

  it('passes custom relay authentication beside unchanged relay URLs', async () => {
    const syntheticToken = 'synthetic-relay-credential-for-tests-only';
    let captured: NodeOptions | undefined;
    native.createNode.mockImplementationOnce(async (options: NodeOptions) => {
      captured = options;
      throw native.failure;
    });

    await expect(IrohEndpoint.create(
      new TextEncoder().encode('p2prpc-relay-auth-propagation'),
      {
        relay: {
          mode: 'custom',
          urls: ['https://relay.invalid'],
          authToken: syntheticToken
        }
      }
    )).rejects.toBe(native.failure);

    expect(captured?.relay).toEqual({
      urls: ['https://relay.invalid/'],
      authToken: syntheticToken
    });
    expect(JSON.stringify((captured?.relay as { urls?: string[] }).urls)).not.toContain(syntheticToken);
  });
});
