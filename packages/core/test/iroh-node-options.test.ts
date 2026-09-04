import type * as IrohHttpNode from '@momics/iroh-http-node';
import type { NodeOptions } from '@momics/iroh-http-node';
import { describe, expect, it, vi } from 'vitest';

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
});
