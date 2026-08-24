import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import * as root from '../src/index.js';
import * as advanced from '../src/advanced.js';
import * as testing from '../src/testing.js';

const t = initTRPC.create();
const router = t.router({ ping: t.procedure.query(() => 'pong') });

describe('public trust-boundary exports', () => {
  it('keeps insecure and raw protocol components out of the package root', () => {
    expect(root).not.toHaveProperty('dangerouslyAllowInsecureSessions');
    expect(root).not.toHaveProperty('createAdvancedP2PNode');
    expect(root).not.toHaveProperty('createTestingP2PNode');
    expect(root).not.toHaveProperty('irohLink');
    expect(root).not.toHaveProperty('ShareRegistry');
    expect(root).not.toHaveProperty('Transfer');

    expect(advanced).toHaveProperty('createAdvancedP2PNode');
    expect(advanced).toHaveProperty('irohLink');
    expect(advanced).toHaveProperty('ShareRegistry');
    expect(testing).toHaveProperty('createTestingP2PNode');
    expect(testing).toHaveProperty('dangerouslyAllowInsecureSessions');
  });

  it('rejects an unbranded security implementation at the production factory', async () => {
    await expect(root.createP2PNode({
      router,
      protocol: { applicationId: 'public-api-test', contractVersion: '1' },
      createContext: () => ({}),
      security: testing.dangerouslyAllowInsecureSessions()
    } as never)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('rejects endpoint injection at the production factory before invoking it', async () => {
    let invoked = false;
    const security = root.createSharedSecretSecurity('x'.repeat(32), { authorize: () => false });
    await expect(root.createP2PNode({
      router,
      protocol: { applicationId: 'public-api-test', contractVersion: '1' },
      createContext: () => ({}),
      security,
      endpointFactory: async () => {
        invoked = true;
        throw new Error('must not run');
      }
    } as never)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(invoked).toBe(false);
  });
});
