import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createNode as createRawIrohNode } from '@momics/iroh-http-node';
import { initTRPC, TRPCError } from '@trpc/server';
import { z } from 'zod';
import { afterEach, describe, expect, it } from 'vitest';
import { RpcFrameKind, StreamKind, writeFrame, writeStreamKind } from '../src/protocol.js';
import { serializeValue } from '../src/rpc/wire.js';
import type { QuicSendStream } from '../src/transport/types.js';
import {
  createP2PNode,
  createSharedSecretSecurity,
  dangerouslyAllowInsecureSessions,
  fileDestination,
  fileSource,
  p2pRpcContext,
  type ConnectOptions,
  type P2PNode,
  type PeerContext,
  type SessionCredential,
  type SessionSecurity
} from '../src/index.js';

const t = initTRPC.context<PeerContext>().create();
const requireTenantHeader = t.middleware(({ ctx, next }) => {
  if (ctx.request.headers['x-tenant-id'] !== 'tenant-a') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'missing tenant metadata' });
  }
  return next();
});
let protectedInvocations = 0;
const router = t.router({
  add: t.procedure.input(z.object({ left: z.number(), right: z.number() })).query(({ input, ctx }) => ({
    value: input.left + input.right,
    peer: ctx.peer.id
  })),
  fail: t.procedure.query(() => {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'integration denied' });
  }),
  inspectSecurity: t.procedure.use(requireTenantHeader).query(({ ctx }) => ({
    tenant: ctx.request.headers['x-tenant-id'],
    subject: ctx.auth.principal.subject,
    sessionId: ctx.auth.id,
    contextFrozen: Object.isFrozen(ctx),
    connectionFacadeFrozen: Object.isFrozen(ctx.connection)
  })),
  protectedMutation: t.procedure.mutation(() => {
    protectedInvocations += 1;
    return 'should-not-run';
  }),
  count: t.procedure.input(z.number().int().positive()).subscription(async function* ({ input, signal }) {
    for (let index = 0; index < input && !signal?.aborted; index += 1) yield index;
  })
});
type Router = typeof router;

const nodes: Array<P2PNode<Router>> = [];
const directories: string[] = [];
afterEach(async () => {
  protectedInvocations = 0;
  await Promise.all(nodes.splice(0).map((node) => node.close()));
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function makeNode(
  onIncomingFile?: Parameters<typeof createP2PNode<Router>>[0]['onIncomingFile'],
  security = dangerouslyAllowInsecureSessions()
): Promise<P2PNode<Router>> {
  const node = await createP2PNode({
    router,
    protocol: { applicationId: 'integration', contractVersion: '1' },
    createContext: (context) => context,
    security,
    ...(onIncomingFile ? { onIncomingFile } : {}),
    iroh: { relayMode: 'disabled' }
  });
  nodes.push(node);
  return node;
}

describe('Iroh integration', () => {
  it('serializes only the canonical credential fields during mutual authentication', { timeout: 30_000 }, async () => {
    const authenticatedCredentials: SessionCredential[] = [];
    const credentialContextsFrozen: boolean[] = [];
    const security: SessionSecurity = {
      getCredential: (context) => {
        credentialContextsFrozen.push(Object.isFrozen(context));
        return {
          scheme: 'P2PRPC-TEST',
          value: 'credential',
          accidentalSecret: 'must-not-cross-the-wire'
        } as SessionCredential;
      },
      authenticate: (credential, context) => {
        authenticatedCredentials.push(credential);
        return {
          id: context.remotePeerId,
          subject: context.remotePeerId,
          expiresAt: Date.now() + 60_000,
          scopes: new Set(['p2prpc:*']),
          claims: {}
        };
      },
      authorize: () => true
    };
    const receiver = await makeNode(undefined, security);
    const sender = await makeNode(undefined, security);

    await sender.connect(nodeTarget(receiver));

    expect(authenticatedCredentials).toHaveLength(2);
    expect(credentialContextsFrozen).toEqual([true, true]);
    for (const credential of authenticatedCredentials) {
      expect(Object.keys(credential).sort()).toEqual(['scheme', 'value']);
      expect(Object.isFrozen(credential)).toBe(true);
      expect('accidentalSecret' in credential).toBe(false);
    }
  });

  it('rejects a peer with the locator but the wrong application credential', { timeout: 30_000 }, async () => {
    const receiver = await makeNode(undefined, createSharedSecretSecurity('a'.repeat(32)));
    const stranger = await makeNode(undefined, createSharedSecretSecurity('b'.repeat(32)));
    await expect(stranger.connect(nodeTarget(receiver))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const [prefix, body, signature] = receiver.ticket().split('.');
    const locator = JSON.parse(Buffer.from(body!, 'base64url').toString('utf8')) as Record<string, unknown>;
    locator.protocol = 'tampered';
    const tampered = `${prefix}.${Buffer.from(JSON.stringify(locator)).toString('base64url')}.${signature}`;
    await expect(stranger.connect({ ...nodeTarget(receiver), ticket: tampered }))
      .rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('rejects a raw peer that knows the signed address but has no application credential', { timeout: 30_000 }, async () => {
    const receiver = await makeNode();
    const [, encoded] = receiver.ticket().split('.');
    const locator = JSON.parse(Buffer.from(encoded!, 'base64url').toString('utf8')) as {
      peerId: string;
      directAddresses: string[];
      relayUrl: string | null;
    };
    const attacker = await createRawIrohNode({ relay: { mode: 'disabled' } });
    try {
      const session = await attacker.dial(locator.peerId, {
        directAddrs: locator.directAddresses,
        ...(locator.relayUrl ? { relayUrl: locator.relayUrl } : {})
      });
      await session.ready;
      const raw = await session.createBidirectionalStream();
      const writer = raw.writable.getWriter();
      const send: QuicSendStream = {
        writeAll: (data) => writer.write(data),
        finish: () => writer.close(),
        reset: async () => writer.abort(),
        setPriority: async () => undefined
      };
      await writeStreamKind(send, StreamKind.Rpc);
      await writeFrame(send, RpcFrameKind.Request, {
        id: 1,
        path: 'protectedMutation',
        type: 'mutation',
        headers: {},
        input: serializeValue(undefined)
      }).catch(() => undefined);
      await new Promise((resolve) => setTimeout(resolve, 250));
      expect(protectedInvocations).toBe(0);
    } finally {
      await attacker.close();
    }
  });

  it('closes expired sessions and obtains fresh credentials on reconnect', { timeout: 30_000 }, async () => {
    const receiver = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: 500 }));
    const sender = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: 500 }));
    const peer = await sender.connect<Router>(nodeTarget(receiver));
    const firstSessionId = peer.session.id;
    await expect(peer.rpc.add.query({ left: 1, right: 1 })).resolves.toMatchObject({ value: 2 });
    await new Promise((resolve) => setTimeout(resolve, 750));
    await expect(peer.rpc.add.query({ left: 2, right: 2 })).resolves.toMatchObject({ value: 4 });
    expect(peer.session.id).not.toBe(firstSessionId);
  });

  it('multiplexes typed RPC, subscriptions, push, and capability pull', { timeout: 30_000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-integration-'));
    directories.push(directory);
    const pushedPath = join(directory, 'pushed.bin');
    const pulledPath = join(directory, 'pulled.bin');
    const sourcePath = join(directory, 'source.bin');
    const content = Buffer.alloc(3 * 1024 * 1024 + 123, 0x5a);
    await writeFile(sourcePath, content);

    const receiver = await makeNode((offer) => {
      expect(Object.isFrozen(offer)).toBe(true);
      offer.accept(fileDestination(pushedPath));
    });
    const sender = await makeNode();
    const peer = await sender.connect<Router>(nodeTarget(receiver));

    await expect(peer.rpc.add.query({ left: 20, right: 22 })).resolves.toMatchObject({ value: 42, peer: sender.id });
    await expect(peer.rpc.inspectSecurity.query(undefined, {
      context: p2pRpcContext({ 'X-Tenant-ID': 'tenant-a' })
    })).resolves.toMatchObject({
      tenant: 'tenant-a',
      subject: sender.id,
      contextFrozen: true,
      connectionFacadeFrozen: true
    });
    await expect(peer.rpc.inspectSecurity.query()).rejects.toMatchObject({ data: { code: 'FORBIDDEN' } });
    await expect(peer.rpc.fail.query()).rejects.toMatchObject({ message: 'integration denied', data: { code: 'FORBIDDEN' } });
    const values: number[] = [];
    await new Promise<void>((resolve, reject) => {
      peer.rpc.count.subscribe(3, {
        onData: (value) => values.push(value),
        onComplete: resolve,
        onError: reject
      });
    });
    expect(values).toEqual([0, 1, 2]);

    const push = await peer.files.sendFile(await fileSource(sourcePath));
    const concurrentCalls = Array.from({ length: 25 }, (_, index) => peer.rpc.add.query({ left: index, right: 1 }));
    const [, callResults] = await Promise.all([push.result, Promise.all(concurrentCalls)]);
    expect(callResults.map((result) => result.value)).toEqual(Array.from({ length: 25 }, (_, index) => index + 1));
    expect(await readFile(pushedPath)).toEqual(content);

    const handle = receiver.files.share(await fileSource(sourcePath), { allowedPeerIds: [sender.id], maxDownloads: 1 });
    const pull = await peer.files.download(handle, fileDestination(pulledPath));
    await pull.result;
    expect(await readFile(pulledPath)).toEqual(content);
  });
});

function nodeTarget(node: P2PNode<Router>): ConnectOptions {
  return {
    ticket: node.ticket(),
    expectedPeerId: node.id,
    expectedPrincipal: {
      id: node.id,
      subject: node.id,
      issuer: null,
      clientId: null,
      tenantId: null
    }
  };
}
