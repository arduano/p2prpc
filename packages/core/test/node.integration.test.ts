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
  createSharedSecretSecurity,
  fileDestination,
  fileSource,
  p2pRpcContext,
  type ConnectOptions,
  type P2PNode,
  type P2PRequestFiles,
  type Peer,
  type PeerContext
} from '../src/index.js';
import { createAdvancedP2PNode as createP2PNode } from '../src/node.js';
import { dangerouslyAllowInsecureSessions } from '../src/security/shared-secret.js';
import type { SessionCredential, SessionSecurity } from '../src/security/types.js';
import { IrohEndpoint } from '../src/transport/iroh.js';

const t = initTRPC.context<PeerContext>().create();
const requireTenantHeader = t.middleware(({ ctx, next }) => {
  if (ctx.p2p.request.headers['x-tenant-id'] !== 'tenant-a') {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'missing tenant metadata' });
  }
  return next();
});
let protectedInvocations = 0;
let pullSourcePath: string | undefined;
let capturedRequestFiles: P2PRequestFiles | undefined;
const router = t.router({
  add: t.procedure.input(z.object({ left: z.number(), right: z.number() })).query(({ input, ctx }) => ({
    value: input.left + input.right,
    peer: ctx.p2p.peer.id
  })),
  fail: t.procedure.query(() => {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'integration denied' });
  }),
  inspectSecurity: t.procedure.use(requireTenantHeader).query(({ ctx }) => ({
    tenant: ctx.p2p.request.headers['x-tenant-id'],
    subject: ctx.p2p.auth.principal.subject,
    sessionId: ctx.p2p.auth.id,
    contextFrozen: Object.isFrozen(ctx),
    p2pContextFrozen: Object.isFrozen(ctx.p2p),
    hasUnreservedAuthAlias: Object.hasOwn(ctx, 'auth'),
    connectionFacadeFrozen: Object.isFrozen(ctx.p2p.connection),
    filesFacadeFrozen: Object.isFrozen(ctx.p2p.files)
  })),
  protectedMutation: t.procedure.mutation(() => {
    protectedInvocations += 1;
    return 'should-not-run';
  }),
  requestFile: t.procedure.query(async ({ ctx }) => {
    if (!pullSourcePath) throw new TRPCError({ code: 'NOT_FOUND' });
    return ctx.p2p.files.share(await fileSource(pullSourcePath), { maxDownloads: 1 });
  }),
  captureFileFacade: t.procedure.mutation(({ ctx }) => {
    capturedRequestFiles = ctx.p2p.files;
    return ctx.p2p.files.share({
      name: 'captured.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
  }),
  count: t.procedure.input(z.number().int().positive()).subscription(async function* ({ input, signal }) {
    for (let index = 0; index < input && !signal?.aborted; index += 1) yield index;
  }),
  hold: t.procedure.subscription(async function* ({ signal }) {
    yield 'ready';
    if (signal?.aborted) return;
    await new Promise<void>((resolve) => {
      const finish = () => resolve();
      signal?.addEventListener('abort', finish, { once: true });
    });
  })
});
type Router = typeof router;

const nodes: Array<P2PNode<Router>> = [];
const directories: string[] = [];
afterEach(async () => {
  protectedInvocations = 0;
  pullSourcePath = undefined;
  capturedRequestFiles = undefined;
  await Promise.all(nodes.splice(0).map((node) => node.close()));
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

async function makeNode(
  onIncomingFile?: Parameters<typeof createP2PNode<Router>>[0]['onIncomingFile'],
  security = dangerouslyAllowInsecureSessions(),
  onPeer?: (peer: Peer<Router>) => void
): Promise<P2PNode<Router>> {
  const node = await createP2PNode({
    router,
    protocol: { applicationId: 'integration', contractVersion: '1' },
    createContext: (context) => context,
    security,
    ...(onIncomingFile ? { onIncomingFile } : {}),
    ...(onPeer ? { onPeer: (peer) => onPeer(peer as Peer<Router>) } : {}),
    iroh: {
      relayMode: 'disabled',
      // The integration topology is an explicitly trusted local lab.
      allowDirectAddress: () => true
    }
  });
  nodes.push(node);
  return node;
}

describe('Iroh integration', () => {
  it('connects over advertised LAN addresses with relays genuinely disabled', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc-relayless-lan-regression');
    const allowNonLoopback = (address: string) => !address.startsWith('127.') && !address.startsWith('[::1]');
    const receiver = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      bindAddress: '0.0.0.0:0',
      allowAdvertisedAddress: allowNonLoopback,
      allowDirectAddress: () => true
    });
    const sender = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      bindAddress: '0.0.0.0:0',
      allowAdvertisedAddress: allowNonLoopback,
      allowDirectAddress: () => true
    });
    try {
      const ticket = await receiver.createTicket();
      const encoded = ticket.split('.')[1];
      expect(encoded).toBeDefined();
      const locator = JSON.parse(Buffer.from(encoded!, 'base64url').toString('utf8')) as {
        directAddresses: string[];
        relayUrl: string | null;
      };
      expect(locator.relayUrl).toBeNull();
      expect(locator.directAddresses.length).toBeGreaterThan(0);
      expect(locator.directAddresses.every(allowNonLoopback)).toBe(true);

      const incoming = receiver.accept();
      const outbound = await sender.connect(ticket, alpn, receiver.id);
      const inbound = await incoming;
      expect(inbound).not.toBeNull();

      const accepted = inbound!.acceptUni();
      const send = await outbound.openUni();
      await send.writeAll(Uint8Array.of(0x2a));
      await send.finish();
      const recv = await accepted;
      await expect(recv.readExact(1)).resolves.toEqual(Uint8Array.of(0x2a));
      await expect(recv.expectEnd()).resolves.toBeUndefined();
    } finally {
      await Promise.allSettled([sender.close(), receiver.close()]);
    }
  });

  it('keeps a session reusable after defensive cleanup follows premature EOF', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc-reader-cleanup-regression');
    const receiver = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      allowDirectAddress: () => true
    });
    const sender = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      allowDirectAddress: () => true
    });
    try {
      const incoming = receiver.accept();
      const outbound = await sender.connect(await receiver.createTicket(), alpn, receiver.id);
      const inbound = await incoming;
      expect(inbound).not.toBeNull();

      const firstIncoming = inbound!.acceptUni();
      const firstSend = await outbound.openUni();
      await firstSend.writeAll(Uint8Array.of(1));
      await firstSend.finish();
      const firstRecv = await firstIncoming;
      await expect(firstRecv.readExact(2)).rejects.toMatchObject({ code: 'DISCONNECTED' });
      // readExact() already observed EOF and released the native reader. A
      // later defensive stop must be an idempotent success, not an attempt to
      // cancel the detached WHATWG reader.
      await expect(firstRecv.stop(3n)).resolves.toBeUndefined();

      const canaryIncoming = inbound!.acceptUni();
      const canarySend = await outbound.openUni();
      await canarySend.writeAll(Uint8Array.of(2));
      await canarySend.finish();
      const canaryRecv = await canaryIncoming;
      await expect(canaryRecv.readExact(1)).resolves.toEqual(Uint8Array.of(2));
      await expect(canaryRecv.expectEnd()).resolves.toBeUndefined();
    } finally {
      await Promise.allSettled([sender.close(), receiver.close()]);
    }
  });

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
    const receiver = await makeNode(undefined, createSharedSecretSecurity('a'.repeat(32), { authorize: () => true }));
    const stranger = await makeNode(undefined, createSharedSecretSecurity('b'.repeat(32), { authorize: () => true }));
    await expect(stranger.connect(nodeTarget(receiver))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const [prefix, body, signature] = receiver.ticket().split('.');
    const locator = JSON.parse(Buffer.from(body!, 'base64url').toString('utf8')) as Record<string, unknown>;
    locator.protocol = 'tampered';
    const tampered = `${prefix}.${Buffer.from(JSON.stringify(locator)).toString('base64url')}.${signature}`;
    const target = nodeTarget(receiver);
    await expect(stranger.connect({
      expectedPeerId: target.expectedPeerId,
      expectedPrincipal: target.expectedPrincipal,
      locator: { kind: 'ticket', ticket: tampered }
    }))
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

  it('multiplexes typed RPC, subscriptions, push, and capability pull', { timeout: 120_000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-integration-'));
    directories.push(directory);
    const pushedPath = join(directory, 'pushed.bin');
    const pulledPath = join(directory, 'pulled.bin');
    const sourcePath = join(directory, 'source.bin');
    const content = Buffer.alloc(3 * 1024 * 1024 + 123, 0x5a);
    await writeFile(sourcePath, content);

    const receiver = await makeNode((offer) => {
      expect(Object.isFrozen(offer)).toBe(true);
      return { accept: fileDestination(pushedPath) };
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
      p2pContextFrozen: true,
      hasUnreservedAuthAlias: false,
      connectionFacadeFrozen: true,
      filesFacadeFrozen: true
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

    pullSourcePath = sourcePath;
    const handle = await peer.rpc.requestFile.query();
    const pull = await peer.files.download(handle, fileDestination(pulledPath));
    await pull.result;
    expect(await readFile(pulledPath)).toEqual(content);
  });

  it('keeps one physical session reusable across subscription replacement churn', { timeout: 60_000 }, async () => {
    const receiver = await makeNode();
    const sender = await makeNode();
    const peer = await sender.connect<Router>(nodeTarget(receiver));

    for (let batch = 0; batch < 25; batch += 1) {
      const started = Array.from({ length: 4 }, () => deferred<void>());
      const subscriptions = started.map((ready) => peer.rpc.hold.subscribe(undefined, {
        onStarted: () => ready.resolve(),
        onData: () => undefined,
        onError: (error) => ready.reject(error)
      }));
      await Promise.all(started.map((ready) => ready.promise));
      for (const subscription of subscriptions) subscription.unsubscribe();

      const canaries = await Promise.all(
        Array.from({ length: 4 }, (_, index) =>
          peer.rpc.add.query({ left: batch * 4 + index, right: 1 })
        )
      );
      expect(canaries.map((result) => result.value)).toEqual(
        Array.from({ length: 4 }, (_, index) => batch * 4 + index + 1)
      );
    }

    await expect.poll(async () => (await peer.diagnostics()).resources.active.streams).toBe(0);
  });

  it('reconnects a retained peer proxy after a short authenticated-session expiry', { timeout: 30_000 }, async () => {
    const ttlMs = 250;
    const receiver = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }));
    const sender = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }));
    const peer = await sender.connect<Router>(nodeTarget(receiver));

    await expect(peer.rpc.add.query({ left: 20, right: 1 })).resolves.toMatchObject({ value: 21 });
    const initialSessionId = (await peer.diagnostics()).sessionId;

    await expect.poll(() => sender.getPeer(receiver.id), { timeout: 5_000 }).toBeUndefined();
    await expect.poll(() => receiver.getPeer(sender.id), { timeout: 5_000 }).toBeUndefined();

    await expect(peer.rpc.add.query({ left: 40, right: 2 })).resolves.toMatchObject({ value: 42 });
    expect((await peer.diagnostics()).sessionId).not.toBe(initialSessionId);
  });

  it('reconnects a retained peer proxy after expiry terminates an active subscription', { timeout: 30_000 }, async () => {
    const ttlMs = 250;
    const receiver = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }));
    const sender = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }));
    const peer = await sender.connect<Router>(nodeTarget(receiver));
    const ready = deferred<void>();
    const ended = deferred<void>();
    const subscription = peer.rpc.hold.subscribe(undefined, {
      onData: () => ready.resolve(),
      onComplete: () => ended.resolve(),
      onError: () => ended.resolve()
    });

    await ready.promise;
    const initialSessionId = (await peer.diagnostics()).sessionId;
    await expect.poll(() => sender.getPeer(receiver.id), { timeout: 5_000 }).toBeUndefined();
    await expect.poll(() => receiver.getPeer(sender.id), { timeout: 5_000 }).toBeUndefined();
    await ended.promise;

    await expect(peer.rpc.add.query({ left: 40, right: 2 })).resolves.toMatchObject({ value: 42 });
    expect((await peer.diagnostics()).sessionId).not.toBe(initialSessionId);
    subscription.unsubscribe();
  });

  it('publishes a fresh inbound peer after an expired subscription session is redialed', { timeout: 30_000 }, async () => {
    // Leave enough of the renewed epoch for the reverse-call canary even on a
    // busy CI host; this is still short enough to exercise real timer expiry.
    const ttlMs = 750;
    const inboundPeers: Peer<Router>[] = [];
    const receiver = await makeNode(
      undefined,
      dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }),
      (peer) => inboundPeers.push(peer)
    );
    const sender = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: ttlMs }));
    const outboundPeer = await sender.connect<Router>(nodeTarget(receiver));
    const ready = deferred<void>();
    const ended = deferred<void>();
    const subscription = outboundPeer.rpc.hold.subscribe(undefined, {
      onData: () => ready.resolve(),
      onComplete: () => ended.resolve(),
      onError: () => ended.resolve()
    });

    await ready.promise;
    await expect.poll(() => inboundPeers.length).toBe(1);
    const expiredInboundPeer = inboundPeers[0]!;
    await expect.poll(() => sender.getPeer(receiver.id), { timeout: 5_000 }).toBeUndefined();
    await expect.poll(() => receiver.getPeer(sender.id), { timeout: 5_000 }).toBeUndefined();
    await ended.promise;
    await expect(expiredInboundPeer.rpc.add.query({ left: 1, right: 1 }))
      .rejects.toMatchObject({ cause: { code: 'DISCONNECTED' } });

    await expect(outboundPeer.rpc.add.query({ left: 40, right: 2 })).resolves.toMatchObject({ value: 42 });
    await expect.poll(() => inboundPeers.length, { timeout: 5_000 }).toBe(2);
    const currentInboundPeer = receiver.getPeer<Router>(sender.id);
    expect(currentInboundPeer).toBeDefined();
    await expect(currentInboundPeer!.rpc.add.query({ left: 20, right: 1 })).resolves.toMatchObject({ value: 21 });
    subscription.unsubscribe();
  });

  it('invalidates captured request file facades with their exact authenticated session', { timeout: 30_000 }, async () => {
    const receiver = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: 500 }));
    const sender = await makeNode(undefined, dangerouslyAllowInsecureSessions({ sessionTtlMs: 500 }));
    const peer = await sender.connect<Router>(nodeTarget(receiver));
    const handle = await peer.rpc.captureFileFacade.mutate();
    expect(capturedRequestFiles).toBeDefined();

    await new Promise((resolve) => setTimeout(resolve, 750));
    expect(() => capturedRequestFiles!.share({
      name: 'stale.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    })).toThrow(expect.objectContaining({ code: 'UNAUTHORIZED' }));
    expect(() => capturedRequestFiles!.revoke(handle)).toThrow(expect.objectContaining({ code: 'UNAUTHORIZED' }));
  });
});

function nodeTarget(node: P2PNode<Router>): ConnectOptions {
  return {
    locator: { kind: 'ticket', ticket: node.ticket() },
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

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
  readonly reject: (cause: unknown) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (cause: unknown) => void;
  const promise = new Promise<T>((accept, decline) => {
    resolve = accept;
    reject = decline;
  });
  return { promise, resolve, reject };
}
