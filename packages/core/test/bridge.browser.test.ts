import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:https';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { initTRPC } from '@trpc/server';
import { build } from 'esbuild';
import { chromium } from 'playwright-core';
import { WebSocketServer } from 'ws';
import { expect, it } from 'vitest';
import { z } from 'zod';
import type { connectBridge } from '../src/bridge/client.js';
import type { controlChannel, readySchema } from '../src/bridge/control.js';
import type { BridgeContext } from '../src/bridge/contracts.js';
import { relayBridge } from '../src/bridge/gateway.js';
import { createBridgeHost } from '../src/bridge/host.js';
import type { webSocketDuplex } from '../src/bridge/transport/index.js';
import type { BinaryWebSocket } from '../src/bridge/transport/contracts.js';
import { blobSource, memoryDestination } from '../src/files/browser.js';
import type { FileManifest, IncomingFileDecision } from '../src/files/types.js';
import { createAdvancedP2PNode, type P2PNode, type PeerContext } from '../src/node.js';
import { createSharedSecretSecurity } from '../src/security/shared-secret.js';

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(yes => { resolve = yes; });
  return { promise, resolve };
}
function makeRouter(state: { calls: number; subscriptions: number; released: ReturnType<typeof deferred>; entered: ReturnType<typeof deferred> }) {
  const t = initTRPC.context<BridgeContext>().create();
  return t.router({
    inspect: t.procedure.query(({ ctx }) => ({ principal: ctx.bridge.principal.id, peer: ctx.bridge.peerId,
      gateway: ctx.bridge.via.peerId, calls: state.calls })),
    once: t.procedure.input(z.object({ originalId: z.literal('observation-loss') })).mutation(async ({ input }) => {
      state.calls += 1;
      state.entered.resolve();
      // The observable can go away after this effect; its receipt must not be
      // invented or its invocation automatically replayed by the bridge.
      await state.released.promise;
      return input.originalId;
    }),
    watch: t.procedure.subscription(async function* ({ signal }) {
      try {
        yield 'watch-ready';
        await new Promise<void>(yes => {
          if (signal?.aborted) yes();
          else signal?.addEventListener('abort', () => yes(), { once: true });
        });
      } finally { state.subscriptions += 1; }
    }),
    file: t.procedure.query(({ ctx }) => ctx.bridge.files.share(blobSource(new Blob(['shared across reconnect']), { name: 'shared.txt' }), { maxDownloads: 1 }))
  });
}
type Router = ReturnType<typeof makeRouter>;
interface BrowserHarness {
  inspect(): Promise<{ principal: string; peer: string; gateway: string; calls: number }>;
  subscribe(): void;
  snapshot(): { watch: string[]; watchErrors: number; lost: string; connected: boolean };
  startLost(): void;
  rememberShare(): Promise<void>;
  reconnect(): Promise<void>;
  pull(): Promise<string>;
  startPush(): void;
  pushResult(): Promise<{ id: string; resumed: boolean; size: number }>;
  probeResumption(): Promise<{ unknownDenied: boolean; foreignDenied: boolean }>;
  close(): Promise<void>;
}
type BrowserGlobal = typeof globalThis & { bridgeHarness: BrowserHarness };

/** This function is typechecked against the ACTUAL Host router. Its runtime is
 * bundled below and runs only inside Chromium; dependencies are explicit. */
async function browserMain(
  connect: typeof connectBridge,
  source: typeof blobSource,
  destination: typeof memoryDestination,
  control: typeof controlChannel,
  ready: typeof readySchema,
  duplex: typeof webSocketDuplex,
  config: { url: string; expectedHostId: string }
): Promise<void> {
  const errors: string[] = [];
  const carriers: Array<{ socket: WebSocket; closeCalls: number }> = [];
  const peer = await connect<Router>({ ...config,
    onError: error => { errors.push(error.message); },
    socket(url) {
      const socket = new WebSocket(url);
      const carrier = { socket, closeCalls: 0 };
      const close = socket.close.bind(socket);
      socket.close = (...args: Parameters<WebSocket['close']>): void => { carrier.closeCalls += 1; close(...args); };
      carriers.push(carrier);
      return socket;
    },
    limits: { setupTimeoutMs: 10_000, ioTimeoutMs: 15_000 }
  });
  const watch: string[] = [];
  let watchErrors = 0;
  let lost = 'not-started';
  let subscription: { unsubscribe(): void } | undefined;
  let shared: Awaited<ReturnType<typeof peer.rpc.file.query>> | undefined;
  let push: Promise<{ id: string; resumed: boolean; size: number }> | undefined;
  const harness: BrowserHarness = {
    inspect: () => peer.rpc.inspect.query(),
    subscribe() {
      subscription?.unsubscribe();
      subscription = peer.rpc.watch.subscribe(undefined, { onData: value => { watch.push(value); }, onError: () => { watchErrors += 1; } });
    },
    snapshot: () => ({ watch: [...watch], watchErrors, lost, connected: peer.diagnostics().connected }),
    startLost() {
      lost = 'pending';
      void peer.rpc.once.mutate({ originalId: 'observation-loss' }).then(() => { lost = 'completed'; }, () => { lost = 'interrupted'; });
    },
    async rememberShare() { shared = await peer.rpc.file.query(); },
    reconnect: () => peer.reconnect(),
    async pull() {
      if (!shared) throw new Error('No original capability');
      const output = destination({ maxBytes: 1024 });
      const transfer = await peer.files.download(shared, output, { operationId: 'same-capability-after-loss', chunkSize: 64 * 1024, lanes: 1 });
      try { await transfer.result; }
      catch (cause) { throw new Error(`Pull failed: ${String(cause)}; ${JSON.stringify(peer.diagnostics())}`, { cause }); }
      return await output.blob()!.text();
    },
    startPush() {
      const bytes = new Uint8Array(384 * 1024);
      for (let index = 0; index < bytes.length; index += 1) bytes[index] = index % 251;
      push = (async () => {
        const transfer = await peer.files.sendFile(source(new Blob([bytes]), { name: 'browser.bin' }), { transferId: 'browser-owned-transfer', chunkSize: 64 * 1024, lanes: 1 });
        const result = await transfer.result;
        return { id: result.manifest.transferId, resumed: result.resumed, size: result.manifest.size };
      })();
      void push.catch(() => {});
    },
    async pushResult() { if (!push) throw new Error('No push'); return await push; },
    async probeResumption() {
      const hello = async (url: string, resume?: string) => {
        const channel = duplex(new WebSocket(url));
        try {
          const handshake = control(channel);
          await handshake.write(62, { version: 1, ...(resume ? { resume } : {}) });
          const frame = await handshake.read();
          if (frame.kind !== 63) throw new Error('No BrowserReady');
          return ready.parse(frame.value);
        } finally { await channel.close(); await channel.closed; }
      };
      // This creates the second and final logical browser lifetime. Its secret
      // stays in this Chromium closure and never enters logs or a receipt.
      const probe = await hello(config.url);
      let unknownDenied = false, foreignDenied = false;
      try { await hello(config.url, 'unknown-resumption-secret-01234567890123456789'); } catch { unknownDenied = true; }
      try { await hello(config.url.replace('/owner-a', '/owner-b'), probe.resume); } catch { foreignDenied = true; }
      return { unknownDenied, foreignDenied };
    },
    async close() {
      subscription?.unsubscribe();
      try { await peer.close(); }
      catch (cause) {
        const failures = cause instanceof AggregateError ? cause.errors.map(error => String(error)) : [String(cause)];
        const sockets = carriers.map(carrier => ({ readyState: carrier.socket.readyState, closeCalls: carrier.closeCalls }));
        throw new Error(`Browser cleanup failed: ${JSON.stringify({ failures, errors, sockets })}; ${JSON.stringify(peer.diagnostics())}`, { cause });
      }
    }
  };
  (globalThis as BrowserGlobal).bridgeHarness = harness;
}

it('runs browser/WSS/Iroh RPC and files with honest observation loss, retained identity and isolated cleanup', { timeout: 180_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'p2prpc-bridge-integration-'));
  const state = { calls: 0, subscriptions: 0, entered: deferred(), released: deferred() };
  const firstChunk = deferred(), releaseChunk = deferred();
  const received = memoryDestination({ maxBytes: 1024 * 1024 });
  const offers: FileManifest[] = [];
  const deniedResumptions: string[] = [];
  const delegatedPrincipals: string[] = [];
  let paused = false;
  const router = makeRouter(state);
  const n = initTRPC.context<PeerContext>().create();
  const nativeRouter = n.router({ health: n.procedure.query(() => 'outer-peer-alive') });
  const nodes: Array<P2PNode<typeof nativeRouter>> = [];
  let gatewayId = '';
  const hostService = createBridgeHost({
    router, createContext: context => context,
    authorizeDelegation(offer) {
      if (offer.peer.id !== gatewayId || offer.auth.principal.id !== gatewayId) throw new Error('Untrusted Gateway');
      const id = offer.headers['x-lab-browser'];
      if (id !== 'owner-a' && id !== 'owner-b') throw new Error('No verified fixture identity');
      delegatedPrincipals.push(id);
      return { id, subject: id, expiresAt: Math.min(Date.now() + 120_000, offer.auth.expiresAt), scopes: new Set(['bridge:lab']), claims: {} };
    },
    authorizeOperation: () => true,
    onIncomingFile(offer): IncomingFileDecision {
      offers.push(offer.manifest);
      return { accept: {
        prepare: (manifest, signal) => received.prepare(manifest, signal),
        async writeChunk(manifest, index, bytes, signal) {
          await received.writeChunk(manifest, index, bytes, signal);
          if (!paused) { paused = true; firstChunk.resolve(); await releaseChunk.promise; }
        },
        finalize: (manifest, context) => received.finalize(manifest, context),
        abort: (manifest, options, signal) => received.abort(manifest, options, signal)
      } };
    },
    limits: { maxPeers: 2, setupTimeoutMs: 10_000, shutdownTimeoutMs: 10_000, ioTimeoutMs: 15_000 }
  });
  const makeNode = async (host: boolean) => {
    const node = await createAdvancedP2PNode({ router: nativeRouter, createContext: context => context,
      protocol: { applicationId: 'bridge-owned-integration', contractVersion: '1' },
      security: createSharedSecretSecurity('owned-disposable-bridge-lab-key-32-bytes', { authorize: () => true }),
      onError: error => { nativeErrors.push(`${error.code}: ${error.message}`); },
      ...(host ? { onBridge: async offer => {
        try { await hostService.accept(offer); } catch (cause) {
          if (cause instanceof Error && cause.message === 'Unknown Bridge resumption') deniedResumptions.push(cause.message);
          throw cause;
        }
      } } : {}),
      iroh: { relay: { mode: 'disabled' }, discovery: { dns: false, mdns: false }, allowDirectAddress: () => true }
    });
    nodes.push(node); return node;
  };
  let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
  let server: ReturnType<typeof createServer> | undefined;
  let sockets: WebSocketServer | undefined;
  const relays = new Set<Promise<void>>();
  const browserErrors: string[] = [];
  let cleaned = false;
  let phase = 'setup';
  const proven: string[] = [];
  const nativeErrors: string[] = [];
  const failures: unknown[] = [];
  try {
    const host = await makeNode(true), gateway = await makeNode(false);
    gatewayId = gateway.id;
    const outer = await gateway.connect<typeof nativeRouter>({ locator: { kind: 'ticket', ticket: host.ticket() }, expectedPeerId: host.id,
      expectedPrincipal: { id: host.id, subject: host.id, issuer: null, clientId: null, tenantId: null } });
    expect(await outer.rpc.health.query()).toBe('outer-peer-alive');
    await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
      '-subj', '/CN=localhost', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')], { timeout: 10_000 });
    let program = '';
    server = createServer({ key: await readFile(join(directory, 'key.pem')), cert: await readFile(join(directory, 'cert.pem')) }, (request, response) => {
      response.setHeader('content-type', request.url === '/browser.js' ? 'text/javascript' : 'text/html');
      response.end(request.url === '/browser.js' ? program : '<!doctype html><script type="module" src="/browser.js"></script>');
    });
    sockets = new WebSocketServer({ server });
    sockets.on('connection', (socket, request) => {
      // Explicit test authentication fixture. Only this trusted Gateway code
      // constructs the delegation header; BrowserHello cannot supply it.
      const principal = request.url === '/owner-b' ? 'owner-b' : 'owner-a';
      const relay = relayBridge(socket as unknown as BinaryWebSocket, outer, { headers: { 'x-lab-browser': principal } }).catch(() => {});
      relays.add(relay); void relay.finally(() => relays.delete(relay));
    });
    await new Promise<void>(yes => server!.listen(0, '127.0.0.1', yes));
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('No HTTPS listener');
    const url = `https://127.0.0.1:${address.port}`;
    const bundle = await build({ stdin: { contents: `import {connectBridge,blobSource,memoryDestination} from '@arduano/p2prpc-core/browser';
      import {controlChannel,readySchema} from './src/bridge/control.ts';
      import {webSocketDuplex} from './src/bridge/transport/index.ts';
      (${browserMain.toString()})(connectBridge,blobSource,memoryDestination,controlChannel,readySchema,webSocketDuplex,${JSON.stringify({ url: `${url.replace('https:', 'wss:')}/owner-a`, expectedHostId: host.id })}).catch(error=>{globalThis.browserFailure=String(error)});`,
      resolveDir: resolve(import.meta.dirname, '..'), sourcefile: 'bridge-browser-fixture.ts' }, bundle: true, write: false, platform: 'browser', format: 'esm', target: 'es2022', logLevel: 'silent' });
    program = bundle.outputFiles[0]!.text;
    browser = await chromium.launch({ ...(process.env.P2PRPC_CHROMIUM_EXECUTABLE ? { executablePath: process.env.P2PRPC_CHROMIUM_EXECUTABLE } : {}), headless: true });
    const page = await browser.newPage({ ignoreHTTPSErrors: true });
    let bootFailure!: (error: Error) => void;
    const bootFailed = new Promise<never>((_, no) => { bootFailure = no; });
    void bootFailed.catch(() => {});
    page.on('pageerror', error => { browserErrors.push(error.message); bootFailure(error); });
    await page.goto(url);
    await Promise.race([bootFailed, page.waitForFunction(() => 'bridgeHarness' in globalThis || 'browserFailure' in globalThis, undefined, { timeout: 20_000 })]);
    expect(await page.evaluate(() => Reflect.get(globalThis, 'browserFailure'))).toBeUndefined();
    phase = 'rpc';
    const first = await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.inspect());
    expect(first).toMatchObject({ principal: 'owner-a', gateway: gateway.id, calls: 0 });
    proven.push('typed-browser-query-and-authenticated-context');
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.subscribe());
    await expect.poll(() => page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.snapshot().watch)).toEqual(['watch-ready']);
    proven.push('browser-subscription');
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.rememberShare());
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.startLost());
    await state.entered.promise;
    for (const socket of sockets.clients) socket.terminate();
    await expect.poll(() => page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.snapshot().lost)).toBe('interrupted');
    state.released.resolve();
    await expect.poll(() => state.subscriptions).toBe(1);
    await expect.poll(() => hostService.diagnostics().admitting).toBe(0);
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.reconnect());
    const after = await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.inspect());
    expect(after).toMatchObject({ principal: 'owner-a', peer: first.peer, calls: 1 });
    expect(state.calls).toBe(1);
    proven.push('reply-loss-no-mutation-replay-and-same-logical-peer');
    phase = 'retained-capability-pull';
    expect(await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.pull())).toBe('shared across reconnect');
    proven.push('original-shared-capability-survives-reconnect');
    phase = 'interrupted-file-push';
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.startPush());
    await firstChunk.promise;
    for (const socket of sockets.clients) socket.terminate();
    releaseChunk.resolve();
    const pushed = await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.pushResult());
    expect(pushed).toMatchObject({ id: 'browser-owned-transfer', resumed: true, size: 384 * 1024 });
    expect(new Set(offers.map(offer => offer.transferId))).toEqual(new Set(['browser-owned-transfer']));
    const bytes = new Uint8Array(await received.blob()!.arrayBuffer());
    expect(bytes).toEqual(Uint8Array.from({ length: 384 * 1024 }, (_, index) => index % 251));
    proven.push('interrupted-blob-push-resumes-same-transfer-and-exact-bytes');
    phase = 'resumption-denials';
    expect(await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.probeResumption())).toEqual({ unknownDenied: true, foreignDenied: true });
    await expect.poll(() => deniedResumptions.length).toBe(2);
    expect(delegatedPrincipals).toContain('owner-b');
    expect(hostService.diagnostics().peers).toBe(2);
    proven.push('unknown-and-foreign-principal-resumption-refused-without-new-peer');
    expect(await outer.rpc.health.query()).toBe('outer-peer-alive');
    phase = 'explicit-browser-close';
    await page.evaluate(() => (globalThis as BrowserGlobal).bridgeHarness.close());
    proven.push('browser-close-proved');
    await expect.poll(() => relays.size).toBe(0);
    await hostService.close();
    expect(hostService.diagnostics()).toMatchObject({ closed: true, peers: 0, admitting: 0, channels: 0, tasks: 0 });
    expect(await outer.rpc.health.query()).toBe('outer-peer-alive');
    expect(browserErrors).toEqual([]);
    proven.push('host-close-proved-and-borrowed-outer-peer-alive');
    cleaned = true;
  } catch (cause) {
    console.info(JSON.stringify({ phase, nativeErrors, host: hostService.diagnostics() }));
    failures.push(cause);
  }
  finally {
    state.released.resolve(); releaseChunk.resolve();
    const cleanupFailures: unknown[] = [];
    const reap = async (task: () => Promise<unknown>): Promise<void> => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([Promise.resolve().then(task), new Promise<never>((_, no) => {
          timer = setTimeout(() => no(new Error('Owned integration cleanup deadline exceeded')), 15_000);
        })]);
      } catch (cause) { cleanupFailures.push(cause); }
      finally { if (timer) clearTimeout(timer); }
    };
    await reap(async () => browser?.close());
    for (const socket of sockets?.clients ?? []) socket.terminate();
    await reap(() => hostService.close());
    await reap(async () => {
      const results = await Promise.allSettled(nodes.map(node => node.close()));
      for (const result of results) if (result.status === 'rejected') throw result.reason;
    });
    await reap(() => Promise.allSettled([...relays]));
    if (sockets) await reap(() => new Promise<void>((yes, no) => sockets!.close(error => error ? no(error) : yes())));
    if (server) { server.closeAllConnections(); await reap(() => new Promise<void>((yes, no) => server!.close(error => error ? no(error) : yes()))); }
    await rm(directory, { recursive: true, force: true });
    console.info(JSON.stringify({ campaign: 'bridge-real-browser-iroh', irohEndpoints: nodes.length, chromium: browser ? 1 : 0,
      logicalPeerLimit: 2, modelCalls: 0, nativeAgentAllocations: 0, ownedDirectoryRemoved: true,
      cleanupFailures: cleanupFailures.length, proven, journeyCompleted: cleaned }));
    failures.push(...cleanupFailures);
  }
  if (failures.length) throw new AggregateError(failures, 'Bridge integration or owned cleanup failed');
});
