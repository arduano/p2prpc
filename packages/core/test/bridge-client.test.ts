import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import { connectBridge } from '../src/bridge/client.js';
import { controlChannel } from '../src/bridge/control.js';
import { createBridgeHost } from '../src/bridge/host.js';
import { fromByteDuplex, webSocketDuplex } from '../src/bridge/transport/index.js';
import type { BinaryWebSocket } from '../src/bridge/transport/contracts.js';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}

/** Delay the physical close event independently from the caller's close request. */
class Socket implements BinaryWebSocket {
  readyState = 1;
  bufferedAmount = 0;
  binaryType = '';
  closeCalls = 0;
  other!: Socket;
  private readonly messages = new Set<(event: { data: unknown }) => void>();
  private readonly events = new Map<string, Set<() => void>>();
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
  addEventListener(type: string, listener: ((event: { data: unknown }) => void) | (() => void)): void {
    if (type === 'message') this.messages.add(listener);
    else {
      const events = this.events.get(type) ?? new Set();
      events.add(listener as () => void); this.events.set(type, events);
    }
  }
  removeEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
  removeEventListener(type: string, listener: ((event: { data: unknown }) => void) | (() => void)): void {
    if (type === 'message') this.messages.delete(listener);
    else this.events.get(type)?.delete(listener as () => void);
  }
  message(data: unknown): void { for (const listener of this.messages) listener({ data }); }
  send(bytes: Uint8Array<ArrayBuffer>): void {
    if (this.readyState !== 1) throw Error('Socket is not open');
    this.other.message(Uint8Array.from(bytes).buffer);
  }
  close(): void { this.closeCalls++; this.readyState = 2; }
  finish(): void {
    if (this.readyState === 3) return;
    this.readyState = 3;
    for (const listener of this.events.get('close') ?? []) listener();
  }
}
function pair() {
  const client = new Socket(), server = new Socket();
  client.other = server; server.other = client;
  return { client, server, finish() { client.finish(); server.finish(); } };
}
const router = initTRPC.create().router({});
const ready = () => {
  const expiresAt = Date.now() + 60_000;
  return { version: 2, hostId: 'host', peerId: 'browser', sessionId: 'session',
    resume: 'test-resumption-identity-at-least-32-characters', expiresAt,
    principal: { id: 'host', subject: 'host', expiresAt },
    gateway: { peerId: 'gateway', principal: { id: 'gateway', subject: 'gateway', expiresAt } } };
};
async function serve(sockets: ReturnType<typeof pair>, hello: ReturnType<typeof deferred<void>>, permit: Promise<void>) {
  const channel = webSocketDuplex(sockets.server);
  const control = controlChannel(channel);
  expect((await control.read()).kind).toBe(62);
  hello.resolve();
  await permit;
  await control.write(63, ready());
  const raw = fromByteDuplex(control.remaining, { side: 'server', remoteId: 'browser' });
  await raw.closed();
}

describe('Browser Bridge close custody', () => {
  it('repeated Host close waits retain one physical retirement until late closure', async () => {
    const sockets = pair();
    const expiresAt = Date.now() + 60_000;
    const principal = (id: string) => ({ id, subject: id, expiresAt, scopes: new Set<string>(), claims: {} });
    const host = createBridgeHost({ router, createContext: () => ({}),
      authorizeDelegation: () => principal('user'), authorizeOperation: () => true,
      limits: { shutdownTimeoutMs: 15 } });
    const accepted = host.accept({ localPeerId: 'host', peer: { id: 'gateway', direction: 'inbound' },
      auth: { id: 'test-session', generation: 0, establishedAt: Date.now(), expiresAt, principal: principal('gateway') },
      headers: {}, signal: new AbortController().signal, channel: webSocketDuplex(sockets.server) });
    const peer = await connectBridge<typeof router>({ url: 'wss://test', expectedHostId: 'host', socket: () => sockets.client });
    try {
      await expect(host.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
      await new Promise(resolve => setTimeout(resolve, 0));
      const retained = host.diagnostics().tasks;
      expect(retained).toBeGreaterThan(0);
      for (let attempt = 0; attempt < 4; attempt++) {
        await expect(host.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
        await new Promise(resolve => setTimeout(resolve, 0));
        expect(host.diagnostics().tasks).toBe(retained);
      }
      expect(host.diagnostics()).toMatchObject({ closed: true, peers: 1, channels: 1 });
      expect(sockets.server.closeCalls).toBe(1);
      sockets.finish();
      await accepted;
      await host.close();
      expect(host.diagnostics()).toMatchObject({ closed: true, peers: 0, channels: 0, tasks: 0 });
    } finally {
      sockets.finish();
      await Promise.allSettled([accepted, peer.close(), host.close()]);
    }
  });

  it('forwards Host errors and retries retirement without readmitting a failed-close lifetime', async () => {
    const sockets = pair();
    const error = deferred<unknown>();
    const expiresAt = Date.now() + 60_000;
    const principal = (id: string) => ({ id, subject: id, expiresAt, scopes: new Set<string>(), claims: {} });
    const host = createBridgeHost({ router, createContext: () => ({}),
      authorizeDelegation: () => principal('user'), authorizeOperation: () => true,
      onError: cause => error.resolve(cause), limits: { shutdownTimeoutMs: 15 } });
    const accepted = host.accept({ localPeerId: 'host', peer: { id: 'gateway', direction: 'inbound' },
      auth: { id: 'test-session', generation: 0, establishedAt: Date.now(), expiresAt, principal: principal('gateway') },
      headers: {}, signal: new AbortController().signal, channel: webSocketDuplex(sockets.server) });
    const peer = await connectBridge<typeof router>({ url: 'wss://test', expectedHostId: 'host', socket: () => sockets.client });
    try {
      const peerId = host.diagnostics().entries[0]!.peerId;
      sockets.server.message('invalid binary carrier data');
      await expect(error.promise).resolves.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(host.revoke(peerId)).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(host.diagnostics()).toMatchObject({ peers: 1, entries: [{ retiring: true, closed: true }] });
      await expect(host.revoke(peerId)).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(sockets.server.closeCalls).toBe(1);
      sockets.finish();
      await accepted;
      await host.revoke(peerId);
      expect(host.diagnostics()).toMatchObject({ peers: 0, channels: 0 });
    } finally {
      sockets.finish();
      await Promise.allSettled([accepted, peer.close(), host.close()]);
    }
  });

  it('retries failed close waits on the same owner and succeeds only after physical closure', async () => {
    const sockets = pair();
    const server = serve(sockets, deferred<void>(), Promise.resolve());
    const peer = await connectBridge<typeof router>({ url: 'wss://test', expectedHostId: 'host',
      socket: () => sockets.client, limits: { shutdownTimeoutMs: 15 } });
    try {
      const first = peer.close();
      expect(peer.close()).toBe(first);
      await expect(first).rejects.toBeInstanceOf(AggregateError);
      const retained = peer.diagnostics().tasks;
      expect(retained).toBeGreaterThan(0);
      for (let attempt = 0; attempt < 4; attempt++) {
        await expect(peer.close()).rejects.toBeInstanceOf(AggregateError);
        expect(peer.diagnostics().tasks).toBe(retained);
      }
      expect(sockets.client.closeCalls).toBe(1);
      await expect(peer.reconnect()).rejects.toMatchObject({ code: 'DISCONNECTED' });
      sockets.finish();
      await server;
      const completed = peer.close();
      await completed;
      expect(peer.close()).toBe(completed);
      expect(peer.diagnostics()).toMatchObject({ closed: true, connected: false, tasks: 0 });
      expect(peer.diagnostics().resources).toMatchObject({ queued: 0, active: { streams: 0, callbacks: 0 } });
    } finally {
      sockets.finish();
      await Promise.allSettled([server, peer.close()]);
    }
  });

  it('bounds close while a replacement carrier is still in admission and retains its late cleanup', async () => {
    const first = pair(), second = pair();
    const firstServer = serve(first, deferred<void>(), Promise.resolve());
    const secondHello = deferred<void>(), allowReady = deferred<void>();
    const secondServer = serve(second, secondHello, allowReady.promise).catch(() => undefined);
    let calls = 0;
    const peer = await connectBridge<typeof router>({ url: 'wss://test', expectedHostId: 'host',
      socket: () => calls++ === 0 ? first.client : second.client,
      limits: { setupTimeoutMs: 1000, shutdownTimeoutMs: 15 } });
    let reconnect: Promise<unknown> | undefined;
    try {
      first.finish();
      await firstServer;
      reconnect = peer.reconnect().catch(error => error);
      await secondHello.promise;
      await expect(peer.close()).rejects.toBeInstanceOf(AggregateError);
      await expect(peer.close()).rejects.toBeInstanceOf(AggregateError);
      expect(calls).toBe(2);
      expect(second.client.closeCalls).toBe(1);
      expect(second.client.readyState).toBe(2);
      second.finish();
      allowReady.resolve();
      await secondServer;
      await expect(reconnect).resolves.toMatchObject({ code: 'DISCONNECTED' });
      await peer.close();
      expect(peer.diagnostics()).toMatchObject({ closed: true, tasks: 0 });
    } finally {
      first.finish(); second.finish(); allowReady.resolve();
      await Promise.allSettled([firstServer, secondServer, reconnect, peer.close()]);
    }
  });
});
