import { initTRPC } from '@trpc/server';
import { describe, expect, it, vi } from 'vitest';
import { createBridgeHost } from '../src/bridge/host.js';
import { openNativeBridge, type NativeBridgeOffer } from '../src/bridge/native.js';
import type { ByteDuplex } from '../src/bridge/transport/contracts.js';
import { P2PError } from '../src/errors.js';
import { TaskGroup } from '../src/runtime/task-group.js';
import type { SessionPrincipal } from '../src/security/types.js';
import type { QuicBiStream, QuicConnection } from '../src/transport/types.js';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}
function principal(id: string): SessionPrincipal {
  return { id, subject: id, expiresAt: Date.now() + 60_000, scopes: new Set(['test']), claims: {} };
}

describe('Bridge admission custody', () => {
  it('retains timed-out delegation until actual settlement and refuses a late ghost attachment', async () => {
    const started = deferred<void>();
    const release = deferred<SessionPrincipal>();
    const closed = deferred<void>();
    let reads = 0, writes = 0;
    const channel: ByteDuplex = {
      closed: closed.promise,
      close: () => { closed.resolve(); },
      write: async () => { writes += 1; },
      readable: { [Symbol.asyncIterator]: () => ({
        async next() { reads += 1; await closed.promise; return { done: true as const, value: undefined }; }
      }) }
    };
    const user = principal('user');
    const gateway = principal('gateway');
    const host = createBridgeHost({
      router: initTRPC.create().router({}), createContext: () => ({}),
      authorizeOperation: () => true,
      authorizeDelegation: () => { started.resolve(); return release.promise; },
      limits: { setupTimeoutMs: 20, shutdownTimeoutMs: 30 }
    });
    const offer: NativeBridgeOffer = {
      localPeerId: 'host', peer: { id: 'gateway', direction: 'inbound' },
      auth: { id: 'verified-test-session', generation: 0, establishedAt: Date.now(), expiresAt: gateway.expiresAt, principal: gateway },
      headers: {}, signal: new AbortController().signal, channel
    };
    const accepted = host.accept(offer);
    const observed = accepted.then(() => ({ allowed: true as const }), error => ({ error }));
    try {
      await started.promise;
      // Actual carrier close proves that admission's deadline fired.
      await channel.closed;
      expect(host.diagnostics()).toMatchObject({ admitting: 1, peers: 0 });
      expect(host.diagnostics().tasks).toBeGreaterThan(0);
      await expect(host.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(host.diagnostics().tasks).toBeGreaterThan(0);
      release.resolve(user);
      await expect(observed).resolves.toMatchObject({ error: { code: 'TIMEOUT' } });
      await host.close();
      expect(host.diagnostics()).toMatchObject({ closed: true, admitting: 0, tasks: 0, channels: 0, peers: 0 });
      expect({ reads, writes }).toEqual({ reads: 0, writes: 0 });
    } finally {
      release.resolve(user);
      await Promise.allSettled([observed, host.close()]);
    }
  });

  it('rejects cancelled native opening while retaining late-stream reset and stop ownership', async () => {
    const openStarted = deferred<void>();
    const lateStream = deferred<QuicBiStream>();
    const resetStarted = deferred<void>();
    const stopStarted = deferred<void>();
    const resetReleased = deferred<void>();
    const stopReleased = deferred<void>();
    const resetSettled = deferred<void>();
    const reset = vi.fn(async () => { resetStarted.resolve(); await resetReleased.promise; resetSettled.resolve(); });
    const stop = vi.fn(async () => { stopStarted.resolve(); await stopReleased.promise; });
    const write = vi.fn(async () => {});
    const stream: QuicBiStream = {
      send: { writeAll: write, finish: async () => {}, reset, setPriority: async () => {} },
      recv: { readExact: async () => { throw new Error('Cancelled stream must not read'); }, expectEnd: async () => {}, stop }
    };
    const physicalClose = vi.fn();
    const unexpected = async (): Promise<never> => { throw new Error('Unexpected outer connection operation'); };
    const connection: QuicConnection = {
      remoteId: 'host', side: 'client',
      openBi: async () => { openStarted.resolve(); return lateStream.promise; },
      acceptBi: unexpected, openUni: unexpected, acceptUni: unexpected,
      closed: unexpected, close: physicalClose,
      stats: async () => ({ rttMs: null, sentBytes: 0, receivedBytes: 0, lostPackets: 0 })
    };
    const owner = new TaskGroup('Native bridge opening test');
    const controller = new AbortController();
    const opening = openNativeBridge(async () => connection, { signal: controller.signal }, work => { owner.track(work); });
    try {
      await openStarted.promise;
      controller.abort(new P2PError('CANCELLED', 'Test cancelled'));
      await expect(opening).rejects.toMatchObject({ code: 'CANCELLED' });
      expect(owner.size).toBe(1);
      await expect(owner.join({ timeoutMs: 20 })).rejects.toMatchObject({ code: 'TIMEOUT' });
      lateStream.resolve(stream);
      await Promise.all([resetStarted.promise, stopStarted.promise]);
      resetReleased.resolve();
      await resetSettled.promise;
      expect(owner.size).toBe(1); // Stop still owns the same late stream.
      stopReleased.resolve();
      await owner.join({ timeoutMs: 200 });
      expect(owner.size).toBe(0);
      expect(reset).toHaveBeenCalledTimes(1);
      expect(stop).toHaveBeenCalledTimes(1);
      expect(write).not.toHaveBeenCalled();
      expect(physicalClose).not.toHaveBeenCalled();
    } finally {
      controller.abort(); lateStream.resolve(stream); resetReleased.resolve(); stopReleased.resolve();
      await Promise.allSettled([opening, owner.close(undefined, { timeoutMs: 200 })]);
    }
  });
});
