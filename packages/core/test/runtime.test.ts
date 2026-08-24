import { describe, expect, it, vi } from 'vitest';
import { HandshakeRateLimiter } from '../src/runtime/rate-limit.js';
import { ManagedConnection } from '../src/runtime/managed-connection.js';
import { DEFAULT_RESOURCE_LIMITS, ResourceScheduler } from '../src/runtime/resources.js';
import { TaskGroup } from '../src/runtime/task-group.js';
import { RuntimeSlotRegistry } from '../src/runtime/runtime-slots.js';
import type {
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicRecvStream,
  QuicSendStream
} from '../src/transport/types.js';

describe('structured runtime ownership', () => {
  it('bounds runtime slots by distinct peer ID while sharing same-peer claims', async () => {
    const registry = new RuntimeSlotRegistry<object>(1);
    const first = registry.reserve('peer-a');
    const duplicate = registry.reserve('peer-a');
    expect(registry.occupied).toBe(1);
    expect(() => registry.reserve('peer-b')).toThrow(/runtime limit/i);

    const runtime = Object.freeze({ id: 'runtime-a' });
    first.commit(runtime);
    first.release();
    expect(registry.get('peer-a')).toBe(runtime);
    expect(registry.size).toBe(1);

    expect(registry.delete('peer-a', Object.freeze({}))).toBe(false);
    expect(registry.delete('peer-a', runtime)).toBe(true);
    expect(registry.size).toBe(0);
    // The duplicate admission still owns peer-a's keyed slot even though the
    // committed runtime was removed.
    expect(() => registry.reserve('peer-b')).toThrow(/runtime limit/i);
    duplicate.release();

    const replacement = registry.reserve('peer-b');
    replacement.release();
    await registry.whenEmpty();
    expect(registry.occupied).toBe(0);
  });

  it('closes runtime-slot admission without erasing existing ownership', async () => {
    const registry = new RuntimeSlotRegistry<object>(1);
    const claim = registry.reserve('peer');
    const runtime = Object.freeze({ id: 'runtime' });
    claim.commit(runtime);
    registry.close();

    expect(() => registry.reserve('other')).toThrow(/closed/);
    expect(() => {
      const uncommitted = new RuntimeSlotRegistry<object>(1);
      const pending = uncommitted.reserve('peer');
      uncommitted.close();
      pending.commit({});
    }).toThrow(/closed/);
    expect(registry.get('peer')).toBe(runtime);

    claim.release();
    expect(registry.delete('peer', runtime)).toBe(true);
    await registry.whenEmpty();
  });

  it('joins every tracked library task before close resolves', async () => {
    const group = new TaskGroup('test');
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    void group.run(() => pending);
    const closing = group.close();
    let closed = false;
    void closing.then(() => { closed = true; });
    await Promise.resolve();
    expect(closed).toBe(false);
    release();
    await closing;
    expect(group.size).toBe(0);
  });

  it('bounds a shutdown wait without forgetting non-cooperative work', async () => {
    const group = new TaskGroup('test');
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    group.track(pending);
    group.abort();

    await expect(group.join({ timeoutMs: 5 })).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(group.size).toBe(1);

    release();
    await group.join({ timeoutMs: 100 });
    expect(group.size).toBe(0);
  });

  it('retains already-started work discovered after closing begins', async () => {
    const group = new TaskGroup('test');
    group.abort();
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    group.track(pending);

    const joining = group.join({ timeoutMs: 100 });
    await Promise.resolve();
    expect(group.size).toBe(1);
    release();
    await joining;
    expect(group.size).toBe(0);
  });

  it('does not linearize an empty join before work tracked in the next microtask epoch', async () => {
    const group = new TaskGroup('test');
    group.abort();
    const joining = group.join({ timeoutMs: 100 });
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    await Promise.resolve();
    group.track(pending);

    let joined = false;
    void joining.then(() => { joined = true; });
    await Promise.resolve();
    expect(joined).toBe(false);
    expect(group.size).toBe(1);

    release();
    await joining;
    expect(group.size).toBe(0);
  });

  it('observes the expected rejection when run loses a shutdown race', async () => {
    const group = new TaskGroup('test');
    group.abort(new Error('closed'));
    const unhandled: unknown[] = [];
    const onUnhandled = (cause: unknown): void => { unhandled.push(cause); };
    process.on('unhandledRejection', onUnhandled);
    try {
      void group.run(() => undefined);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      await expect(group.run(() => undefined)).rejects.toThrow('closed');
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('bounds and fairly drains peer queues with exact-once leases', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 10, callbacks: 1, queued: 4 },
      perPeer: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 10, callbacks: 1, queued: 2 },
      perPrincipal: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 10, callbacks: 1, queued: 4 },
      fileDataReserve: testFileDataReserve(),
      fileControlReserve: testFileControlReserve(),
      generalReserve: testGeneralReserve()
    });
    const first = scheduler.tryAcquire('peer-a', { streams: 1 })!;
    const order: string[] = [];
    const second = scheduler.acquire('peer-a', { streams: 1 }).then((lease) => { order.push('a'); return lease; });
    const third = scheduler.acquire('peer-b', { streams: 1 }).then((lease) => { order.push('b'); return lease; });
    expect(scheduler.snapshot().queued).toBe(2);
    first.release();
    first.release();
    const a = await second;
    expect(order).toEqual(['a']);
    a.release();
    const b = await third;
    expect(order).toEqual(['a', 'b']);
    b.release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, active: { streams: 0 } });
  });

  it('cancels queued admission without leaking peer state', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const generalBuffer = generalReservedBytes(DEFAULT_RESOURCE_LIMITS, 'perPeer');
    const held = scheduler.tryAcquire('peer', { bufferedBytes: generalBuffer })!;
    const controller = new AbortController();
    const queued = scheduler.acquire('peer', { bufferedBytes: 1 }, controller.signal);
    controller.abort(new Error('stop'));
    await expect(queued).rejects.toThrow('stop');
    held.release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0 });
  });

  it('rejects pre-aborted admission without granting or retaining owner state', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const controller = new AbortController();
    controller.abort(new Error('already stopped'));

    for (let index = 0; index < 1_000; index += 1) {
      await expect(scheduler.acquire(
        { peerId: `peer-${index}`, principalId: `principal-${index}` },
        { streams: 1 },
        controller.signal
      )).rejects.toThrow('already stopped');
    }

    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      peers: 0,
      principals: 0,
      active: { streams: 0 }
    });
  });

  it('compacts cancelled round-robin entries even when no lease is released', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const held = scheduler.tryAcquire('holder', {
      bufferedBytes: generalReservedBytes(DEFAULT_RESOURCE_LIMITS, 'perPeer')
    })!;

    for (let index = 0; index < 100; index += 1) {
      const controller = new AbortController();
      const queued = scheduler.acquire('holder', { bufferedBytes: 1 }, controller.signal);
      controller.abort(new Error('stop'));
      await expect(queued).rejects.toThrow('stop');
    }

    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 1 });
    expect((scheduler as unknown as { ready: string[] }).ready).toHaveLength(0);
    held.release();
  });

  it('enforces one principal quota across multiple authenticated endpoint keys', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 2, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 4 },
      perPeer: { handshakes: 1, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 2 },
      perPrincipal: { handshakes: 2, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 10, callbacks: 1, queued: 4 },
      fileDataReserve: testFileDataReserve(),
      fileControlReserve: testFileControlReserve(),
      generalReserve: testGeneralReserve()
    });
    const first = scheduler.tryAcquire({ peerId: 'device-a', principalId: 'workload' }, { streams: 1 })!;
    const second = scheduler.acquire({ peerId: 'device-b', principalId: 'workload' }, { streams: 1 });
    const unrelated = scheduler.tryAcquire({ peerId: 'device-c', principalId: 'other' }, { streams: 1 })!;
    expect(scheduler.snapshot()).toMatchObject({ queued: 1, peers: 3, principals: 2 });
    unrelated.release();
    first.release();
    (await second).release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it('does not let a blocked transfer admission deadlock its active transfer stream', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 2, streams: 6, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 34, callbacks: 2, queued: 8 },
      perPeer: { handshakes: 1, streams: 6, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 34, callbacks: 2, queued: 8 },
      perPrincipal: { handshakes: 2, streams: 6, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 34, callbacks: 2, queued: 8 },
      fileDataReserve: testFileDataReserve(),
      fileControlReserve: testFileControlReserve(),
      generalReserve: testGeneralReserve()
    });
    const owner = { peerId: 'peer', principalId: 'principal' };
    const activeTransfer = scheduler.tryAcquire(owner, { inboundTransfers: 1 })!;
    const nextTransfer = scheduler.acquire(owner, { inboundTransfers: 1 });
    const completionStream = scheduler.acquire(owner, { streams: 1, bufferedBytes: 1 });

    const streamLease = await completionStream;
    expect(scheduler.snapshot()).toMatchObject({ queued: 1, active: { streams: 1, inboundTransfers: 1 } });
    streamLease.release();
    activeTransfer.release();
    (await nextTransfer).release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it('keeps both file-data directions admissible when general stream and buffer capacity is saturated', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 2, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 60, callbacks: 2, queued: 4 },
      perPeer: { handshakes: 1, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 60, callbacks: 2, queued: 4 },
      perPrincipal: { handshakes: 2, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 60, callbacks: 2, queued: 4 },
      fileDataReserve: {
        global: testDirectionalReserve(10),
        perPeer: testDirectionalReserve(10),
        perPrincipal: testDirectionalReserve(10)
      },
      fileControlReserve: testFileControlReserve(10),
      generalReserve: testGeneralReserve(10)
    });
    const owner = { peerId: 'peer', principalId: 'principal' };
    const firstGeneral = scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10 })!;
    const secondGeneral = scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10 })!;
    const blockedGeneral = scheduler.acquire(owner, { streams: 1, bufferedBytes: 1 });

    const outboundLane = await scheduler.acquire(owner, {
      streams: 1,
      bufferedBytes: 10,
      fileData: 'outbound'
    });
    expect(scheduler.tryAcquire(owner, {
      streams: 1,
      bufferedBytes: 10,
      fileData: 'outbound'
    })).toBeUndefined();
    const inboundLane = await scheduler.acquire(owner, {
      streams: 1,
      bufferedBytes: 10,
      fileData: 'inbound'
    });

    expect(scheduler.snapshot()).toMatchObject({
      queued: 1,
      active: { streams: 4, bufferedBytes: 40 }
    });

    outboundLane.release();
    inboundLane.release();
    firstGeneral.release();
    (await blockedGeneral).release();
    secondGeneral.release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it('keeps all four directional file stream classes admissible beside saturated general capacity', () => {
    const limits = {
      global: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      perPeer: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      perPrincipal: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      fileDataReserve: {
        global: testDirectionalReserve(10),
        perPeer: testDirectionalReserve(10),
        perPrincipal: testDirectionalReserve(10)
      },
      fileControlReserve: testFileControlReserve(10),
      generalReserve: testGeneralReserve(10)
    } as const;
    const scheduler = new ResourceScheduler(limits);
    const owner = { peerId: 'peer', principalId: 'principal' };
    const leases = [
      scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10 }),
      scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10, fileControl: 'outbound' }),
      scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10, fileControl: 'inbound' }),
      scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10, fileData: 'outbound' }),
      scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10, fileData: 'inbound' })
    ];

    expect(leases.every((lease) => lease !== undefined)).toBe(true);
    expect(scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 1 })).toBeUndefined();
    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      active: { streams: 5, bufferedBytes: 50 }
    });

    for (const lease of leases) lease!.release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it('charges stream overflow from every directional file class to one shared general budget', () => {
    const limits = sharedOverflowLimits();
    for (const [firstIndex, firstClass] of directionalFileClasses.entries()) {
      for (const secondClass of directionalFileClasses.slice(firstIndex + 1)) {
        const scheduler = new ResourceScheduler(limits);
        const owner = { peerId: 'peer', principalId: 'principal' };
        const first = scheduler.tryAcquire(owner, {
          ...firstClass,
          streams: 2,
          bufferedBytes: 10
        });
        expect(first).toBeDefined();

        // Four directional reserves and one protected general stream leave
        // exactly one borrowable stream. The first class spends it by
        // exceeding its reserve, so a second class cannot also overflow.
        expect(scheduler.tryAcquire(owner, {
          ...secondClass,
          streams: 2,
          bufferedBytes: 10
        })).toBeUndefined();
        const reservedOnly = scheduler.tryAcquire(owner, {
          ...secondClass,
          streams: 1,
          bufferedBytes: 10
        });
        expect(reservedOnly).toBeDefined();

        reservedOnly!.release();
        first!.release();
        expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
      }
    }
  });

  it('charges buffer overflow from every directional file class to one shared general budget', () => {
    const limits = sharedOverflowLimits();
    for (const [firstIndex, firstClass] of directionalFileClasses.entries()) {
      for (const secondClass of directionalFileClasses.slice(firstIndex + 1)) {
        const scheduler = new ResourceScheduler(limits);
        const owner = { peerId: 'peer', principalId: 'principal' };
        const first = scheduler.tryAcquire(owner, {
          ...firstClass,
          streams: 1,
          bufferedBytes: 20
        });
        expect(first).toBeDefined();

        // Four directional reserves and ten protected general bytes leave ten
        // borrowable bytes. The first class has already spent them.
        expect(scheduler.tryAcquire(owner, {
          ...secondClass,
          streams: 1,
          bufferedBytes: 20
        })).toBeUndefined();
        const reservedOnly = scheduler.tryAcquire(owner, {
          ...secondClass,
          streams: 1,
          bufferedBytes: 10
        });
        expect(reservedOnly).toBeDefined();

        reservedOnly!.release();
        first!.release();
        expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
      }
    }
  });

  it('does not let a queued general request hide an available directional reserve', async () => {
    const limits = {
      global: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      perPeer: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      perPrincipal: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 1, queued: 4 },
      fileDataReserve: {
        global: testDirectionalReserve(10),
        perPeer: testDirectionalReserve(10),
        perPrincipal: testDirectionalReserve(10)
      },
      fileControlReserve: testFileControlReserve(10),
      generalReserve: testGeneralReserve(10)
    } as const;
    const scheduler = new ResourceScheduler(limits);
    const owner = { peerId: 'peer', principalId: 'principal' };
    const general = scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10 })!;
    const blockedGeneral = scheduler.acquire(owner, { streams: 1, bufferedBytes: 1 });

    const inboundControl = scheduler.tryAcquire(owner, {
      streams: 1,
      bufferedBytes: 10,
      fileControl: 'inbound'
    });
    expect(inboundControl).toBeDefined();
    expect(scheduler.snapshot()).toMatchObject({
      queued: 1,
      active: { streams: 2, bufferedBytes: 20 }
    });

    inboundControl!.release();
    general.release();
    (await blockedGeneral).release();
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it.each(['perPeer', 'perPrincipal'] as const)(
    'keeps the %s RPC reserve non-borrowable by file-class overflow',
    (constrainedLevel) => {
      const scheduler = new ResourceScheduler(rpcReserveLimits(constrainedLevel));
      const owner = { peerId: 'peer', principalId: 'principal' };
      const files = [
        scheduler.tryAcquire(owner, {
          streams: 2,
          bufferedBytes: 20,
          fileData: 'outbound'
        }),
        ...directionalFileClasses.slice(1).map((resourceClass) => scheduler.tryAcquire(owner, {
          ...resourceClass,
          streams: 1,
          bufferedBytes: 10
        }))
      ];

      expect(files.every((lease) => lease !== undefined)).toBe(true);
      expect(scheduler.tryAcquire(owner, {
        streams: 1,
        bufferedBytes: 10,
        fileControl: 'inbound'
      })).toBeUndefined();

      const rpc = scheduler.tryAcquire(owner, { streams: 1, bufferedBytes: 10 });
      expect(rpc).toBeDefined();
      expect(scheduler.snapshot()).toMatchObject({
        queued: 0,
        active: { streams: 6, bufferedBytes: 60 }
      });

      rpc!.release();
      for (const lease of files) lease!.release();
      expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
    }
  );

  it('keeps the global RPC reserve non-borrowable across distributed file traffic', () => {
    const scheduler = new ResourceScheduler(rpcReserveLimits('global'));
    const fileRequests = [
      { streams: 1, bufferedBytes: 10, fileData: 'outbound' as const },
      { streams: 1, bufferedBytes: 10, fileData: 'outbound' as const },
      { streams: 1, bufferedBytes: 10, fileData: 'inbound' as const },
      { streams: 1, bufferedBytes: 10, fileControl: 'outbound' as const },
      { streams: 1, bufferedBytes: 10, fileControl: 'inbound' as const }
    ];
    const files = fileRequests.map((request, index) => scheduler.tryAcquire(
      { peerId: `file-peer-${index}`, principalId: `file-principal-${index}` },
      request
    ));

    expect(files.every((lease) => lease !== undefined)).toBe(true);
    const nextOwner = { peerId: 'rpc-peer', principalId: 'rpc-principal' };
    expect(scheduler.tryAcquire(nextOwner, {
      streams: 1,
      bufferedBytes: 10,
      fileData: 'inbound'
    })).toBeUndefined();

    const rpc = scheduler.tryAcquire(nextOwner, { streams: 1, bufferedBytes: 10 });
    expect(rpc).toBeDefined();
    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      active: { streams: 6, bufferedBytes: 60 }
    });

    rpc!.release();
    for (const lease of files) lease!.release();
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('reserves inbound progress when both peers fill their outbound transfer quotas', () => {
    const peerA = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const peerB = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const ownerA = { peerId: 'peer-b', principalId: 'principal-b' };
    const ownerB = { peerId: 'peer-a', principalId: 'principal-a' };
    const outboundA = Array.from(
      { length: DEFAULT_RESOURCE_LIMITS.perPeer.outboundTransfers },
      () => peerA.tryAcquire(ownerA, { outboundTransfers: 1 })!
    );
    const outboundB = Array.from(
      { length: DEFAULT_RESOURCE_LIMITS.perPeer.outboundTransfers },
      () => peerB.tryAcquire(ownerB, { outboundTransfers: 1 })!
    );

    const inboundA = peerA.tryAcquire(ownerA, { inboundTransfers: 1 });
    const inboundB = peerB.tryAcquire(ownerB, { inboundTransfers: 1 });

    expect(inboundA).toBeDefined();
    expect(inboundB).toBeDefined();
    expect(peerA.snapshot()).toMatchObject({
      queued: 0,
      active: {
        outboundTransfers: DEFAULT_RESOURCE_LIMITS.perPeer.outboundTransfers,
        inboundTransfers: 1
      }
    });
    expect(peerB.snapshot()).toMatchObject({
      queued: 0,
      active: {
        outboundTransfers: DEFAULT_RESOURCE_LIMITS.perPeer.outboundTransfers,
        inboundTransfers: 1
      }
    });

    inboundA!.release();
    inboundB!.release();
    for (const lease of outboundA) lease.release();
    for (const lease of outboundB) lease.release();
    expect(peerA.snapshot()).toMatchObject({ peers: 0, principals: 0 });
    expect(peerB.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('admits incoming lanes after both peers have consumed their outbound lane reserves', () => {
    const limits = {
      global: { handshakes: 2, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 2, queued: 4 },
      perPeer: { handshakes: 1, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 2, queued: 4 },
      perPrincipal: { handshakes: 2, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 50, callbacks: 2, queued: 4 },
      fileDataReserve: {
        global: testDirectionalReserve(10),
        perPeer: testDirectionalReserve(10),
        perPrincipal: testDirectionalReserve(10)
      },
      fileControlReserve: testFileControlReserve(10),
      generalReserve: testGeneralReserve(10)
    } as const;
    const peers = [new ResourceScheduler(limits), new ResourceScheduler(limits)];
    const leases = peers.map((scheduler, index) => {
      const owner = { peerId: `peer-${index}`, principalId: `principal-${index}` };
      const outboundControl = scheduler.tryAcquire(owner, {
        streams: 1, bufferedBytes: 10, fileControl: 'outbound'
      })!;
      const inboundControl = scheduler.tryAcquire(owner, {
        streams: 1, bufferedBytes: 10, fileControl: 'inbound'
      })!;
      const outboundLane = scheduler.tryAcquire(owner, {
        streams: 1,
        bufferedBytes: 10,
        fileData: 'outbound'
      })!;
      const inboundLane = scheduler.tryAcquire(owner, {
        streams: 1,
        bufferedBytes: 10,
        fileData: 'inbound'
      });
      expect(inboundLane).toBeDefined();
      expect(scheduler.snapshot()).toMatchObject({
        queued: 0,
        active: { streams: 4, bufferedBytes: 40 }
      });
      return [outboundControl, inboundControl, outboundLane, inboundLane!] as const;
    });

    for (const peerLeases of leases) for (const lease of peerLeases) lease.release();
    for (const scheduler of peers) {
      expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
    }
  });

  it('rejects a request that can never fit its authenticated principal quota', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 2, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 4 },
      perPeer: { handshakes: 1, streams: 6, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 2 },
      perPrincipal: { handshakes: 2, streams: 5, outboundTransfers: 1, inboundTransfers: 1, bufferedBytes: 10, callbacks: 1, queued: 4 },
      fileDataReserve: testFileDataReserve(),
      fileControlReserve: testFileControlReserve(),
      generalReserve: testGeneralReserve()
    });

    await expect(scheduler.acquire(
      { peerId: 'device', principalId: 'workload' },
      { streams: 2 }
    )).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(scheduler.snapshot()).toMatchObject({ queued: 0, peers: 0, principals: 0 });
  });

  it('keeps active ownership visible after close until the resource settles', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const generalBuffer = generalReservedBytes(DEFAULT_RESOURCE_LIMITS, 'perPeer');
    const active = scheduler.tryAcquire(
      { peerId: 'peer', principalId: 'principal' },
      { streams: 1, bufferedBytes: generalBuffer }
    )!;
    const queued = scheduler.acquire(
      { peerId: 'peer', principalId: 'principal' },
      { bufferedBytes: 1 }
    );
    scheduler.close();
    await expect(queued).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(scheduler.snapshot()).toEqual({
      active: {
        handshakes: 0,
        streams: 1,
        outboundTransfers: 0,
        inboundTransfers: 0,
        bufferedBytes: generalBuffer,
        callbacks: 0
      },
      queued: 0,
      peers: 1,
      principals: 1,
      closed: true
    });
    let idle = false;
    const idleness = scheduler.whenIdle().then(() => { idle = true; });
    await Promise.resolve();
    expect(idle).toBe(false);
    active.release();
    await idleness;
    expect(scheduler.snapshot()).toMatchObject({
      active: { streams: 0, bufferedBytes: 0 },
      peers: 0,
      principals: 0,
      closed: true
    });
  });

  it('waits for one exact endpoint and principal without retaining unrelated owners', async () => {
    const scheduler = new ResourceScheduler({
      global: { handshakes: 4, streams: 6, outboundTransfers: 4, inboundTransfers: 4, bufferedBytes: 34, callbacks: 4, queued: 4 },
      perPeer: { handshakes: 2, streams: 5, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 2 },
      perPrincipal: { handshakes: 2, streams: 5, outboundTransfers: 2, inboundTransfers: 2, bufferedBytes: 18, callbacks: 2, queued: 4 },
      fileDataReserve: testFileDataReserve(),
      fileControlReserve: testFileControlReserve(),
      generalReserve: testGeneralReserve()
    });
    const first = scheduler.tryAcquire(
      { peerId: 'peer-a', principalId: 'principal' },
      { callbacks: 1 }
    )!;
    const otherPeer = scheduler.tryAcquire(
      { peerId: 'peer-b', principalId: 'principal' },
      { callbacks: 1 }
    )!;
    const otherPrincipal = scheduler.tryAcquire(
      { peerId: 'peer-a', principalId: 'other' },
      { streams: 1 }
    )!;

    let exactIdle = false;
    const exact = scheduler.whenOwnerIdle({ peerId: 'peer-a', principalId: 'principal' })
      .then(() => { exactIdle = true; });
    let peerIdle = false;
    const entirePeer = scheduler.whenOwnerIdle('peer-a').then(() => { peerIdle = true; });
    otherPeer.release();
    await Promise.resolve();
    expect(exactIdle).toBe(false);
    expect(peerIdle).toBe(false);

    first.release();
    await exact;
    expect(exactIdle).toBe(true);
    expect(peerIdle).toBe(false);
    otherPrincipal.release();
    await entirePeer;
    expect(peerIdle).toBe(true);
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('does not start or account native opens for pre-aborted BI and UNI requests', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    let biOpenCalls = 0;
    let uniOpenCalls = 0;
    const base = testConnection(async () => {
      biOpenCalls += 1;
      return recordingStream();
    });
    const managed = new ManagedConnection(
      {
        ...base,
        openUni: async () => {
          uniOpenCalls += 1;
          return recordingStream().send;
        }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      16
    );
    const controller = new AbortController();
    controller.abort(new Error('already cancelled'));

    await expect(managed.openBi({ signal: controller.signal })).rejects.toThrow('already cancelled');
    await expect(managed.openUni({ signal: controller.signal })).rejects.toThrow('already cancelled');

    expect({ biOpenCalls, uniOpenCalls }).toEqual({ biOpenCalls: 0, uniOpenCalls: 0 });
    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      peers: 0,
      principals: 0,
      active: { streams: 0, bufferedBytes: 0 }
    });
  });

  it('promptly rejects a cancelled hung BI open and retains admission until physical closure', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const nativeOpenStarted = deferred<void>();
    const physicallyClosed = deferred<string>();
    let closeRequests = 0;
    const base = testConnection(() => {
      nativeOpenStarted.resolve();
      return new Promise<never>(() => undefined);
    });
    const managed = new ManagedConnection(
      {
        ...base,
        closed: () => physicallyClosed.promise,
        close: () => { closeRequests += 1; }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      16
    );
    const controller = new AbortController();

    const opening = managed.openBi({ signal: controller.signal });
    await nativeOpenStarted.promise;
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });
    controller.abort(new Error('cancel hung BI open'));

    await expect(opening).rejects.toThrow('cancel hung BI open');
    expect(closeRequests).toBe(1);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });

    physicallyClosed.resolve('closed');
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('promptly rejects a cancelled hung UNI open and retains admission until physical closure', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const nativeOpenStarted = deferred<void>();
    const physicallyClosed = deferred<string>();
    let closeRequests = 0;
    const base = testConnection(async () => recordingStream());
    const managed = new ManagedConnection(
      {
        ...base,
        openUni: () => {
          nativeOpenStarted.resolve();
          return new Promise<never>(() => undefined);
        },
        closed: () => physicallyClosed.promise,
        close: () => { closeRequests += 1; }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      16
    );
    const controller = new AbortController();

    const opening = managed.openUni({ fileData: 'outbound', signal: controller.signal });
    await nativeOpenStarted.promise;
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });
    controller.abort(new Error('cancel hung UNI open'));

    await expect(opening).rejects.toThrow('cancel hung UNI open');
    expect(closeRequests).toBe(1);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });

    physicallyClosed.resolve('closed');
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('terminally cleans BI and UNI streams which arrive after their opens are cancelled', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const biOpened = deferred<QuicBiStream>();
    const uniOpened = deferred<QuicSendStream>();
    const biStarted = deferred<void>();
    const uniStarted = deferred<void>();
    const biStream = recordingStream();
    const uniStream = recordingStream().send;
    let closeRequests = 0;
    const base = testConnection(() => {
      biStarted.resolve();
      return biOpened.promise;
    });
    const managed = new ManagedConnection(
      {
        ...base,
        openUni: () => {
          uniStarted.resolve();
          return uniOpened.promise;
        },
        close: () => { closeRequests += 1; }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      16
    );
    const biController = new AbortController();
    const uniController = new AbortController();
    const openingBi = managed.openBi({ signal: biController.signal });
    const openingUni = managed.openUni({ fileData: 'outbound', signal: uniController.signal });
    await Promise.all([biStarted.promise, uniStarted.promise]);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 2, bufferedBytes: 32 });

    biController.abort(new Error('cancel late opens'));
    await expect(openingBi).rejects.toThrow('cancel late opens');
    // Quarantining one physical multiplexed connection cancels every opening
    // stream on it, independently of which operation first detected failure.
    await expect(openingUni).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(closeRequests).toBe(1);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 2, bufferedBytes: 32 });

    biOpened.resolve(biStream);
    uniOpened.resolve(uniStream);
    await expect.poll(() => biStream.send.resetCalls).toBe(1);
    await expect.poll(() => biStream.recv.stopCalls).toBe(1);
    await expect.poll(() => uniStream.resetCalls).toBe(1);
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('releases a pending stream-open lease and closes a stream which arrives after connection close', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const opened = deferred<QuicBiStream>();
    const nativeOpenStarted = deferred<void>();
    const stream = recordingStream();
    const connection = testConnection(() => {
      nativeOpenStarted.resolve();
      return opened.promise;
    });
    const managed = new ManagedConnection(
      connection,
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      1,
      1
    );

    const opening = managed.openBi();
    const rejectedOpening = expect(opening).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await nativeOpenStarted.promise;
    expect(scheduler.snapshot().active.streams).toBe(1);
    managed.close(0n, new Uint8Array());
    await expect.poll(() => scheduler.snapshot().active.streams).toBe(0);
    opened.resolve(stream);

    await rejectedOpening;
    await expect.poll(() => stream.send.resetCalls).toBe(1);
    await expect.poll(() => stream.recv.stopCalls).toBe(1);
    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      peers: 0,
      principals: 0,
      active: { streams: 0, bufferedBytes: 0 }
    });
  });

  it('classifies ManagedConnection unidirectional opens as file-data lanes', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const owner = { peerId: 'peer', principalId: 'principal' };
    const reserve = DEFAULT_RESOURCE_LIMITS.fileDataReserve.perPeer;
    const controls = DEFAULT_RESOURCE_LIMITS.fileControlReserve.perPeer;
    const general = scheduler.tryAcquire(owner, {
      streams: DEFAULT_RESOURCE_LIMITS.perPeer.streams -
        reserve.outbound.streams - reserve.inbound.streams -
        controls.outbound.streams - controls.inbound.streams,
      bufferedBytes: generalReservedBytes(DEFAULT_RESOURCE_LIMITS, 'perPeer')
    })!;
    const stream = recordingStream().send;
    const base = testConnection(async () => recordingStream());
    const managed = new ManagedConnection(
      { ...base, openUni: async () => stream },
      scheduler,
      owner,
      new AbortController().signal,
      1,
      reserve.outbound.bufferedBytes
    );

    const opened = await managed.openUni();
    expect(scheduler.snapshot()).toMatchObject({
      queued: 0,
      active: {
        streams: DEFAULT_RESOURCE_LIMITS.perPeer.streams - reserve.inbound.streams -
          controls.outbound.streams - controls.inbound.streams,
        bufferedBytes: DEFAULT_RESOURCE_LIMITS.perPeer.bufferedBytes - reserve.inbound.bufferedBytes -
          controls.outbound.bufferedBytes - controls.inbound.bufferedBytes
      }
    });
    await opened.finish();
    general.release();
    expect(scheduler.snapshot()).toMatchObject({ peers: 0, principals: 0 });
  });

  it('keeps a pending native stream-open lease until physical connection closure is confirmed', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const opened = deferred<QuicBiStream>();
    const physicallyClosed = deferred<string>();
    const nativeOpenStarted = deferred<void>();
    const stream = recordingStream();
    let closeRequests = 0;
    const base = testConnection(() => {
      nativeOpenStarted.resolve();
      return opened.promise;
    });
    const connection: QuicConnection = {
      ...base,
      closed: () => physicallyClosed.promise,
      close: () => { closeRequests += 1; }
    };
    const managed = new ManagedConnection(
      connection,
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      1,
      1
    );

    const opening = managed.openBi();
    const rejectedOpening = expect(opening).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await nativeOpenStarted.promise;
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 1 });

    managed.close(0n, new Uint8Array());
    await Promise.resolve();
    expect(closeRequests).toBe(1);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 1 });

    physicallyClosed.resolve('closed');
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });

    opened.resolve(stream);
    await rejectedOpening;
    expect(stream.send.resetCalls).toBe(1);
    expect(stream.recv.stopCalls).toBe(1);
  });

  it('quarantines a native stream if adoption throws after open', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const physicallyClosed = deferred<string>();
    let closeRequests = 0;
    const poisoned: QuicBiStream = Object.freeze({
      get send(): QuicSendStream { throw new Error('poisoned native stream'); },
      recv: recordingStream().recv
    });
    const base = testConnection(async () => poisoned);
    const managed = new ManagedConnection(
      {
        ...base,
        closed: () => physicallyClosed.promise,
        close: () => { closeRequests += 1; }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      1
    );

    await expect(managed.openBi()).rejects.toThrow('poisoned native stream');
    expect(closeRequests).toBe(1);
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });

    physicallyClosed.resolve('closed');
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });
  });

  it('preserves an adoption failure when the adapter also throws while closing', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const physicallyClosed = deferred<string>();
    const poisoned: QuicBiStream = Object.freeze({
      get send(): QuicSendStream { throw new Error('primary adoption failure'); },
      recv: recordingStream().recv
    });
    const base = testConnection(async () => poisoned);
    const managed = new ManagedConnection(
      {
        ...base,
        closed: () => physicallyClosed.promise,
        close: () => { throw new Error('secondary close failure'); }
      },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      1
    );

    await expect(managed.openBi()).rejects.toThrow('primary adoption failure');
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });

    physicallyClosed.resolve('closed');
    await expect.poll(() => scheduler.snapshot().active).toMatchObject({ streams: 0, bufferedBytes: 0 });
  });

  it('does not treat a rejected closed observation as physical stream settlement', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const stream = recordingStream();
    const base = testConnection(async () => stream);
    const managed = new ManagedConnection(
      { ...base, closed: () => Promise.reject(new Error('adapter closed observation failed')) },
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      1
    );

    await managed.openBi();
    await Promise.resolve();
    await Promise.resolve();
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });
  });

  it('retains a bidirectional stream lease until both halves terminate', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const stream = recordingStream();
    const managed = new ManagedConnection(
      testConnection(async () => stream),
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      1
    );

    const opened = await managed.openBi();
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });
    await opened.send.finish();
    expect(scheduler.snapshot().active.streams).toBe(1);
    await opened.recv.expectEnd();
    expect(scheduler.snapshot()).toMatchObject({
      peers: 0,
      principals: 0,
      active: { streams: 0, bufferedBytes: 0 }
    });
  });

  it('settles each bidirectional stream half at most once', async () => {
    const scheduler = new ResourceScheduler(DEFAULT_RESOURCE_LIMITS);
    const stream = recordingStream();
    const managed = new ManagedConnection(
      testConnection(async () => stream),
      scheduler,
      { peerId: 'peer', principalId: 'principal' },
      new AbortController().signal,
      16,
      1
    );

    const opened = await managed.openBi();
    await opened.recv.expectEnd();
    await opened.recv.stop(1n);
    await opened.recv.expectEnd();
    expect(scheduler.snapshot().active).toMatchObject({ streams: 1, bufferedBytes: 16 });

    await opened.send.finish();
    expect(scheduler.snapshot()).toMatchObject({
      peers: 0,
      principals: 0,
      active: { streams: 0, bufferedBytes: 0 }
    });
  });
});

describe('handshake admission', () => {
  it('rejects invalid direct configuration and unbounded peer identifiers', () => {
    const valid = {
      globalBurst: 3,
      globalRatePerSecond: 1,
      peerBurst: 1,
      peerRatePerSecond: 1,
      maxPeerEntries: 2
    };
    for (const options of [
      { ...valid, globalBurst: 0 },
      { ...valid, peerBurst: Number.NaN },
      { ...valid, globalRatePerSecond: 0 },
      { ...valid, peerRatePerSecond: Number.POSITIVE_INFINITY },
      { ...valid, maxPeerEntries: 1.5 },
      { ...valid, now: () => -1 }
    ]) {
      expect(() => new HandshakeRateLimiter(options)).toThrowError(
        expect.objectContaining({ code: 'RESOURCE_LIMIT' })
      );
    }
    const limiter = new HandshakeRateLimiter(valid);
    expect(() => limiter.admit('')).toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(() => limiter.admit('x'.repeat(2_049))).toThrowError(
      expect.objectContaining({ code: 'INVALID_FRAME' })
    );
  });

  it('does not mint tokens across a wall-clock rollback', () => {
    let now = 1_000;
    const limiter = new HandshakeRateLimiter({
      globalBurst: 1,
      globalRatePerSecond: 1,
      peerBurst: 1,
      peerRatePerSecond: 1,
      maxPeerEntries: 2,
      now: () => now
    });
    limiter.admit('a');
    now = 0;
    expect(() => limiter.admit('b')).toThrow(/Handshake rate/);
    now = 1_000;
    expect(() => limiter.admit('b')).toThrow(/Handshake rate/);
    now = 2_000;
    limiter.admit('b');
  });

  it('enforces both global and bounded per-peer token buckets without charging peer-local denials globally', () => {
    let now = 0;
    const limiter = new HandshakeRateLimiter({
      globalBurst: 3,
      globalRatePerSecond: 1,
      peerBurst: 1,
      peerRatePerSecond: 1,
      maxPeerEntries: 2,
      now: () => now
    });
    limiter.admit('a');
    expect(() => limiter.admit('a')).toThrow(/Peer handshake/);
    limiter.admit('b');
    now = 1_000;
    limiter.admit('a');
    limiter.admit('c');
    expect(() => limiter.admit('d')).toThrow(/Handshake rate/);
    vi.restoreAllMocks();
  });
});

function testFileDataReserve() {
  return {
    global: testDirectionalReserve(1),
    perPeer: testDirectionalReserve(1),
    perPrincipal: testDirectionalReserve(1)
  } as const;
}

function testFileControlReserve(bufferedBytes = 1) {
  return {
    global: testDirectionalReserve(bufferedBytes),
    perPeer: testDirectionalReserve(bufferedBytes),
    perPrincipal: testDirectionalReserve(bufferedBytes)
  } as const;
}

function testDirectionalReserve(bufferedBytes: number) {
  return {
    outbound: { streams: 1, bufferedBytes },
    inbound: { streams: 1, bufferedBytes }
  } as const;
}

const directionalFileClasses = [
  { fileData: 'outbound' },
  { fileData: 'inbound' },
  { fileControl: 'outbound' },
  { fileControl: 'inbound' }
] as const;

function sharedOverflowLimits() {
  const level = {
    handshakes: 1,
    streams: 6,
    outboundTransfers: 1,
    inboundTransfers: 1,
    bufferedBytes: 60,
    callbacks: 1,
    queued: 4
  } as const;
  return {
    global: level,
    perPeer: level,
    perPrincipal: level,
    fileDataReserve: {
      global: testDirectionalReserve(10),
      perPeer: testDirectionalReserve(10),
      perPrincipal: testDirectionalReserve(10)
    },
    fileControlReserve: testFileControlReserve(10),
    generalReserve: testGeneralReserve(10)
  } as const;
}

function rpcReserveLimits(constrainedLevel: 'global' | 'perPeer' | 'perPrincipal') {
  const constrained = {
    handshakes: 1,
    streams: 6,
    outboundTransfers: 1,
    inboundTransfers: 1,
    bufferedBytes: 60,
    callbacks: 1,
    queued: 4
  } as const;
  const roomy = { ...constrained, streams: 10, bufferedBytes: 100 } as const;
  return {
    global: constrainedLevel === 'global' ? constrained : roomy,
    perPeer: constrainedLevel === 'global' || constrainedLevel === 'perPeer' ? constrained : roomy,
    perPrincipal: constrainedLevel === 'global' || constrainedLevel === 'perPrincipal' ? constrained : roomy,
    fileDataReserve: {
      global: testDirectionalReserve(10),
      perPeer: testDirectionalReserve(10),
      perPrincipal: testDirectionalReserve(10)
    },
    fileControlReserve: testFileControlReserve(10),
    generalReserve: testGeneralReserve(10)
  } as const;
}

function testGeneralReserve(bufferedBytes = 1) {
  return {
    global: { streams: 1, bufferedBytes },
    perPeer: { streams: 1, bufferedBytes },
    perPrincipal: { streams: 1, bufferedBytes }
  } as const;
}

function reservedBytes(reserve: {
  readonly outbound: { readonly bufferedBytes: number };
  readonly inbound: { readonly bufferedBytes: number };
}): number {
  return reserve.outbound.bufferedBytes + reserve.inbound.bufferedBytes;
}

function generalReservedBytes(
  limits: typeof DEFAULT_RESOURCE_LIMITS,
  level: 'global' | 'perPeer' | 'perPrincipal'
): number {
  return limits[level].bufferedBytes -
    reservedBytes(limits.fileDataReserve[level]) -
    reservedBytes(limits.fileControlReserve[level]);
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function recordingStream(): {
  readonly send: QuicSendStream & { resetCalls: number };
  readonly recv: QuicRecvStream & { stopCalls: number };
} {
  return {
    send: {
      resetCalls: 0,
      writeAll: async () => undefined,
      finish: async () => undefined,
      async reset() { this.resetCalls += 1; },
      setPriority: async () => undefined
    },
    recv: {
      stopCalls: 0,
      readExact: async () => new Uint8Array(),
      expectEnd: async () => undefined,
      async stop() { this.stopCalls += 1; }
    }
  };
}

function testConnection(openBi: () => Promise<QuicBiStream>): QuicConnection {
  const closed = deferred<string>();
  return {
    remoteId: 'peer',
    side: 'client',
    openBi,
    acceptBi: () => new Promise<never>(() => undefined),
    openUni: () => new Promise<never>(() => undefined),
    acceptUni: () => new Promise<never>(() => undefined),
    closed: () => closed.promise,
    close: () => closed.resolve('closed'),
    stats: async (): Promise<ConnectionStats> => ({
      rttMs: null,
      sentBytes: 0,
      receivedBytes: 0,
      lostPackets: 0
    })
  };
}
