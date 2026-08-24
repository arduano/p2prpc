import { lstat, mkdtemp, readFile, rename, rm, stat, symlink, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import process from 'node:process';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { chunkDigest, createManifest, fileDestination, fileSource } from '../src/files/fs.js';
import {
  ReceiverOperationLedger,
  TransferManager,
  type FileTransferConnectionContext
} from '../src/files/manager.js';
import { ShareRegistry } from '../src/files/share.js';
import { Transfer } from '../src/files/transfer.js';
import type {
  FileDestination,
  FileDestinationFinalizeContext,
  FileManifest,
  FileMetadataSchema,
  TransferProgress,
  TransferResult
} from '../src/files/types.js';
import { PROTOCOL_VERSION, TransferFrameKind, readFrame, writeFrame } from '../src/protocol.js';
import type {
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicRecvStream,
  QuicSendStream
} from '../src/transport/types.js';
import {
  cloneValidatedMetadata,
  DEFAULT_FILE_TRANSFER_LIMITS,
  manifestWireValue,
  validateManifest
} from '../src/files/validation.js';
import { P2PError } from '../src/errors.js';

const temporary: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe('filesystem transfers', () => {
  it('preserves an immediate failure for a result consumer which attaches later', async () => {
    const manifest: FileManifest = Object.freeze({
      transferId: 'delayed-result-consumer',
      name: 'failure.bin',
      size: 0,
      digest: chunkDigest(new Uint8Array()),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });
    const failure = new Error('immediate transfer failure');
    const unhandled: unknown[] = [];
    const onUnhandled = (cause: unknown): void => { unhandled.push(cause); };
    process.on('unhandledRejection', onUnhandled);
    try {
      const transfer = new Transfer(manifest, new AbortController(), async () => {
        throw failure;
      });

      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
      await expect(transfer.result).rejects.toBe(failure);
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('delivers immutable progress snapshots to every observer', async () => {
    const manifest: FileManifest = Object.freeze({
      transferId: 'progress-transfer',
      name: 'empty.bin',
      size: 0,
      digest: chunkDigest(new Uint8Array()),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });
    const transfer = new Transfer(manifest, new AbortController(), async () => ({
      manifest,
      resumed: false,
      durationMs: 0
    }));
    let observed: unknown;
    transfer.onProgress((progress) => {
      observed = progress;
      expect(Object.isFrozen(progress)).toBe(true);
    });
    const mutable = {
      transferId: manifest.transferId,
      direction: 'receive' as const,
      transferredBytes: 0,
      totalBytes: 0,
      completedChunks: 0,
      totalChunks: 0
    };

    transfer.emit(mutable);
    mutable.completedChunks = 99;

    expect(observed).toMatchObject({ completedChunks: 0 });
    await expect(transfer.result).resolves.toMatchObject({ manifest });
  });

  it('broadcasts conflated progress independently and unregisters returned iterators', async () => {
    const manifest: FileManifest = Object.freeze({
      transferId: 'progress-broadcast',
      name: 'file.bin',
      size: 2,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 1
    });
    const settled = deferred<TransferResult>();
    const transfer = new Transfer(manifest, new AbortController(), () => settled.promise);
    const first = transfer.progress()[Symbol.asyncIterator]();
    const second = transfer.progress()[Symbol.asyncIterator]();
    const firstWaiting = first.next();
    const secondWaiting = second.next();
    transfer.emit(progressFor(manifest, 1));
    await expect(firstWaiting).resolves.toMatchObject({ done: false, value: { completedChunks: 1 } });
    await expect(secondWaiting).resolves.toMatchObject({ done: false, value: { completedChunks: 1 } });

    transfer.emit(progressFor(manifest, 2));
    transfer.emit(progressFor(manifest, 3));
    await expect(first.next()).resolves.toMatchObject({ value: { completedChunks: 3 } });
    await first.return?.();
    expect((transfer as unknown as { subscribers: Set<unknown> }).subscribers.size).toBe(1);

    await expect(second.next()).resolves.toMatchObject({ done: false, value: { completedChunks: 3 } });
    const secondDone = second.next();
    settled.resolve({ manifest, resumed: false, durationMs: 1 });
    await expect(secondDone).resolves.toMatchObject({ done: true });
    await transfer.result;
    expect((transfer as unknown as { subscribers: Set<unknown> }).subscribers.size).toBe(0);
  });

  it('does not let a never-settling progress observer retain transfer ownership', async () => {
    const manifest: FileManifest = Object.freeze({
      transferId: 'progress-observer-lifecycle',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });
    const executor = deferred<TransferResult>();
    const observer = deferred<void>();
    const transfer = new Transfer(manifest, new AbortController(), () => executor.promise);
    let observerCalls = 0;
    transfer.onProgress(async () => {
      observerCalls += 1;
      return observer.promise;
    });
    transfer.emit(progressFor(manifest, 0));
    transfer.emit(progressFor(manifest, 1));
    transfer.emit(progressFor(manifest, 2));
    expect(observerCalls).toBe(1);
    executor.resolve({ manifest, resumed: false, durationMs: 1 });
    await expect(transfer.result).resolves.toMatchObject({ manifest });
    expect((transfer as unknown as { listeners: Map<unknown, unknown> }).listeners.size).toBe(0);
    observer.resolve();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(observerCalls).toBe(1);
  });

  it('reports exact sparse-resume send bytes when lanes finish out of order', async () => {
    const chunkSize = 64 * 1024;
    const chunks = [
      Uint8Array.from({ length: chunkSize }, () => 1),
      Uint8Array.from({ length: chunkSize }, () => 2),
      Uint8Array.of(3, 3, 3)
    ];
    const control = duplexPair();
    const lanes = [new RecordingPipe(), new RecordingPipe()];
    let openedLanes = 0;
    const base = testConnection(control.left, lanes[0]!);
    const connection: QuicConnection = {
      ...base,
      openUni: async () => lanes[openedLanes++]!
    };
    const reads = [0, 0, 0];
    const firstLaneBlocked = deferred<void>();
    const releaseFirstLane = deferred<void>();
    const observed: TransferProgress[] = [];
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(connection),
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'sparse-send.bin',
      size: chunkSize * 2 + 3,
      async readChunk(index) {
        reads[index] = (reads[index] ?? 0) + 1;
        if (index === 0 && reads[index] === 2) {
          firstLaneBlocked.resolve();
          await releaseFirstLane.promise;
        }
        return chunks[index]!.slice();
      }
    }, {
      chunkSize,
      lanes: 2,
      onProgress: (progress) => { observed.push(progress); }
    });
    const iterator = transfer.progress()[Symbol.asyncIterator]();
    const baselineProgress = iterator.next();
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [[0, 2]],
        missingCount: 2,
        lanes: 2
      });
      const completion = await readFrame<Record<string, unknown>>(control.right.recv);
      await acknowledgeLocalSender(control.right, completion.value);
    })();

    await expect(baselineProgress).resolves.toMatchObject({
      done: false,
      value: { completedChunks: 1, transferredBytes: 3 }
    });
    await firstLaneBlocked.promise;
    await expect(iterator.next()).resolves.toMatchObject({
      done: false,
      value: { completedChunks: 2, transferredBytes: chunkSize + 3 }
    });
    expect(observed.some((progress) =>
      progress.completedChunks === 2 && progress.transferredBytes === chunkSize + 3
    )).toBe(true);
    releaseFirstLane.resolve();
    await expect(transfer.result).resolves.toMatchObject({ resumed: true });
    await remote;
    expect(openedLanes).toBe(2);
    expect(observed.at(-1)).toMatchObject({
      completedChunks: 3,
      transferredBytes: chunkSize * 2 + 3
    });
  });

  it('routes exact sparse-resume receive progress through the download transfer', async () => {
    const chunkSize = 64 * 1024;
    const chunks = [
      Uint8Array.from({ length: chunkSize }, () => 4),
      Uint8Array.from({ length: chunkSize }, () => 5),
      Uint8Array.of(6, 6, 6)
    ];
    const control = duplexPair();
    const connection = testConnection(control.left, new AsyncPipe());
    const context = testContext(connection);
    const releasePrepare = deferred<void>();
    const firstWriteStarted = deferred<void>();
    const releaseFirstWrite = deferred<void>();
    const optionProgress: TransferProgress[] = [];
    const written: number[] = [];
    const destination: FileDestination = {
      prepare: async () => {
        await releasePrepare.promise;
        return new Set([2]);
      },
      writeChunk: async (_manifest, index) => {
        if (index === 0) {
          firstWriteStarted.resolve();
          await releaseFirstWrite.promise;
        }
        written.push(index);
      },
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => undefined
    };
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => context,
      shares: new ShareRegistry(),
      authorize: () => undefined,
      limits: { chunkSize, lanes: 2 }
    });
    const downloading = manager.download('a'.repeat(43), destination, {
      chunkSize,
      lanes: 2,
      onProgress: (progress) => { optionProgress.push(progress); }
    });
    const offered = (async () => {
      await control.right.recv.readExact(1);
      const pull = await readFrame<Record<string, unknown>>(control.right.recv);
      const manifest: FileManifest = {
        transferId: pull.value.requestId as string,
        name: 'sparse-download.bin',
        size: chunkSize * 2 + 3,
        digest: '0'.repeat(64),
        chunkSize,
        chunkCount: 3
      };
      await writeFrame(control.right.send, TransferFrameKind.Offer, manifest);
      return manifest;
    })();
    const transfer = await downloading;
    const manifest = await offered;
    const iterator = transfer.progress()[Symbol.asyncIterator]();
    const baselineProgress = iterator.next();
    releasePrepare.resolve();
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(accepted.value).toMatchObject({
      missingRanges: [[0, 2]],
      missingCount: 2,
      lanes: 2
    });
    await expect(baselineProgress).resolves.toMatchObject({
      done: false,
      value: { completedChunks: 1, transferredBytes: 3 }
    });

    const firstLane = await completedChunkLane(manifest, accepted.value, 0, 0, chunks[0]!);
    const secondLane = await completedChunkLane(manifest, accepted.value, 1, 1, chunks[1]!);
    const firstHandling = manager.handleData(firstLane, context);
    await firstWriteStarted.promise;
    const sparseProgress = iterator.next();
    await manager.handleData(secondLane, context);
    await expect(sparseProgress).resolves.toMatchObject({
      done: false,
      value: { completedChunks: 2, transferredBytes: chunkSize + 3 }
    });
    expect(optionProgress.some((progress) =>
      progress.completedChunks === 2 && progress.transferredBytes === chunkSize + 3
    )).toBe(true);

    releaseFirstWrite.resolve();
    await firstHandling;
    await completeLocalReceiver(control.right, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await expect(transfer.result).resolves.toMatchObject({ resumed: true });
    expect(written).toEqual([1, 0]);
    expect(optionProgress.at(-1)).toMatchObject({
      completedChunks: 3,
      transferredBytes: chunkSize * 2 + 3
    });
  });

  it('creates stable BLAKE3 manifests and atomically finalizes chunks', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-'));
    temporary.push(directory);
    const input = join(directory, 'input.bin');
    const output = join(directory, 'output.bin');
    const bytes = Buffer.from('0123456789'.repeat(20_000));
    await writeFile(input, bytes);
    const source = await fileSource(input, { kind: 'test' });
    const manifest = await createManifest(source, { chunkSize: 64 * 1024, transferId: 'test-transfer' });
    const destination = fileDestination<{ kind: string }>(output);
    expect(await destination.prepare(manifest)).toEqual(new Set());
    for (let index = 0; index < manifest.chunkCount; index += 1) {
      await destination.writeChunk(manifest, index, await source.readChunk(index, manifest.chunkSize));
    }
    await destination.finalize(manifest, finalizeContext());
    expect(await readFile(output)).toEqual(bytes);
  });

  it('persists completed chunks and resumes into the same partial file', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-resume-'));
    temporary.push(directory);
    const input = join(directory, 'resume-input.bin');
    const output = join(directory, 'resume-output.bin');
    const bytes = Buffer.from('resume-me-'.repeat(30_000));
    await writeFile(input, bytes);
    const source = await fileSource(input);
    const manifest = await createManifest(source, { chunkSize: 64 * 1024, transferId: 'resume-transfer' });
    const first = fileDestination(output);
    await first.prepare(manifest);
    await first.writeChunk(manifest, 0, await source.readChunk(0, manifest.chunkSize));
    await first.abort(manifest, { discard: false });

    const state = await stat(`${output}.p2prpc.state`);
    expect(state.size).toBe(64 + manifest.chunkCount * 33);

    const resumed = fileDestination(output);
    expect(await resumed.prepare(manifest)).toEqual(new Set([0]));
    for (let index = 1; index < manifest.chunkCount; index += 1) {
      await resumed.writeChunk(manifest, index, await source.readChunk(index, manifest.chunkSize));
    }
    await resumed.finalize(manifest, finalizeContext());
    expect(await readFile(output)).toEqual(bytes);
  });

  it('updates fixed-layout resume records in place with constant bytes per chunk', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-resume-layout-'));
    temporary.push(directory);
    const output = join(directory, 'output.bin');
    const chunkSize = 64 * 1024;
    const data = Buffer.alloc(chunkSize, 7);
    const manifest: FileManifest = {
      transferId: 'resume-layout',
      name: 'output.bin',
      size: chunkSize * 32,
      digest: '0'.repeat(64),
      chunkSize,
      chunkCount: 32
    };
    const destination = fileDestination(output, { durable: false });
    await destination.prepare(manifest);
    const statePath = `${output}.p2prpc.state`;
    const expectedSize = 64 + manifest.chunkCount * 33;
    expect((await stat(statePath)).size).toBe(expectedSize);
    for (let index = 0; index < manifest.chunkCount; index += 1) {
      await destination.writeChunk(manifest, index, data);
      expect((await stat(statePath)).size).toBe(expectedSize);
    }
    await destination.abort(manifest, { discard: false });
  });

  it('can re-prepare the same destination object after a resumable disconnect', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-retry-destination-'));
    temporary.push(directory);
    const input = join(directory, 'input.bin');
    const output = join(directory, 'output.bin');
    await writeFile(input, 'retry-safe');
    const source = await fileSource(input);
    const manifest = await createManifest(source, { chunkSize: 64 * 1024 });
    const destination = fileDestination(output);
    await destination.prepare(manifest);
    await destination.writeChunk(manifest, 0, await source.readChunk(0, manifest.chunkSize));
    await destination.abort(manifest, { discard: false });
    expect(await destination.prepare(manifest)).toEqual(new Set([0]));
    await destination.finalize(manifest, finalizeContext());
    expect(await readFile(output, 'utf8')).toBe('retry-safe');
  });

  it('uses peer-bound, expiring, hashed capabilities with atomic one-operation leases', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    let now = 1_000;
    const registry = new ShareRegistry({ defaultTtlMs: 100, maxTtlMs: 1_000, reconnectLeaseMs: 50, now: () => now });
    const request = (peerId: string, operationId: string, subject = 'subject-a', principalId = 'principal-a') => ({
      peerId,
      principalId,
      subject,
      fingerprint: 'v3:65536:1',
      operationId
    });
    expect(() => registry.share(source, {} as never)).toThrow(/peer-bound/);
    const handle = registry.shareForPeer(source, 'peer-a');
    expect(handle.expiresAt).toBe(1_100);
    const entries = (registry as unknown as { entries: Map<string, unknown> }).entries;
    expect(entries.has(handle.token)).toBe(false);
    expect(() => registry.reserve(handle.token, request('peer-b', 'request-a'))).toThrow(/invalid or unavailable/);
    const initial = registry.reserve(handle.token, request('peer-a', 'request-a'));
    expect(registry.operationStatus(handle.token, 'request-a')).toEqual({ state: 'active' });
    expect(initial.source).toBe(source);
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-b'))).toThrow(/invalid or unavailable/);
    initial.release();
    expect(registry.operationStatus(handle.token, 'request-a')).toEqual({ state: 'reconnectable' });
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a', 'subject-a', 'principal-b')))
      .toThrow(/invalid or unavailable/);
    expect(() => registry.reserve(handle.token, { ...request('peer-a', 'request-a'), fingerprint: 'v3:131072:1' }))
      .toThrow(/invalid or unavailable/);
    const resumed = registry.reserve(handle.token, request('peer-a', 'request-a'));
    resumed.complete();
    expect(registry.operationStatus(handle.token, 'request-a')).toEqual({ state: 'completed' });
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);
    now = 1_101;
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);

    const bearer = registry.share(source, { allowBearer: true });
    expect(registry.reserve(bearer.token, request('any-peer', 'request-c')).source).toBe(source);

    const canonicalPrincipal = {
      id: 'principal-a',
      subject: 'subject-a',
      issuer: 'https://identity.example',
      clientId: 'client-a',
      tenantId: 'tenant-a'
    };
    const principalBound = registry.share(source, {
      allowedPeerIds: ['peer-a'],
      allowedPrincipals: [canonicalPrincipal]
    });
    const canonicalRequest = {
      ...request('peer-a', 'request-e'),
      issuer: canonicalPrincipal.issuer,
      clientId: canonicalPrincipal.clientId,
      tenantId: canonicalPrincipal.tenantId
    };
    expect(() => registry.reserve(principalBound.token, { ...canonicalRequest, tenantId: 'tenant-b' }))
      .toThrow(/invalid or unavailable/);
    expect(registry.reserve(principalBound.token, canonicalRequest).source).toBe(source);

    const fullSessionPrincipal = {
      ...canonicalPrincipal,
      expiresAt: 10_000,
      scopes: new Set(['files:read']),
      claims: Object.freeze({ role: 'reader' })
    };
    const sessionPrincipalBound = registry.share(source, {
      allowedPeerIds: ['peer-a'],
      allowedPrincipals: [fullSessionPrincipal]
    });
    expect(registry.reserve(sessionPrincipalBound.token, { ...canonicalRequest, operationId: 'request-full' }).source)
      .toBe(source);

    const tenantReconnect = registry.shareForPeer(source, 'peer-a');
    const tenantRequest = { ...request('peer-a', 'request-f'), tenantId: 'tenant-a' };
    registry.reserve(tenantReconnect.token, tenantRequest).release();
    expect(() => registry.reserve(tenantReconnect.token, { ...tenantRequest, tenantId: 'tenant-b' }))
      .toThrow(/invalid or unavailable/);
  });

  it('rejects null or malformed capability restrictions instead of silently creating a bearer grant', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    const registry = new ShareRegistry();
    for (const policy of [
      { allowBearer: true, allowedPeerIds: null },
      { allowBearer: true, allowedPrincipals: null },
      { allowBearer: true, allowedSubjects: null },
      { allowBearer: true, expiresAt: null },
      { allowBearer: true, maxDownloads: null },
      { allowBearer: true, allowedPrinciple: [{ id: 'principal', subject: 'subject' }] }
    ]) {
      expect(() => registry.share(source, policy as never)).toThrow();
    }
    expect(() => registry.share(source, null as never)).toThrow(/policy must be an object/);
    for (const options of [
      { defaultTtlMs: null },
      { maxTtlMs: null },
      { reconnectLeaseMs: null },
      { maxReconnects: null },
      { maxEntries: null },
      { maxOperations: null },
      { now: null },
      { defaultTTLms: 1_000 }
    ]) {
      expect(() => new ShareRegistry(options as never)).toThrow();
    }
  });

  it('bounds capability operation records globally across shares', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    const registry = new ShareRegistry({ maxOperations: 2 });
    const first = registry.shareForPeer(source, 'peer-a', { maxDownloads: 2 });
    const second = registry.shareForPeer(source, 'peer-a', { maxDownloads: 2 });
    const reserve = (token: string, operationId: string) => registry.reserve(token, {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId
    });
    reserve(first.token, 'operation-a').complete();
    reserve(second.token, 'operation-b').complete();
    expect(() => reserve(first.token, 'operation-c')).toThrow(/operation limit/);
    expect(registry.revoke(second)).toBe(true);
    expect(reserve(first.token, 'operation-c').source).toBe(source);
  });

  it('retains revoked operation permits until active reservations actually settle', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    const registry = new ShareRegistry({ maxOperations: 1 });
    const first = registry.shareForPeer(source, 'peer-a');
    const second = registry.shareForPeer(source, 'peer-a');
    const request = (operationId: string) => ({
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId
    });
    const active = registry.reserve(first.token, request('operation-a'));
    expect(registry.diagnostics()).toMatchObject({
      activeShares: 2,
      operationRecords: 1,
      activeReservations: 1,
      expiryRecords: 2,
      closed: false
    });
    expect(registry.revoke(first)).toBe(true);
    expect(registry.diagnostics()).toMatchObject({
      activeShares: 1,
      operationRecords: 1,
      activeReservations: 1,
      expiryRecords: 1
    });
    expect(() => registry.reserve(second.token, request('operation-b'))).toThrow(/operation limit/);
    active.complete();
    expect(registry.diagnostics()).toMatchObject({ operationRecords: 0, activeReservations: 0 });
    const next = registry.reserve(second.token, request('operation-b'));
    expect(next.source).toBe(source);
    next.complete();
  });

  it('closes capability admission and aborts active reservations quiescently', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    const registry = new ShareRegistry();
    const handle = registry.shareForPeer(source, 'peer-a');
    const active = registry.reserve(handle.token, {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId: 'operation-a'
    });
    registry.close();
    expect(active.signal.aborted).toBe(true);
    expect(registry.diagnostics()).toMatchObject({
      activeShares: 0,
      operationRecords: 1,
      activeReservations: 1,
      expiryRecords: 0,
      closed: true
    });
    expect(() => registry.shareForPeer(source, 'peer-a')).toThrow(/closed/);
    expect(() => registry.reserve(handle.token, {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId: 'operation-a'
    })).toThrow(/closed/);
    active.complete();
    expect(registry.diagnostics()).toMatchObject({ operationRecords: 0, activeReservations: 0, closed: true });
  });

  it('evicts share expirations through the indexed heap without scanning capacity', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    let now = 1_000;
    const registry = new ShareRegistry({
      defaultTtlMs: 100,
      maxTtlMs: 1_000,
      maxEntries: 2,
      now: () => now
    });
    const later = registry.shareForPeer(source, 'peer-a', { expiresAt: 1_200 });
    const sooner = registry.shareForPeer(source, 'peer-a', { expiresAt: 1_100 });
    expect(registry.revoke(later)).toBe(true);
    now = 1_101;
    expect(() => registry.shareForPeer(source, 'peer-a')).not.toThrow();
    expect(registry.revoke(sooner)).toBe(false);
  });

  it('aborts active retries and releases transfer slots when the peer file manager closes', async () => {
    let connectionAttempts = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => {
        connectionAttempts += 1;
        throw new P2PError('DISCONNECTED', 'Peer is offline');
      },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const transfer = await manager.sendFile(source, { transferId: 'peer-close-transfer' });
    await new Promise<void>((resolve) => setImmediate(resolve));

    manager.close(new P2PError('DISCONNECTED', 'Peer permanently closed'));

    await expect(transfer.result).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(connectionAttempts).toBe(1);
    expect(manager.diagnostics()).toMatchObject({ activeTransfers: 0, queuedTransfers: 0 });
  });

  it('retries a trusted connection-provider disconnect with a fresh attempt', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    let connectionAttempts = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => {
        connectionAttempts += 1;
        if (connectionAttempts === 1) throw new P2PError('DISCONNECTED', 'Peer route changed');
        return context;
      },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      const completion = await readFrame<Record<string, unknown>>(control.right.recv);
      await acknowledgeLocalSender(control.right, completion.value);
    })();

    const transfer = await manager.sendFile({
      name: 'provider-retry.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
    await expect(transfer.result).resolves.toMatchObject({ manifest: { name: 'provider-retry.bin' } });
    await remote;
    expect(connectionAttempts).toBe(2);
  });

  it('propagates file cancellation into a pending stream open and quarantines before late cleanup', async () => {
    const opened = deferred<QuicBiStream>();
    const openStarted = deferred<void>();
    const lateStream = { send: new RecordingPipe(), recv: new RecordingPipe() };
    let openingSignal: AbortSignal | undefined;
    const base = testConnection(lateStream, new RecordingPipe());
    const recorded = recordConnectionClose({
      ...base,
      openBi: (options) => {
        openingSignal = options?.signal;
        openStarted.resolve();
        return opened.promise;
      }
    });
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(recorded.connection),
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const controller = new AbortController();
    const transfer = await manager.sendFile({
      name: 'cancelled-open.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    }, { signal: controller.signal });

    await openStarted.promise;
    expect(openingSignal?.aborted).toBe(false);
    controller.abort(new P2PError('CANCELLED', 'cancel pending file open'));

    await expect(transfer.result).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(openingSignal?.aborted).toBe(true);
    await expect(recorded.firstClose).resolves.toMatchObject({ code: 4n });

    opened.resolve(lateStream);
    await expect.poll(() => lateStream.send.resetCalls).toBe(1);
    await expect.poll(() => lateStream.recv.stopCalls).toBe(1);
  });

  it('admits local operations outbound and remote controls inbound', async () => {
    const directions: string[] = [];
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('admission must fail before connecting'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      acquireTransfer: async (direction) => {
        directions.push(direction);
        throw new P2PError('RESOURCE_LIMIT', 'direction captured');
      }
    });
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => undefined
    };

    await expect(manager.sendFile(source)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await expect(manager.download('a'.repeat(43), destination)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });

    const control = { send: new RecordingPipe(), recv: new RecordingPipe() };
    const context = testContext(testConnection(control, new RecordingPipe()));
    await expect(manager.handleControl(control, context)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });

    expect(directions).toEqual(['outbound', 'outbound', 'inbound']);
    expect(manager.diagnostics()).toMatchObject({
      activeTransfers: 0,
      queuedTransfers: 0,
      activeOutboundTransfers: 0,
      activeInboundTransfers: 0
    });
  });

  it('bounds reconnects with a non-sliding lease and an attempt cap', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    let now = 1_000;
    const request = {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId: 'request-a'
    };
    const registry = new ShareRegistry({
      defaultTtlMs: 1_000,
      maxTtlMs: 1_000,
      reconnectLeaseMs: 50,
      maxReconnects: 5,
      now: () => now
    });
    const handle = registry.shareForPeer(source, 'peer-a');
    registry.reserve(handle.token, request).release();
    now = 1_040;
    const second = registry.reserve(handle.token, request);
    second.release();
    now = 1_050;
    expect(() => registry.reserve(handle.token, request)).toThrow(/invalid or unavailable/);

    now = 2_000;
    const capped = new ShareRegistry({
      defaultTtlMs: 1_000,
      maxTtlMs: 1_000,
      reconnectLeaseMs: 500,
      maxReconnects: 1,
      now: () => now
    });
    const cappedHandle = capped.shareForPeer(source, 'peer-a');
    capped.reserve(cappedHandle.token, request).release();
    capped.reserve(cappedHandle.token, request).release();
    expect(() => capped.reserve(cappedHandle.token, request)).toThrow(/invalid or unavailable/);
  });

  it('treats capability expiry as a redemption deadline and explicit revoke as active cancellation', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    let now = 1_000;
    const registry = new ShareRegistry({ defaultTtlMs: 100, maxTtlMs: 1_000, now: () => now });
    const handle = registry.shareForPeer(source, 'peer-a');
    const request = {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId: 'request-a'
    };
    const active = registry.reserve(handle.token, request);
    now = 1_101;
    expect(() => registry.reserve(handle.token, { ...request, operationId: 'request-b' }))
      .toThrow(/invalid or unavailable/);
    expect(active.signal.aborted).toBe(false);
    expect(registry.revoke(handle)).toBe(true);
    expect(active.signal.aborted).toBe(true);
    expect(active.signal.reason).toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('keeps a receipted capability terminal when final stream cleanup fails', async () => {
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const first = duplexPair();
    const failingStream: QuicBiStream = {
      send: new FinishFailingSend(first.left.send),
      recv: first.left.recv
    };
    const handling = manager.handleControl(failingStream, testContext(testConnection(failingStream, new AsyncPipe())));
    const remote = acknowledgeEmptyPull(first.right, handle.token, 'request-a').catch(() => undefined);
    await expect(handling).resolves.toBeUndefined();
    await remote;
    expect(shares.operationStatus(handle.token, 'request-a')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);

    const replay = duplexPair();
    await writePull(replay.right.send, handle.token, 'request-a');
    const replayHandling = manager.handleControl(replay.left, testContext(testConnection(replay.left, new AsyncPipe())));
    expect((await readFrame(replay.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(replayHandling).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('retains known-success control ownership until physical closure when cleanup is unconfirmed', async () => {
    let finalizes = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      incoming: () => ({
        accept: {
          prepare: async () => new Set<number>(),
          writeChunk: async () => undefined,
          finalize: async (_manifest, context) => {
            finalizes += 1;
            context.markCommitted();
          },
          abort: async () => undefined
        }
      })
    });
    const localToRemote = new CleanupRejectingPipe();
    const remoteToLocal = new CleanupRejectingPipe();
    const local = { send: localToRemote, recv: remoteToLocal };
    const remote = { send: remoteToLocal, recv: localToRemote };
    const closure = deferred<string>();
    const lifecycle: string[] = [];
    const connection: QuicConnection = {
      ...testConnection(local, new AsyncPipe()),
      closed: () => {
        lifecycle.push('closed-subscribed');
        return closure.promise;
      },
      close: () => { lifecycle.push('close-requested'); }
    };
    const tracked: Promise<unknown>[] = [];
    const manifest: FileManifest = {
      transferId: 'known-success-physical-closure',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };

    await writeFrame(remote.send, TransferFrameKind.Offer, manifest);
    const handling = manager.handleControl(
      local,
      testContext(connection),
      (work) => { tracked.push(work); }
    );
    const acceptance = await readFrame<Record<string, unknown>>(remote.recv);
    await writeFrame(remote.send, TransferFrameKind.Complete, {
      transferId: manifest.transferId,
      attemptId: acceptance.value.attemptId
    });
    expect((await readFrame(remote.recv)).kind).toBe(TransferFrameKind.Complete);
    // Lose the receipt after durable publication. Both terminal operations
    // reject, so only physical connection closure can discharge ownership.
    await remote.send.finish();

    await expect(handling).resolves.toBeUndefined();
    expect(finalizes).toBe(1);
    expect(tracked).toHaveLength(1);
    expect(lifecycle[0]).toBe('closed-subscribed');
    expect(lifecycle).toContain('close-requested');
    let ownershipReleased = false;
    void tracked[0]!.then(() => { ownershipReleased = true; });
    await Promise.resolve();
    expect(ownershipReleased).toBe(false);

    closure.resolve('closed');
    await tracked[0];
    expect(ownershipReleased).toBe(true);
  });

  it('reports an indeterminate push when the receiver commit acknowledgement is lost', async () => {
    const control = duplexPair();
    let connections = 0;
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { connections += 1; return context; },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      await readFrame(control.right.recv);
      // Close without the receiver's completion acknowledgement. The sender
      // has crossed the possible-commit boundary but cannot know the outcome.
      await control.right.send.finish();
    })();
    const transfer = await manager.sendFile({
      name: 'empty.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
    await expect(transfer.result).rejects.toMatchObject({ code: 'OUTCOME_UNKNOWN' });
    await remote;
    expect(connections).toBe(1);
  });

  it('sends schema-validated metadata as accessor-free manifest wire data', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const manager = new TransferManager<{ classification: string; binary: Uint8Array }>({
      peerId: 'peer-a',
      connection: async () => context,
      shares: new ShareRegistry(),
      authorize: () => undefined,
      metadataSchema: passthroughMetadataSchema()
    });
    const metadata = {
      classification: 'internal',
      binary: Buffer.from([1, 2, 3])
    };
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest<typeof metadata>>(control.right.recv);
      expect(offer.value.metadata).toMatchObject({ classification: 'internal' });
      expect([...(offer.value.metadata?.binary ?? [])]).toEqual([1, 2, 3]);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      const completion = await readFrame<Record<string, unknown>>(control.right.recv);
      await acknowledgeLocalSender(control.right, completion.value);
    })();
    const transfer = await manager.sendFile({
      name: 'metadata.bin',
      size: 0,
      metadata,
      readChunk: async () => new Uint8Array()
    });
    metadata.classification = 'mutated';
    metadata.binary[0] = 9;
    await transfer.result;
    await remote;
  });

  it('reconciles a repeated committed push without invoking destination callbacks again', async () => {
    let authorizations = 0;
    let offers = 0;
    let prepares = 0;
    let finalizes = 0;
    const destination: FileDestination = {
      prepare: async () => { prepares += 1; return new Set(); },
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => {
        finalizes += 1;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => { authorizations += 1; },
      incoming: () => { offers += 1; return { accept: destination }; }
    });
    const manifest: FileManifest = {
      transferId: 'committed-operation',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };

    const runAttempt = async (sendReceipt: boolean): Promise<void> => {
      const control = duplexPair();
      const context = testContext(testConnection(control.left, new AsyncPipe()));
      await writeFrame(control.right.send, TransferFrameKind.Offer, manifest);
      const handling = manager.handleControl(control.left, context);
      const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
      expect(accepted.kind).toBe(TransferFrameKind.Accept);
      expect(accepted.value.missingCount).toBe(0);
      await writeFrame(control.right.send, TransferFrameKind.Complete, {
        transferId: manifest.transferId,
        attemptId: accepted.value.attemptId
      });
      const acknowledgement = await readFrame<Record<string, unknown>>(control.right.recv);
      if (sendReceipt) {
        await writeFrame(control.right.send, TransferFrameKind.Receipt, acknowledgement.value);
      }
      await control.right.send.finish();
      if (sendReceipt) await control.right.recv.expectEnd();
      await handling;
    };

    await runAttempt(false);
    await runAttempt(true);
    expect({ authorizations, offers, prepares, finalizes }).toEqual({
      authorizations: 2,
      offers: 1,
      prepares: 1,
      finalizes: 1
    });

    const replay = duplexPair();
    await writeFrame(replay.right.send, TransferFrameKind.Offer, manifest);
    const replayHandling = manager.handleControl(
      replay.left,
      testContext(testConnection(replay.left, new AsyncPipe()))
    );
    expect((await readFrame(replay.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(replayHandling).rejects.toMatchObject({ code: 'REJECTED' });

    const conflict = duplexPair();
    await writeFrame(conflict.right.send, TransferFrameKind.Offer, {
      ...manifest,
      name: 'different.bin'
    });
    const conflictHandling = manager.handleControl(
      conflict.left,
      testContext(testConnection(conflict.left, new AsyncPipe()))
    );
    expect((await readFrame(conflict.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(conflictHandling).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' });
    expect(offers).toBe(1);
  });

  it('never rejects or rolls back after a destination marks publication and cleanup fails', async () => {
    let offers = 0;
    let prepares = 0;
    let finalizes = 0;
    let aborts = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      incoming: () => {
        offers += 1;
        return {
          accept: {
            prepare: async () => { prepares += 1; return new Set<number>(); },
            writeChunk: async () => undefined,
            finalize: async (_manifest, context) => {
              finalizes += 1;
              context.markCommitted();
              throw new P2PError('OUTCOME_UNKNOWN', 'post-publication cleanup failed');
            },
            abort: async () => { aborts += 1; }
          }
        };
      }
    });
    const manifest: FileManifest = {
      transferId: 'post-commit-cleanup-failure',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };

    const first = duplexPair();
    const recorded = recordConnectionClose(testConnection(first.left, new AsyncPipe()));
    await writeFrame(first.right.send, TransferFrameKind.Offer, manifest);
    const firstHandling = manager.handleControl(first.left, testContext(recorded.connection));
    const firstAcceptance = await readFrame<Record<string, unknown>>(first.right.recv);
    await writeFrame(first.right.send, TransferFrameKind.Complete, {
      transferId: manifest.transferId,
      attemptId: firstAcceptance.value.attemptId
    });

    await expect(firstHandling).resolves.toBeUndefined();
    await expect(readFrame(first.right.recv)).rejects.toThrow(/EOF/);
    expect(recorded.calls).toEqual([{
      code: 4n,
      reason: 'File stream cleanup failed'
    }]);
    expect({ offers, prepares, finalizes, aborts }).toEqual({
      offers: 1,
      prepares: 1,
      finalizes: 1,
      aborts: 0
    });
    expect(manager.diagnostics()).toMatchObject({
      activeOperations: 0,
      ambiguousOperations: 1,
      replayTombstones: 0
    });

    const retry = duplexPair();
    await writeFrame(retry.right.send, TransferFrameKind.Offer, manifest);
    const retryHandling = manager.handleControl(
      retry.left,
      testContext(testConnection(retry.left, new AsyncPipe()))
    );
    const retryAcceptance = await readFrame<Record<string, unknown>>(retry.right.recv);
    await completeLocalReceiver(retry.right, {
      transferId: manifest.transferId,
      attemptId: retryAcceptance.value.attemptId
    });
    await expect(retryHandling).resolves.toBeUndefined();
    expect({ offers, prepares, finalizes, aborts }).toEqual({
      offers: 1,
      prepares: 1,
      finalizes: 1,
      aborts: 0
    });
    expect(manager.diagnostics()).toMatchObject({
      activeOperations: 0,
      ambiguousOperations: 0,
      operationRecords: 0,
      replayTombstones: 1
    });
  });

  const committedReconciliationFailures: readonly {
    readonly name: string;
    readonly idleTimeoutMs?: number;
    readonly fail: (
      remote: QuicBiStream,
      acceptance: Record<string, unknown>,
      controller: AbortController,
      manifest: FileManifest
    ) => Promise<void>;
  }[] = [
    {
      name: 'a wrong Complete',
      fail: async (remote, _acceptance, _controller, manifest) => {
        await writeFrame(remote.send, TransferFrameKind.Complete, {
          transferId: manifest.transferId,
          attemptId: 'z'.repeat(22)
        });
      }
    },
    {
      name: 'a malformed Complete',
      fail: async (remote, acceptance, _controller, manifest) => {
        await writeFrame(remote.send, TransferFrameKind.Complete, {
          transferId: manifest.transferId,
          attemptId: acceptance.attemptId,
          unexpected: true
        });
      }
    },
    {
      name: 'EOF before Complete',
      fail: async (remote) => remote.send.finish()
    },
    {
      name: 'a control-read timeout',
      idleTimeoutMs: 1_000,
      fail: async () => undefined
    },
    {
      name: 'authenticated-session cancellation',
      fail: async (_remote, _acceptance, controller) => {
        controller.abort(new P2PError('UNAUTHORIZED', 'Authenticated session ended'));
      }
    }
  ];

  it.each(committedReconciliationFailures)(
    'preserves a durable push for later reconciliation after $name',
    async ({ fail, idleTimeoutMs }) => {
      let authorizations = 0;
      let offers = 0;
      let prepares = 0;
      let finalizes = 0;
      let aborts = 0;
      const receiverOperations = new ReceiverOperationLedger({
        maxOperationRecords: 1_024,
        maxReplayTombstones: 1_024,
        operationRecordTtlMs: 15 * 60_000
      });
      const createManager = () => new TransferManager({
          peerId: 'peer-a',
          connection: async () => { throw new Error('unused'); },
          shares: new ShareRegistry(),
          authorize: () => { authorizations += 1; },
          incoming: () => {
            offers += 1;
            return {
              accept: {
                prepare: async () => { prepares += 1; return new Set<number>(); },
                writeChunk: async () => undefined,
                finalize: async (_manifest, context) => {
                  finalizes += 1;
                  context.markCommitted();
                },
                abort: async () => { aborts += 1; }
              }
            };
          },
          receiverOperations,
          ...(idleTimeoutMs === undefined ? {} : { idleTimeoutMs })
        });
      let manager = createManager();
      const manifest: FileManifest = {
        transferId: `committed-reconciliation-${idleTimeoutMs ?? 'immediate'}-${authorizations}`,
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 64 * 1024,
        chunkCount: 0
      };

      // Establish a durable local commit while deliberately losing the first
      // acknowledgement receipt. This is the state reconciliation exists for.
      const initial = duplexPair();
      await writeFrame(initial.right.send, TransferFrameKind.Offer, manifest);
      const initialHandling = manager.handleControl(
        initial.left,
        testContext(testConnection(initial.left, new AsyncPipe()))
      );
      const initialAcceptance = await readFrame<Record<string, unknown>>(initial.right.recv);
      await writeFrame(initial.right.send, TransferFrameKind.Complete, {
        transferId: manifest.transferId,
        attemptId: initialAcceptance.value.attemptId
      });
      expect((await readFrame(initial.right.recv)).kind).toBe(TransferFrameKind.Complete);
      await initial.right.send.finish();
      await expect(initialHandling).resolves.toBeUndefined();
      expect(manager.diagnostics()).toMatchObject({
        activeOperations: 0,
        ambiguousOperations: 1,
        operationRecords: 1,
        replayTombstones: 0
      });

      // Inbound-only peer runtimes are connection-scoped. Reconciliation must
      // survive the manager which owned the publishing physical connection.
      manager.close(new P2PError('DISCONNECTED', 'First physical connection closed'));
      manager = createManager();

      const failed = duplexPair();
      const sessionController = new AbortController();
      const recorded = recordConnectionClose(testConnection(failed.left, new AsyncPipe()));
      await writeFrame(failed.right.send, TransferFrameKind.Offer, manifest);
      const failedHandling = manager.handleControl(
        failed.left,
        testContext(recorded.connection, { signal: sessionController.signal })
      );
      const reconciliationAcceptance = await readFrame<Record<string, unknown>>(failed.right.recv);
      expect(reconciliationAcceptance.kind).toBe(TransferFrameKind.Accept);

      await fail(failed.right, reconciliationAcceptance.value, sessionController, manifest);
      await expect(failedHandling).resolves.toBeUndefined();

      // Once finalize() has published the destination, an incomplete retry is
      // a known local success: quarantine it, but never emit a contradictory
      // Reject or invoke any destination callback again.
      await expect(readFrame(failed.right.recv)).rejects.toThrow(/EOF/);
      expect(recorded.calls).toEqual([{
        code: 4n,
        reason: 'File stream cleanup failed'
      }]);
      expect({ offers, prepares, finalizes, aborts }).toEqual({
        offers: 1,
        prepares: 1,
        finalizes: 1,
        aborts: 0
      });
      expect(manager.diagnostics()).toMatchObject({
        activeOperations: 0,
        ambiguousOperations: 1,
        operationRecords: 1,
        replayTombstones: 0
      });

      const valid = duplexPair();
      await writeFrame(valid.right.send, TransferFrameKind.Offer, manifest);
      const validHandling = manager.handleControl(
        valid.left,
        testContext(testConnection(valid.left, new AsyncPipe()))
      );
      const validAcceptance = await readFrame<Record<string, unknown>>(valid.right.recv);
      await completeLocalReceiver(valid.right, {
        transferId: manifest.transferId,
        attemptId: validAcceptance.value.attemptId
      });
      await expect(validHandling).resolves.toBeUndefined();

      expect(authorizations).toBe(3);
      expect({ offers, prepares, finalizes, aborts }).toEqual({
        offers: 1,
        prepares: 1,
        finalizes: 1,
        aborts: 0
      });
      expect(manager.diagnostics()).toMatchObject({
        activeOperations: 0,
        ambiguousOperations: 0,
        operationRecords: 0,
        replayTombstones: 1
      });
    }
  );

  it('does not make acknowledged push throughput proportional to reconciliation capacity', async () => {
    let finalizes = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      incoming: () => ({
        accept: {
          prepare: async () => new Set<number>(),
          writeChunk: async () => undefined,
          finalize: async (_manifest, context) => {
            finalizes += 1;
            context.markCommitted();
          },
          abort: async () => undefined
        }
      }),
      maxOperationRecords: 2,
      maxReplayTombstones: 3
    });

    for (let index = 0; index < 1_100; index += 1) {
      const control = duplexPair();
      const context = testContext(testConnection(control.left, new AsyncPipe()));
      const transferId = `throughput-${index}`;
      await writeFrame(control.right.send, TransferFrameKind.Offer, {
        transferId,
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 64 * 1024,
        chunkCount: 0
      });
      const handling = manager.handleControl(control.left, context);
      const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
      await completeLocalReceiver(control.right, {
        transferId,
        attemptId: accepted.value.attemptId
      });
      await handling;
    }

    expect(finalizes).toBe(1_100);
    expect(manager.diagnostics()).toMatchObject({
      activeOperations: 0,
      ambiguousOperations: 0,
      operationRecords: 0,
      replayTombstones: 3,
      maxOperationRecords: 2,
      maxReplayTombstones: 3
    });
  });

  it('requires the receiver fresh challenge and retains ambiguous commit state for a pre-sent receipt', async () => {
    let aborts = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      incoming: () => ({
        accept: {
          prepare: async () => new Set<number>(),
          writeChunk: async () => undefined,
          finalize: async (_manifest, context) => { context.markCommitted(); },
          abort: async () => { aborts += 1; }
        }
      })
    });
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const manifest = {
      transferId: 'pre-sent-receipt',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    await writeFrame(control.right.send, TransferFrameKind.Offer, manifest);
    const handling = manager.handleControl(control.left, context);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const completion = { transferId: manifest.transferId, attemptId: accepted.value.attemptId };
    await writeFrame(control.right.send, TransferFrameKind.Complete, completion);
    await writeFrame(control.right.send, TransferFrameKind.Receipt, {
      ...completion,
      receiptToken: 'x'.repeat(43)
    });
    await control.right.send.finish();
    const acknowledgement = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(acknowledgement.value.receiptToken).not.toBe('x'.repeat(43));
    await handling;

    expect(aborts).toBe(0);
    expect(manager.diagnostics()).toMatchObject({
      activeOperations: 0,
      ambiguousOperations: 1,
      replayTombstones: 0
    });
  });

  it('never lets a stale operation handle transition a newer same-ID generation', () => {
    const receiverOperations = new ReceiverOperationLedger({
      maxOperationRecords: 1_024,
      maxReplayTombstones: 1_024,
      operationRecordTtlMs: 15 * 60_000
    });
    const manifest: FileManifest = {
      transferId: 'generation-cas',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    const principal = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const internals = receiverOperations as unknown as {
      scopes: Map<string, { operations: Map<string, object> }>;
      admit(peerId: string, value: FileManifest, identity: typeof principal): { record: object; fresh: boolean };
      prepareCommit(peerId: string, value: FileManifest, identity: typeof principal, record: object): () => void;
      acknowledge(peerId: string, value: FileManifest, identity: typeof principal, record: object): void;
    };
    const old = internals.admit('peer-a', manifest, principal).record;
    internals.prepareCommit('peer-a', manifest, principal, old)();
    const operations = internals.scopes.get('peer-a')!.operations;
    const operationKey = operations.keys().next().value!;
    operations.delete(operationKey);
    const current = internals.admit('peer-a', manifest, principal).record;
    const currentOperations = internals.scopes.get('peer-a')!.operations;
    const currentKey = currentOperations.keys().next().value!;

    expect(() => internals.acknowledge('peer-a', manifest, principal, old)).toThrowError(
      expect.objectContaining({ code: 'INTERNAL' })
    );
    expect(currentOperations.get(currentKey)).toBe(current);
  });

  it('enforces node-wide and canonical-principal receiver operation quotas across endpoint keys', () => {
    const ledger = new ReceiverOperationLedger({
      maxOperationRecords: 2,
      maxPrincipalOperationRecords: 2,
      maxGlobalOperationRecords: 3,
      maxReplayTombstones: 3,
      maxPrincipalReplayTombstones: 3,
      maxGlobalReplayTombstones: 3,
      operationRecordTtlMs: 15 * 60_000
    });
    const principalA = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const principalB = Object.freeze({ ...principalA, id: 'principal-b', subject: 'subject-b' });
    const manifest = (transferId: string): FileManifest => ({
      transferId,
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });

    const first = ledger.admit('peer-a1', manifest('a1'), principalA);
    const second = ledger.admit('peer-a2', manifest('a2'), principalA);
    expect(first.fresh).toBe(true);
    expect(second.fresh).toBe(true);
    expect(() => ledger.admit('peer-a3', manifest('a3'), principalA)).toThrowError(
      expect.objectContaining({ code: 'RESOURCE_LIMIT' })
    );
    expect(ledger.admit('peer-b1', manifest('b1'), principalB).fresh).toBe(true);
    expect(() => ledger.admit('peer-b2', manifest('b2'), principalB)).toThrowError(
      expect.objectContaining({ code: 'RESOURCE_LIMIT' })
    );
  });

  it('does not retain principal accounting for admissions rejected by the global quota', () => {
    const ledger = new ReceiverOperationLedger({
      maxOperationRecords: 2,
      maxPrincipalOperationRecords: 2,
      maxGlobalOperationRecords: 2,
      maxReplayTombstones: 2,
      maxPrincipalReplayTombstones: 2,
      maxGlobalReplayTombstones: 2,
      operationRecordTtlMs: 15 * 60_000
    });
    const basePrincipal = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const manifest = (transferId: string): FileManifest => ({
      transferId,
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });

    for (let index = 0; index < 2; index += 1) {
      const principal = Object.freeze({
        ...basePrincipal,
        id: `admitted-principal-${index}`,
        subject: `admitted-subject-${index}`
      });
      expect(ledger.admit(`admitted-peer-${index}`, manifest(`admitted-${index}`), principal).fresh).toBe(true);
    }

    for (let index = 0; index < 1_000; index += 1) {
      const principal = Object.freeze({
        ...basePrincipal,
        id: `rejected-principal-${index}`,
        subject: `rejected-subject-${index}`
      });
      expect(() => ledger.admit(`rejected-peer-${index}`, manifest(`rejected-${index}`), principal)).toThrowError(
        expect.objectContaining({ code: 'RESOURCE_LIMIT' })
      );
    }

    const internals = ledger as unknown as {
      scopes: Map<string, unknown>;
      principalUsage: Map<string, unknown>;
    };
    expect(internals.scopes.size).toBe(2);
    expect(internals.principalUsage.size).toBe(2);
  });

  it('bounds replay tombstones globally and per principal without retaining empty peer scopes', () => {
    const ledger = new ReceiverOperationLedger({
      maxOperationRecords: 2,
      maxPrincipalOperationRecords: 2,
      maxGlobalOperationRecords: 4,
      maxReplayTombstones: 2,
      maxPrincipalReplayTombstones: 2,
      maxGlobalReplayTombstones: 3,
      operationRecordTtlMs: 15 * 60_000
    });
    const principalA = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const principalB = Object.freeze({ ...principalA, id: 'principal-b', subject: 'subject-b' });
    const manifest = (transferId: string): FileManifest => ({
      transferId,
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });
    const reject = (peerId: string, transferId: string, principal: typeof principalA): void => {
      const value = manifest(transferId);
      const operation = ledger.admit(peerId, value, principal).record;
      ledger.reject(peerId, value, principal, operation as never);
    };

    reject('peer-a1', 'a1', principalA);
    reject('peer-a2', 'a2', principalA);
    reject('peer-a3', 'a3', principalA);
    reject('peer-b1', 'b1', principalB);
    reject('peer-b2', 'b2', principalB);
    const internals = ledger as unknown as {
      scopes: Map<string, unknown>;
      totalReplayTombstones: number;
      principalUsage: Map<string, { tombstones: number }>;
    };
    expect(internals.totalReplayTombstones).toBe(3);
    expect([...internals.principalUsage.values()].every((usage) => usage.tombstones <= 2)).toBe(true);
    expect(internals.scopes.size).toBe(3);
  });

  it('rejects new receiver operations after close and releases retained state on clear', () => {
    const ledger = new ReceiverOperationLedger({
      maxOperationRecords: 1,
      maxReplayTombstones: 1,
      operationRecordTtlMs: 15 * 60_000
    });
    const principal = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const manifest: FileManifest = {
      transferId: 'close-ledger',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    ledger.admit('peer-a', manifest, principal);
    ledger.close();
    expect(() => ledger.admit('peer-b', { ...manifest, transferId: 'closed' }, principal)).toThrowError(
      expect.objectContaining({ code: 'DISCONNECTED' })
    );
    ledger.clear();
    const internals = ledger as unknown as {
      scopes: Map<string, unknown>;
      principalUsage: Map<string, unknown>;
      expiryHeap: unknown[];
    };
    expect(internals.scopes.size).toBe(0);
    expect(internals.principalUsage.size).toBe(0);
    expect(internals.expiryHeap).toHaveLength(0);
  });

  it('starts the ambiguous reconciliation TTL at durable commit', () => {
    let now = 1_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      operationRecordTtlMs: 1_000
    });
    const manifest: FileManifest = {
      transferId: 'commit-window',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    const principal = testContext(testConnection(duplexPair().left, new AsyncPipe())).security.principal;
    const internals = manager as unknown as {
      operationRecord(value: FileManifest, identity: typeof principal): { record: object };
      prepareCommitOperation(value: FileManifest, identity: typeof principal, record: object): () => void;
    };
    const record = internals.operationRecord(manifest, principal).record;
    const commit = internals.prepareCommitOperation(manifest, principal, record);

    // Simulate finalization taking longer than the whole configured window.
    now = 2_500;
    commit();
    expect(manager.diagnostics()).toMatchObject({ ambiguousOperations: 1, operationRecords: 1 });
    now = 3_499;
    expect(manager.diagnostics()).toMatchObject({ ambiguousOperations: 1, operationRecords: 1 });
    now = 3_500;
    expect(manager.diagnostics()).toMatchObject({ ambiguousOperations: 0, operationRecords: 0 });
  });

  it('owns one prepared source lifecycle across hashing and transmission', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    let prepares = 0;
    let closes = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => context,
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      const completion = await readFrame<Record<string, unknown>>(control.right.recv);
      await acknowledgeLocalSender(control.right, completion.value);
    })();
    const transfer = await manager.sendFile({
      name: 'empty.bin',
      size: 0,
      prepare: async () => {
        prepares += 1;
        return {
          name: 'empty.bin',
          size: 0,
          readChunk: async () => { throw new Error('empty source must not be read'); },
          close: async () => { closes += 1; }
        };
      },
      readChunk: async () => { throw new Error('unprepared source must not be read'); }
    });
    await transfer.result;
    await remote;
    expect({ prepares, closes }).toEqual({ prepares: 1, closes: 1 });
  });

  it('keeps an acknowledged send successful when its prepared source fails to close', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const cleanupFailure = new Error('descriptor close rejected');
    let connectionRequests = 0;
    let closes = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { connectionRequests += 1; return context; },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      const completion = await readFrame<Record<string, unknown>>(control.right.recv);
      await acknowledgeLocalSender(control.right, completion.value);
    })();
    const transfer = await manager.sendFile({
      name: 'close-after-success.bin',
      size: 0,
      prepare: async () => ({
        name: 'close-after-success.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { closes += 1; throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    });

    await expect(transfer.result).resolves.toMatchObject({ manifest: { name: 'close-after-success.bin' } });
    await remote;
    expect({ connectionRequests, closes }).toEqual({ connectionRequests: 1, closes: 1 });
  });

  it('combines a send failure and prepared-source close failure into a terminal outcome', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const cleanupFailure = new Error('descriptor close rejected');
    let connectionRequests = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { connectionRequests += 1; return context; },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      await readFrame(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Reject, {
        code: 'REJECTED',
        reason: 'Transfer rejected'
      });
      await control.right.send.finish();
    })();
    const transfer = await manager.sendFile({
      name: 'close-after-failure.bin',
      size: 0,
      prepare: async () => ({
        name: 'close-after-failure.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    });

    const error = await transfer.result.then(() => undefined, (cause: unknown) => cause);
    expect(error).toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: {
        operation: { code: 'REJECTED' },
        cleanup: { code: 'INTERNAL', cause: cleanupFailure }
      }
    });
    await remote;
    expect(connectionRequests).toBe(1);
  });

  it('preserves an existing indeterminate send cause when prepared-source close also fails', async () => {
    const control = duplexPair();
    const cleanupFailure = new Error('descriptor close rejected');
    let connectionRequests = 0;
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { connectionRequests += 1; return context; },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const remote = (async () => {
      await control.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(control.right.recv);
      await writeFrame(control.right.send, TransferFrameKind.Accept, {
        transferId: offer.value.transferId,
        attemptId: 'a'.repeat(22),
        laneToken: 'b'.repeat(43),
        missingRanges: [],
        missingCount: 0,
        lanes: 1
      });
      await readFrame(control.right.recv);
      await control.right.send.finish();
    })();
    const transfer = await manager.sendFile({
      name: 'indeterminate-close.bin',
      size: 0,
      prepare: async () => ({
        name: 'indeterminate-close.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    });

    const error = await transfer.result.then(() => undefined, (cause: unknown) => cause);
    expect(error).toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: {
        operation: { code: 'OUTCOME_UNKNOWN' },
        cleanup: { code: 'INTERNAL', cause: cleanupFailure }
      }
    });
    await remote;
    expect(connectionRequests).toBe(1);
  });

  it('combines manifest preparation and prepared-source close failures before connecting', async () => {
    const operationFailure = new Error('source read rejected');
    const cleanupFailure = new Error('descriptor close rejected');
    let connections = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { connections += 1; throw new Error('must not connect'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });

    const error = await manager.sendFile({
      name: 'manifest-close-failure.bin',
      size: 1,
      prepare: async () => ({
        name: 'manifest-close-failure.bin',
        size: 1,
        readChunk: async () => { throw operationFailure; },
        close: async () => { throw cleanupFailure; }
      }),
      readChunk: async () => Uint8Array.of(1)
    }).then(() => undefined, (cause: unknown) => cause);

    expect(error).toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: {
        operation: { code: 'INTERNAL', cause: operationFailure },
        cleanup: { code: 'INTERNAL', cause: cleanupFailure }
      }
    });
    expect(connections).toBe(0);
  });

  it('keeps an acknowledged shared pull successful when its prepared source fails to close', async () => {
    const cleanupFailure = new Error('shared descriptor close rejected');
    let closes = 0;
    const source = {
      name: 'shared-close.bin',
      size: 0,
      prepare: async () => ({
        name: 'shared-close.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { closes += 1; throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const control = duplexPair();
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()))
    );

    await acknowledgeEmptyPull(control.right, handle.token, 'shared-close-success');
    await expect(handling).resolves.toBeUndefined();
    expect(closes).toBe(1);
    expect(shares.operationStatus(handle.token, 'shared-close-success')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    expect(() => shares.reserve(handle.token, shareReservationRequest('shared-close-success')))
      .toThrow(/invalid or unavailable/);
  });

  it('combines shared-pull and prepared-source close failures and consumes the capability', async () => {
    const cleanupFailure = new Error('shared descriptor close rejected');
    const source = {
      name: 'shared-close-failure.bin',
      size: 0,
      prepare: async () => ({
        name: 'shared-close-failure.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const control = duplexPair();
    await writePull(control.right.send, handle.token, 'shared-close-failure');
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()))
    );
    expect((await readFrame(control.right.recv)).kind).toBe(TransferFrameKind.Offer);
    await writeFrame(control.right.send, TransferFrameKind.Reject, {
      code: 'REJECTED',
      reason: 'Transfer rejected'
    });
    await control.right.send.finish();

    await expect(handling).rejects.toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: {
        operation: { code: 'REJECTED' },
        cleanup: { code: 'INTERNAL', cause: cleanupFailure }
      }
    });
    expect(shares.operationStatus(handle.token, 'shared-close-failure')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    expect(() => shares.reserve(handle.token, {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: `v${PROTOCOL_VERSION}:65536:1`,
      operationId: 'shared-close-failure'
    })).toThrow(/invalid or unavailable/);
  });

  it('allows only a bounded reconnect after a drained disconnect and reauthorizes it', async () => {
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    let authorizations = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => { authorizations += 1; }
    });

    const disconnected = duplexPair();
    await writePull(disconnected.right.send, handle.token, 'request-a');
    const firstHandling = manager.handleControl(
      disconnected.left,
      testContext(testConnection(disconnected.left, new AsyncPipe()))
    );
    expect((await readFrame(disconnected.right.recv)).kind).toBe(TransferFrameKind.Offer);
    await disconnected.right.send.finish();
    await expect(firstHandling).rejects.toMatchObject({ code: 'DISCONNECTED' });

    const resumed = duplexPair();
    const secondHandling = manager.handleControl(resumed.left, testContext(testConnection(resumed.left, new AsyncPipe())));
    await acknowledgeEmptyPull(resumed.right, handle.token, 'request-a');
    await secondHandling;
    expect(authorizations).toBe(2);

    const replay = duplexPair();
    await writePull(replay.right.send, handle.token, 'request-a');
    const replayHandling = manager.handleControl(replay.left, testContext(testConnection(replay.left, new AsyncPipe())));
    expect((await readFrame(replay.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(replayHandling).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('keeps a shared pull active until prepared-source cleanup proves reconnect is safe', async () => {
    const closeStarted = deferred<void>();
    const closeRelease = deferred<void>();
    const source = {
      name: 'deferred-close.bin',
      size: 0,
      prepare: async () => ({
        name: 'deferred-close.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => {
          closeStarted.resolve();
          await closeRelease.promise;
        }
      }),
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const control = duplexPair();
    const connectionController = new AbortController();
    await writePull(control.right.send, handle.token, 'deferred-close');
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()), { signal: connectionController.signal })
    );
    expect((await readFrame(control.right.recv)).kind).toBe(TransferFrameKind.Offer);
    connectionController.abort(new P2PError('DISCONNECTED', 'Physical connection replaced'));
    await closeStarted.promise;

    expect(shares.operationStatus(handle.token, 'deferred-close')).toEqual({ state: 'active' });
    expect(shares.diagnostics().activeReservations).toBe(1);
    expect(() => shares.reserve(handle.token, shareReservationRequest('deferred-close')))
      .toThrow(/invalid or unavailable/);

    closeRelease.resolve();
    await expect(handling).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(shares.operationStatus(handle.token, 'deferred-close')).toEqual({ state: 'reconnectable' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    const resumed = shares.reserve(handle.token, shareReservationRequest('deferred-close'));
    expect(resumed.source).toBe(source);
    resumed.complete();
  });

  it('makes a trusted disconnect terminal when prepared-source cleanup is uncertain', async () => {
    const cleanupFailure = new Error('descriptor close rejected');
    const source = {
      name: 'disconnect-close-failure.bin',
      size: 0,
      prepare: async () => ({
        name: 'disconnect-close-failure.bin',
        size: 0,
        readChunk: async () => new Uint8Array(),
        close: async () => { throw cleanupFailure; }
      }),
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const control = duplexPair();
    const connectionController = new AbortController();
    await writePull(control.right.send, handle.token, 'disconnect-close-failure');
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()), { signal: connectionController.signal })
    );
    expect((await readFrame(control.right.recv)).kind).toBe(TransferFrameKind.Offer);
    connectionController.abort(new P2PError('DISCONNECTED', 'Physical connection replaced'));

    await expect(handling).rejects.toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: { cleanup: { cause: cleanupFailure } }
    });
    expect(shares.operationStatus(handle.token, 'disconnect-close-failure')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    expect(() => shares.reserve(handle.token, shareReservationRequest('disconnect-close-failure')))
      .toThrow(/invalid or unavailable/);
  });

  it('does not reconnect a shared pull when transport stream cleanup is unconfirmed', async () => {
    const source = { name: 'stream-cleanup-failure.bin', size: 0, readChunk: async () => new Uint8Array() };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const outbound = new CleanupRejectingPipe();
    const inbound = new CleanupRejectingPipe();
    const local: QuicBiStream = { send: outbound, recv: inbound };
    const remote: QuicBiStream = { send: inbound, recv: outbound };
    const connectionController = new AbortController();
    await writePull(remote.send, handle.token, 'stream-cleanup-failure');
    const handling = manager.handleControl(
      local,
      testContext(testConnection(local, new AsyncPipe()), { signal: connectionController.signal })
    );
    expect((await readFrame(remote.recv)).kind).toBe(TransferFrameKind.Offer);
    connectionController.abort(new P2PError('DISCONNECTED', 'Physical connection replaced'));

    await expect(handling).rejects.toMatchObject({ code: 'INTERNAL' });
    expect(shares.operationStatus(handle.token, 'stream-cleanup-failure')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    expect(() => shares.reserve(handle.token, shareReservationRequest('stream-cleanup-failure')))
      .toThrow(/invalid or unavailable/);
  });

  it('does not let a source manufacture reconnect authority with a DISCONNECTED code', async () => {
    let reads = 0;
    const source = {
      name: 'application-disconnect.bin',
      size: 1,
      prepare: async () => ({
        name: 'application-disconnect.bin',
        size: 1,
        readChunk: async () => {
          reads += 1;
          if (reads === 1) return Uint8Array.of(4);
          throw new P2PError('DISCONNECTED', 'application read failed');
        },
        close: async () => undefined
      }),
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const control = duplexPair();
    await writePull(control.right.send, handle.token, 'application-disconnect');
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()))
    );
    const handlingOutcome = handling.then(
      () => undefined,
      (cause: unknown) => cause
    );
    const offer = await readFrame<FileManifest>(control.right.recv);
    expect(offer.kind).toBe(TransferFrameKind.Offer);
    await writeFrame(control.right.send, TransferFrameKind.Accept, {
      transferId: 'application-disconnect',
      attemptId: 'a'.repeat(22),
      laneToken: 'b'.repeat(43),
      missingRanges: [[0, 1]],
      missingCount: 1,
      lanes: 1
    });

    await expect(handlingOutcome).resolves.toMatchObject({ code: 'DISCONNECTED' });
    expect(shares.operationStatus(handle.token, 'application-disconnect')).toEqual({ state: 'completed' });
    expect(shares.diagnostics().activeReservations).toBe(0);
    expect(() => shares.reserve(handle.token, shareReservationRequest('application-disconnect')))
      .toThrow(/invalid or unavailable/);
  });

  it('does not let a source replay a prior attempt abort reason', async () => {
    const prepareStarted = deferred<void>();
    let prepares = 0;
    let staleReason: unknown;
    const source = {
      name: 'stale-abort-reason.bin',
      size: 0,
      prepare: async (signal?: AbortSignal): Promise<never> => {
        prepares += 1;
        if (prepares === 2) throw staleReason;
        prepareStarted.resolve();
        await new Promise<never>((_resolve, reject) => {
          const abort = (): void => {
            staleReason = signal?.reason;
            reject(staleReason);
          };
          if (signal?.aborted) abort();
          else signal?.addEventListener('abort', abort, { once: true });
        });
        throw new Error('Prepared-source cancellation promise unexpectedly resolved');
      },
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });

    const first = duplexPair();
    const firstController = new AbortController();
    await writePull(first.right.send, handle.token, 'stale-abort-reason');
    const firstHandling = manager.handleControl(
      first.left,
      testContext(testConnection(first.left, new AsyncPipe()), { signal: firstController.signal })
    );
    await prepareStarted.promise;
    firstController.abort(new P2PError('DISCONNECTED', 'First physical connection replaced'));
    await expect(firstHandling).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(shares.operationStatus(handle.token, 'stale-abort-reason')).toEqual({ state: 'reconnectable' });

    const second = duplexPair();
    const secondController = new AbortController();
    await writePull(second.right.send, handle.token, 'stale-abort-reason');
    await expect(manager.handleControl(
      second.left,
      testContext(testConnection(second.left, new AsyncPipe()), { signal: secondController.signal })
    )).rejects.toMatchObject({ code: 'DISCONNECTED' });

    expect(secondController.signal.aborted).toBe(false);
    expect((second.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((second.left.recv as AsyncPipe).stopCalls).toBe(1);
    expect(shares.operationStatus(handle.token, 'stale-abort-reason')).toEqual({ state: 'completed' });
    expect(() => shares.reserve(handle.token, shareReservationRequest('stale-abort-reason')))
      .toThrow(/invalid or unavailable/);
  });

  it('settles the current stream when a source replays a prior drained handler error', async () => {
    let prepares = 0;
    const replay: { failure?: unknown } = {};
    const source = {
      name: 'stale-drain-proof.bin',
      size: 0,
      prepare: async () => {
        prepares += 1;
        if (prepares === 2) throw replay.failure;
        return {
          name: 'stale-drain-proof.bin',
          size: 0,
          readChunk: async () => new Uint8Array(),
          close: async () => undefined
        };
      },
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });

    const first = duplexPair();
    const firstController = new AbortController();
    await writePull(first.right.send, handle.token, 'stale-drain-proof');
    const firstHandling = manager.handleControl(
      first.left,
      testContext(testConnection(first.left, new AsyncPipe()), { signal: firstController.signal })
    );
    expect((await readFrame(first.right.recv)).kind).toBe(TransferFrameKind.Offer);
    firstController.abort(new P2PError('DISCONNECTED', 'First physical connection replaced'));
    replay.failure = await firstHandling.then(
      () => undefined,
      (cause: unknown) => cause
    );
    expect(replay.failure).toMatchObject({ code: 'DISCONNECTED' });
    expect(shares.operationStatus(handle.token, 'stale-drain-proof')).toEqual({ state: 'reconnectable' });

    const second = duplexPair();
    const secondController = new AbortController();
    await writePull(second.right.send, handle.token, 'stale-drain-proof');
    await expect(manager.handleControl(
      second.left,
      testContext(testConnection(second.left, new AsyncPipe()), { signal: secondController.signal })
    )).rejects.toMatchObject({ code: 'DISCONNECTED' });

    expect(secondController.signal.aborted).toBe(false);
    expect((second.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((second.left.send as AsyncPipe).resetCalls).toBe(0);
    expect((second.left.recv as AsyncPipe).stopCalls).toBe(1);
    expect(shares.operationStatus(handle.token, 'stale-drain-proof')).toEqual({ state: 'completed' });
  });

  it('does not grant reconnect authority to a bare connection abort', async () => {
    const prepareStarted = deferred<void>();
    const source = {
      name: 'bare-abort.bin',
      size: 0,
      prepare: async (signal?: AbortSignal): Promise<never> => {
        prepareStarted.resolve();
        await new Promise<never>((_resolve, reject) => {
          const abort = (): void => reject(signal?.reason);
          if (signal?.aborted) abort();
          else signal?.addEventListener('abort', abort, { once: true });
        });
        throw new Error('Prepared-source cancellation promise unexpectedly resolved');
      },
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const control = duplexPair();
    const connectionController = new AbortController();
    await writePull(control.right.send, handle.token, 'bare-connection-abort');
    const handling = manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()), { signal: connectionController.signal })
    );
    await prepareStarted.promise;
    connectionController.abort();

    expect((await readFrame(control.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(handling).rejects.toMatchObject({ code: 'CANCELLED' });
    expect((control.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).stopCalls).toBe(1);
    expect(shares.operationStatus(handle.token, 'bare-connection-abort')).toEqual({ state: 'completed' });
    expect(() => shares.reserve(handle.token, shareReservationRequest('bare-connection-abort')))
      .toThrow(/invalid or unavailable/);
  });

  it('does not redial when an outbound source replays a prior transport abort reason', async () => {
    const captureStarted = deferred<void>();
    let staleReason: unknown;
    const captureSource = {
      name: 'capture-retry-reason.bin',
      size: 0,
      prepare: async (signal?: AbortSignal): Promise<never> => {
        captureStarted.resolve();
        await new Promise<never>((_resolve, reject) => {
          const abort = (): void => {
            staleReason = signal?.reason;
            reject(staleReason);
          };
          if (signal?.aborted) abort();
          else signal?.addEventListener('abort', abort, { once: true });
        });
        throw new Error('Prepared-source cancellation promise unexpectedly resolved');
      },
      readChunk: async () => new Uint8Array()
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(captureSource, 'peer-a');
    const outboundControl = duplexPair();
    let connectionRequests = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => {
        connectionRequests += 1;
        if (connectionRequests > 1) throw new P2PError('REJECTED', 'Unexpected redial');
        return testContext(testConnection(outboundControl.left, new RecordingPipe()));
      },
      shares,
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });

    const capture = duplexPair();
    const captureController = new AbortController();
    await writePull(capture.right.send, handle.token, 'capture-retry-reason');
    const captureHandling = manager.handleControl(
      capture.left,
      testContext(testConnection(capture.left, new AsyncPipe()), { signal: captureController.signal })
    );
    await captureStarted.promise;
    captureController.abort(new P2PError('DISCONNECTED', 'Capture physical connection replaced'));
    await expect(captureHandling).rejects.toMatchObject({ code: 'DISCONNECTED' });

    let reads = 0;
    const transfer = await manager.sendFile({
      name: 'stale-outbound-retry.bin',
      size: 1,
      readChunk: async () => {
        reads += 1;
        if (reads === 1) return Uint8Array.of(7);
        throw staleReason;
      }
    }, { lanes: 1, chunkSize: 64 * 1024 });
    const remote = (async () => {
      await outboundControl.right.recv.readExact(1);
      const offer = await readFrame<FileManifest>(outboundControl.right.recv);
      await acceptAllChunks(outboundControl.right.send, offer.value);
    })();

    await expect(transfer.result).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await remote;
    expect(connectionRequests).toBe(1);
  });

  it('prefers a delayed receiver rejection over a racing lane write error without retrying', async () => {
    const control = duplexPair();
    const lane = new RejectingSendStream();
    let connectionRequests = 0;
    const context = testContext(testConnection(control.left, lane));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => {
        connectionRequests += 1;
        return context;
      },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'destination-failure.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    }, { lanes: 1, chunkSize: 64 * 1024 });

    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await lane.writeAttempted;
    // Independent QUIC streams are unordered. This intentionally exceeds the
    // former one-second heuristic so a delayed control Reject remains the
    // terminal decision and cannot cause a duplicate transfer attempt.
    await new Promise<void>((resolve) => setTimeout(resolve, 1_200));
    await writeFrame(control.right.send, TransferFrameKind.Reject, {
      code: 'INTERNAL',
      reason: 'Transfer rejected'
    });
    await control.right.send.finish();

    await expect(transfer.result).rejects.toMatchObject({ code: 'REJECTED' });
    expect(connectionRequests).toBe(1);
    expect(lane.resetCalls).toBeGreaterThan(0);
  });

  it('does no source or network work for pre-aborted transfers', async () => {
    let sourceReads = 0;
    let connections = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => {
        connections += 1;
        throw new Error('must not connect');
      },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const controller = new AbortController();
    controller.abort();
    const source = {
      name: 'cancelled.bin',
      size: 1,
      readChunk: async () => {
        sourceReads += 1;
        return Uint8Array.of(1);
      }
    };
    const destination: FileDestination = {
      prepare: async () => { throw new Error('must not prepare'); },
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => undefined
    };

    await expect(manager.sendFile(source, { signal: controller.signal })).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(manager.download('a'.repeat(43), destination, { signal: controller.signal }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
    expect(sourceReads).toBe(0);
    expect(connections).toBe(0);
  });

  it('applies transfer admission before outbound manifest hashing', async () => {
    const hashingStarted = deferred<void>();
    let secondReads = 0;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      limits: { maxTransfers: 1, maxQueuedTransfers: 0 }
    });
    const controller = new AbortController();
    const first = manager.sendFile({
      name: 'first.bin',
      size: 1,
      async readChunk(_index, _chunkSize, signal) {
        hashingStarted.resolve();
        await new Promise<void>((_resolve, reject) => {
          if (signal?.aborted) reject(signal.reason);
          else signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
        });
        return Uint8Array.of(1);
      }
    }, { signal: controller.signal, chunkSize: 64 * 1024 });
    await hashingStarted.promise;
    await expect(manager.sendFile({
      name: 'second.bin',
      size: 1,
      readChunk: async () => {
        secondReads += 1;
        return Uint8Array.of(2);
      }
    }, { chunkSize: 64 * 1024 })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(secondReads).toBe(0);
    controller.abort();
    await expect(first).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('cancels a stalled write and resets every active stream', async () => {
    const control = duplexPair();
    const stalled = new StalledSendStream();
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(testConnection(control.left, stalled)),
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'cancel.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await stalled.started;

    transfer.cancel();
    await expect(transfer.result).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(stalled.resetCalls).toBeGreaterThan(0);
    expect((control.left.send as AsyncPipe).resetCalls).toBeGreaterThan(0);
    expect((control.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
  });

  it('cancels a stalled receive and stops every active stream', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const manifest = oneByteManifest('cancel-receive');
    let destinationAborted = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => { destinationAborted = true; }
    };
    const control = duplexPair();
    const controller = new AbortController();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receive = privateReceive(manager, context);
    const receiving = receive(control.left, manifest, destination, undefined, controller.signal);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = await stalledLane(manifest, accepted.value);
    const handlingLane = manager.handleData(lane, context);
    await lane.waitingForBytes;

    controller.abort();
    await expect(receiving).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(handlingLane).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(lane.stopCalls).toBeGreaterThan(0);
    expect((control.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
    expect(destinationAborted).toBe(true);
  });

  it('times out a flow-control-stalled write and resets its streams', async () => {
    const control = duplexPair();
    const stalled = new StalledSendStream();
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(testConnection(control.left, stalled)),
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const transfer = await manager.sendFile({
      name: 'timeout.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await stalled.started;

    await expect(transfer.result).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(stalled.resetCalls).toBeGreaterThan(0);
    expect((control.left.send as AsyncPipe).resetCalls).toBeGreaterThan(0);
    expect((control.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
  });

  it('times out a stalled finish and resets the lane', async () => {
    const control = duplexPair();
    const stalled = new FinishStalledSendStream();
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(testConnection(control.left, stalled)),
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const transfer = await manager.sendFile({
      name: 'finish-timeout.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await stalled.finishStarted;

    await expect(transfer.result).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(stalled.resetCalls).toBeGreaterThan(0);
  });

  it('times out opening a lane and resets the stream if it resolves late', async () => {
    const control = duplexPair();
    const laneRequested = deferred<void>();
    const lateLane = deferred<QuicSendStream>();
    const base = testConnection(control.left, new AsyncPipe());
    const connection: QuicConnection = {
      ...base,
      openUni: () => {
        laneRequested.resolve();
        return lateLane.promise;
      }
    };
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(connection),
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const transfer = await manager.sendFile({
      name: 'open-timeout.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await laneRequested.promise;

    await expect(transfer.result).rejects.toMatchObject({ code: 'TIMEOUT' });
    const resolvedLate = new AsyncPipe();
    lateLane.resolve(resolvedLate);
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(resolvedLate.resetCalls).toBeGreaterThan(0);
  });

  it('quarantines a pending lane open immediately and keeps late-reset failure fail-closed', async () => {
    const control = duplexPair();
    const laneRequested = deferred<void>();
    const lateLane = deferred<QuicSendStream>();
    const base = testConnection(control.left, new AsyncPipe());
    const recorded = recordConnectionClose({
      ...base,
      openUni: () => {
        laneRequested.resolve();
        return lateLane.promise;
      }
    });
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(recorded.connection),
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const transfer = await manager.sendFile({
      name: 'late-lane-cleanup.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await laneRequested.promise;

    await expect(transfer.result).rejects.toMatchObject({ code: 'TIMEOUT' });
    await expect(recorded.firstClose).resolves.toEqual({
      code: 4n,
      reason: 'File stream cleanup failed'
    });
    const resolvedLate = new ResetRejectingSendStream();
    lateLane.resolve(resolvedLate);

    await expect.poll(() => resolvedLate.resetCalls).toBe(1);
    expect(recorded.calls.length).toBeGreaterThanOrEqual(1);
  });

  it('quarantines a pending control open immediately and keeps late-reset failure fail-closed', async () => {
    const controlRequested = deferred<void>();
    const lateControl = deferred<QuicBiStream>();
    const base = testConnection(duplexPair().left, new AsyncPipe());
    const recorded = recordConnectionClose({
      ...base,
      openBi: () => {
        controlRequested.resolve();
        return lateControl.promise;
      }
    });
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(recorded.connection),
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const transfer = await manager.sendFile({
      name: 'late-control-cleanup.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
    await controlRequested.promise;

    await expect(transfer.result).rejects.toMatchObject({ code: 'TIMEOUT' });
    await expect(recorded.firstClose).resolves.toEqual({
      code: 4n,
      reason: 'File stream cleanup failed'
    });
    const rejectedSend = new ResetRejectingSendStream();
    lateControl.resolve({ send: rejectedSend, recv: new AsyncPipe() });

    await expect.poll(() => rejectedSend.resetCalls).toBe(1);
    expect(recorded.calls.length).toBeGreaterThanOrEqual(1);
  });

  it('treats a rejected active-lane reset as cleanup failure and quarantines its connection', async () => {
    const control = duplexPair();
    const lane = new ResetRejectingSendStream();
    const recorded = recordConnectionClose(testConnection(control.left, lane));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => testContext(recorded.connection),
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'rejected-reset.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    await lane.started;

    transfer.cancel();
    await expect(transfer.result).rejects.toMatchObject({ code: 'INTERNAL' });
    await expect(recorded.firstClose).resolves.toEqual({
      code: 4n,
      reason: 'File stream cleanup failed'
    });
    expect(lane.resetCalls).toBeGreaterThan(0);
  });

  it('times out a stalled lane stop and quarantines its connection', async () => {
    const lane = new StopStalledRecvStream();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: 'stale-stalled-lane',
      attemptId: 'a'.repeat(22),
      laneToken: 'b'.repeat(43),
      laneId: 0,
      count: 1
    });
    const recorded = recordConnectionClose(testConnection(duplexPair().left, new AsyncPipe()));
    const context = testContext(recorded.connection);
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });

    await expect(manager.handleData(lane, context)).rejects.toMatchObject({ code: 'INTERNAL' });
    await expect(recorded.firstClose).resolves.toEqual({
      code: 4n,
      reason: 'File stream cleanup failed'
    });
    expect(lane.stopCalls).toBe(1);
  });

  it('times out a stalled read and stops its streams', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const manifest = oneByteManifest('timeout-receive');
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => undefined
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receive = privateReceive(manager, context);
    const receiving = receive(control.left, manifest, destination, undefined, new AbortController().signal);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = await stalledLane(manifest, accepted.value);
    const handlingLane = manager.handleData(lane, context);
    await lane.waitingForBytes;

    await expect(receiving).rejects.toMatchObject({ code: 'TIMEOUT' });
    await expect(handlingLane).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(lane.stopCalls).toBeGreaterThan(0);
    expect((control.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
  });

  it('rejects source symlinks and changes after authorization', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-source-security-'));
    temporary.push(directory);
    const input = join(directory, 'input.bin');
    const linked = join(directory, 'linked.bin');
    await writeFile(input, 'first-value');
    await symlink(input, linked);
    await expect(fileSource(linked)).rejects.toMatchObject({ code: 'REJECTED' });

    const source = await fileSource(input);
    await writeFile(input, 'other-value');
    const changedAt = new Date(Date.now() + 60_000);
    await utimes(input, changedAt, changedAt);
    await expect(source.readChunk(0, 64 * 1024)).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' });
  });

  it('uses restrictive partial permissions and never overwrites a raced destination', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-destination-security-'));
    temporary.push(directory);
    const input = join(directory, 'input.bin');
    const output = join(directory, 'output.bin');
    const bytes = Buffer.from('secure destination');
    await writeFile(input, bytes);
    const source = await fileSource(input);
    const manifest = await createManifest(source, { chunkSize: 64 * 1024 });
    const destination = fileDestination(output);
    await destination.prepare(manifest);
    if (process.platform !== 'win32') {
      expect((await stat(`${output}.p2prpc.part`)).mode & 0o777).toBe(0o600);
    }
    await destination.writeChunk(manifest, 0, bytes);
    await writeFile(output, 'winner');
    await expect(destination.finalize(manifest, finalizeContext())).rejects.toMatchObject({ code: 'REJECTED' });
    expect(await readFile(output, 'utf8')).toBe('winner');
    await destination.abort(manifest, { discard: true });
  });

  it('rejects non-boolean destination safety options instead of enabling overwrite accidentally', () => {
    expect(() => fileDestination('/unused', { overwrite: 'false' as never })).toThrow(/overwrite.*boolean/);
    expect(() => fileDestination('/unused', { durable: 'false' as never })).toThrow(/durable.*boolean/);
  });

  it('does not follow a malicious partial-file symlink', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-partial-security-'));
    temporary.push(directory);
    const victim = join(directory, 'victim.bin');
    const output = join(directory, 'output.bin');
    await writeFile(victim, 'do-not-touch');
    await symlink(victim, `${output}.p2prpc.part`);
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const manifest = await createManifest(source, { chunkSize: 64 * 1024 });
    const destination = fileDestination(output);
    await destination.prepare(manifest);
    expect((await lstat(`${output}.p2prpc.part`)).isSymbolicLink()).toBe(false);
    await destination.finalize(manifest, finalizeContext());
    expect(await readFile(victim, 'utf8')).toBe('do-not-touch');
  });

  it('surfaces managed-path replacement during cleanup without deleting the replacement', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-cleanup-race-'));
    temporary.push(directory);
    const output = join(directory, 'output.bin');
    const source = { name: 'empty.bin', size: 0, readChunk: async () => new Uint8Array() };
    const manifest = await createManifest(source, { chunkSize: 64 * 1024 });
    const destination = fileDestination(output);
    await destination.prepare(manifest);

    const partialPath = `${output}.p2prpc.part`;
    await rename(partialPath, `${partialPath}.moved`);
    await writeFile(partialPath, 'local-replacement');

    await expect(destination.abort(manifest, { discard: true })).rejects.toMatchObject({
      code: 'INTERNAL'
    });
    expect(await readFile(partialPath, 'utf8')).toBe('local-replacement');
    await expect(lstat(`${output}.p2prpc.lock`)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('rejects oversized and unsafe manifests before allocating chunk state', () => {
    const base = {
      transferId: 'transfer-1',
      name: 'file.bin',
      size: 64 * 1024,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 1
    };
    expect(() => validateManifest({ ...base, name: '../escape' }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/name/);
    expect(() => validateManifest({ ...base, name: 'report\u202egnp.exe' }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/name/);
    expect(() => validateManifest({ ...base, name: 'report\u0085.pdf' }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/name/);
    expect(() => validateManifest({
      ...base,
      size: DEFAULT_FILE_TRANSFER_LIMITS.maxFileSize + 1,
      chunkCount: DEFAULT_FILE_TRANSFER_LIMITS.maxChunkCount + 1
    }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/size/);
    expect(() => validateManifest({ ...base, digest: 'not-a-digest' }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/digest/);
  });

  it('rejects duplicate sessions and oversized chunk bodies before reading them', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
    });
    const manifest: FileManifest = {
      transferId: 'active-transfer',
      name: 'file.bin',
      size: 64 * 1024,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 1
    };
    let aborted = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => { aborted = true; }
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receive = privateReceive(manager, context);
    const receiving = receive(control.left, manifest, destination, undefined, new AbortController().signal);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(accepted.kind).toBe(TransferFrameKind.Accept);

    const duplicate = duplexPair();
    await expect(receive(duplicate.left, manifest, destination, undefined, new AbortController().signal))
      .rejects.toThrow(/already active/);

    const lane = new RecordingPipe();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: 0xffff_ffff,
      digest: '0'.repeat(64)
    });
    await expect(manager.handleData(lane, context)).rejects.toThrow(/size/);
    await expect(receiving).rejects.toThrow(/size/);
    expect(Math.max(...lane.readSizes)).toBeLessThan(1024 * 1024);
    expect(aborted).toBe(true);
  });

  it('authorizes a parsed file offer before invoking the incoming-file handler', async () => {
    let incomingCalled = false;
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => { throw new Error('policy denied'); },
      incoming: () => { incomingCalled = true; return { reject: true }; }
    });
    const control = duplexPair();
    await writeFrame(control.right.send, TransferFrameKind.Offer, {
      transferId: 'denied-transfer',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    });
    const handling = manager.handleControl(control.left, testContext(testConnection(control.left, new AsyncPipe())));
    const rejection = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(rejection.kind).toBe(TransferFrameKind.Reject);
    await expect(handling).rejects.toThrow(/policy denied/);
    expect(incomingCalled).toBe(false);
  });

  it('binds data lanes to the exact authenticated connection context', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const byte = Uint8Array.of(7);
    const manifest: FileManifest = {
      transferId: 'connection-bound-transfer',
      name: 'bound.bin',
      size: 1,
      digest: chunkDigest(byte),
      chunkSize: 64 * 1024,
      chunkCount: 1
    };
    const writes: Uint8Array[] = [];
    let finalized = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async (_manifest, _index, data) => { writes.push(data.slice()); },
      finalize: async (_manifest, context) => {
        finalized = true;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const control = duplexPair();
    const connection = testConnection(control.left, new AsyncPipe());
    const context = testContext(connection, { sessionId: 'session-a' });
    const replacement = testContext(connection, { sessionId: 'session-b' });
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);

    const staleLane = new AsyncPipe();
    await writeFrame(staleLane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await expect(manager.handleData(staleLane, replacement)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(staleLane.stopCalls).toBeGreaterThan(0);
    expect(writes).toHaveLength(0);

    const lane = new RecordingPipe();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: 1,
      digest: chunkDigest(byte)
    });
    await lane.writeAll(byte);
    await lane.finish();
    await manager.handleData(lane, context);
    await completeLocalReceiver(control.right, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await receiving;
    expect(writes).toEqual([byte]);
    expect(finalized).toBe(true);
    expect(lane.expectEndCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).expectEndCalls).toBe(1);
  });

  it('waits for every data-lane FIN before finalizing and acknowledging a transfer', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const byte = Uint8Array.of(11);
    const manifest: FileManifest = {
      ...oneByteManifest('lane-fin-before-finalize'),
      digest: chunkDigest(byte)
    };
    const chunkWritten = deferred<void>();
    let finalized = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => { chunkWritten.resolve(); },
      finalize: async (_manifest, context) => {
        finalized = true;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = new AsyncPipe();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: byte.byteLength,
      digest: chunkDigest(byte)
    });
    await lane.writeAll(byte);
    const handlingLane = manager.handleData(lane, context);
    await chunkWritten.promise;
    const terminal = completeLocalReceiver(control.right, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(finalized).toBe(false);

    await lane.finish();
    await handlingLane;
    await terminal;
    await receiving;
    expect(finalized).toBe(true);
    expect(lane.expectEndCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).expectEndCalls).toBe(1);
  });

  it('keeps a healthy segmented transfer alive beyond one idle interval', async () => {
    const idleTimeoutMs = 1_000;
    const segmentBytes = 64 * 1024;
    const data = new Uint8Array(4 * segmentBytes).fill(23);
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs
    });
    const manifest: FileManifest = {
      transferId: 'healthy-long-segmented-transfer',
      name: 'segmented.bin',
      size: data.byteLength,
      digest: chunkDigest(data),
      chunkSize: data.byteLength,
      chunkCount: 1
    };
    let finalized = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => {
        finalized = true;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = new SegmentedSlowReadPipe(segmentBytes, 350);
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: data.byteLength,
      digest: chunkDigest(data)
    });
    for (let offset = 0; offset < data.byteLength; offset += segmentBytes) {
      await lane.writeAll(data.subarray(offset, offset + segmentBytes));
    }
    await lane.finish();

    const startedAt = Date.now();
    const handlingLane = manager.handleData(lane, context);
    const terminal = completeLocalReceiver(control.right, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await Promise.all([handlingLane, terminal, receiving]);

    expect(Date.now() - startedAt).toBeGreaterThan(idleTimeoutMs);
    expect(finalized).toBe(true);
  });

  it('rejects trailing lane bytes and cleans up without finalizing', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const byte = Uint8Array.of(12);
    const manifest: FileManifest = {
      ...oneByteManifest('trailing-lane-bytes'),
      digest: chunkDigest(byte)
    };
    let finalized = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => {
        finalized = true;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = new AsyncPipe();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: byte.byteLength,
      digest: chunkDigest(byte)
    });
    await lane.writeAll(byte);
    await lane.writeAll(Uint8Array.of(99));
    await lane.finish();

    await expect(manager.handleData(lane, context)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    await expect(receiving).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    const rejection = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(rejection.kind).toBe(TransferFrameKind.Reject);
    expect(rejection.value.code).toBe('INVALID_FRAME');
    expect(finalized).toBe(false);
    expect(lane.expectEndCalls).toBe(1);
    expect(lane.stopCalls).toBe(1);
    expect((control.left.send as AsyncPipe).finishCalls).toBe(1);
    expect((control.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
  });

  it('pins every sender lane to the control connection', async () => {
    const control = duplexPair();
    const laneA = new RecordingPipe();
    const laneB = new RecordingPipe();
    let opensA = 0;
    let opensB = 0;
    let contextRequests = 0;
    const baseA = testConnection(control.left, laneA);
    const baseB = testConnection(control.left, laneB);
    const connectionA: QuicConnection = { ...baseA, openUni: async () => { opensA += 1; return laneA; } };
    const connectionB: QuicConnection = { ...baseB, openUni: async () => { opensB += 1; return laneB; } };
    const contextA = testContext(connectionA, { sessionId: 'session-a' });
    const contextB = testContext(connectionB, { sessionId: 'session-b' });
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => (++contextRequests === 1 ? contextA : contextB),
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'pinned.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(9)
    }, { lanes: 1, chunkSize: 64 * 1024 });
    await control.right.recv.readExact(1);
    const offer = await readFrame<FileManifest>(control.right.recv);
    await acceptAllChunks(control.right.send, offer.value);
    const complete = await readFrame<Record<string, unknown>>(control.right.recv);
    await acknowledgeLocalSender(control.right, complete.value);
    await transfer.result;
    expect(contextRequests).toBe(1);
    expect(opensA).toBe(1);
    expect(opensB).toBe(0);
  });

  it('removes and aborts a failed session before accepting late lanes', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const manifest = oneByteManifest('late-lane-transfer');
    const cleanupStarted = deferred<void>();
    const releaseCleanup = deferred<void>();
    let writes = 0;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => { writes += 1; },
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => {
        cleanupStarted.resolve();
        await releaseCleanup.promise;
      }
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const observed = receiving.then(() => undefined, (error: unknown) => error);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    await writeFrame(control.right.send, TransferFrameKind.Complete, {
      transferId: 'different-transfer',
      attemptId: accepted.value.attemptId
    });
    await cleanupStarted.promise;

    const late = new AsyncPipe();
    await writeFrame(late, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await expect(manager.handleData(late, context)).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(late.stopCalls).toBeGreaterThan(0);
    expect(writes).toBe(0);
    releaseCleanup.resolve();
    expect(await observed).toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('makes an unconfirmed destination rollback terminal instead of retryable', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const manifest = oneByteManifest('failed-destination-rollback');
    const cleanupFailure = new Error('staging rollback rejected');
    let abortCalls = 0;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => {
        abortCalls += 1;
        throw cleanupFailure;
      }
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    await writeFrame(control.right.send, TransferFrameKind.Complete, {
      transferId: 'different-transfer',
      attemptId: accepted.value.attemptId
    });

    const error = await receiving.then(() => undefined, (cause: unknown) => cause);
    expect(error).toMatchObject({
      code: 'OUTCOME_UNKNOWN',
      cause: {
        cleanup: {
          code: 'INTERNAL',
          cause: cleanupFailure
        }
      }
    });
    expect(abortCalls).toBe(1);
  });

  it('drains delayed lane writes before aborting a custom destination', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const byte = Uint8Array.of(7);
    const manifest: FileManifest = {
      ...oneByteManifest('drain-lane-before-abort'),
      digest: chunkDigest(byte)
    };
    const writeStarted = deferred<void>();
    const writeAborted = deferred<void>();
    const releaseWrite = deferred<void>();
    const events: string[] = [];
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async (_manifest, _index, _data, signal) => {
        events.push('write-started');
        writeStarted.resolve();
        await new Promise<void>((resolve) => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener('abort', () => resolve(), { once: true });
        });
        events.push('write-aborted');
        writeAborted.resolve();
        await releaseWrite.promise;
        events.push('write-finished');
      },
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => { events.push('abort'); }
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    let receivingSettled = false;
    const observed = receiving.then(
      () => { receivingSettled = true; return undefined; },
      (error: unknown) => { receivingSettled = true; return error; }
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    const lane = new AsyncPipe();
    await writeFrame(lane, TransferFrameKind.Accept, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId,
      laneToken: accepted.value.laneToken,
      laneId: 0,
      count: 1
    });
    await writeFrame(lane, TransferFrameKind.ChunkHeader, {
      index: 0,
      size: byte.byteLength,
      digest: chunkDigest(byte)
    });
    await lane.writeAll(byte);
    const handlingLane = manager.handleData(lane, context);
    await writeStarted.promise;

    await writeFrame(control.right.send, TransferFrameKind.Complete, {
      transferId: 'different-transfer',
      attemptId: accepted.value.attemptId
    });
    await writeAborted.promise;
    expect(lane.stopCalls).toBeGreaterThan(0);
    expect(receivingSettled).toBe(false);
    expect(events).toEqual(['write-started', 'write-aborted']);

    releaseWrite.resolve();
    await expect(handlingLane).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    expect(await observed).toMatchObject({ code: 'INVALID_FRAME' });
    expect(events).toEqual(['write-started', 'write-aborted', 'write-finished', 'abort']);
  });

  it('waits for an aborted finalizer to settle and never publishes after timeout', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      idleTimeoutMs: 1_000
    });
    const manifest: FileManifest = {
      transferId: 'late-finalizer',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    const finalizeStarted = deferred<void>();
    const finalizeAborted = deferred<void>();
    const releaseFinalize = deferred<void>();
    let published = false;
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => {
        const { signal } = context;
        finalizeStarted.resolve();
        await new Promise<void>((resolve) => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener('abort', () => resolve(), { once: true });
        });
        finalizeAborted.resolve();
        await releaseFinalize.promise;
        if (signal?.aborted) throw signal.reason;
        published = true;
        context.markCommitted();
      },
      abort: async () => undefined
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receiving = privateReceive(manager, context)(
      control.left,
      manifest,
      destination,
      undefined,
      new AbortController().signal
    );
    let settled = false;
    const observed = receiving.then(
      () => { settled = true; return undefined; },
      (error: unknown) => { settled = true; return error; }
    );
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    await writeFrame(control.right.send, TransferFrameKind.Complete, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await control.right.send.finish();
    await finalizeStarted.promise;
    await finalizeAborted.promise;
    expect(settled).toBe(false);
    expect(published).toBe(false);
    releaseFinalize.resolve();
    expect(await observed).toMatchObject({ code: 'TIMEOUT' });
    expect(published).toBe(false);
  });

  it('makes built-in filesystem operations cooperative and prevents pre-aborted publication', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-abort-fs-'));
    temporary.push(directory);
    const input = join(directory, 'input.bin');
    const output = join(directory, 'output.bin');
    await writeFile(input, 'secure');
    const source = await fileSource(input);
    const manifest = await createManifest(source, { chunkSize: 64 * 1024 });
    const controller = new AbortController();
    controller.abort(new P2PError('UNAUTHORIZED', 'Session revoked'));
    await expect(source.readChunk(0, manifest.chunkSize, controller.signal))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const neverPrepared = fileDestination(output);
    await expect(neverPrepared.prepare(manifest, controller.signal))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(lstat(`${output}.p2prpc.lock`)).rejects.toMatchObject({ code: 'ENOENT' });

    const racedOutput = join(directory, 'raced-output.bin');
    const racedDestination = fileDestination(racedOutput);
    const racedController = new AbortController();
    const preparing = racedDestination.prepare(manifest, racedController.signal);
    queueMicrotask(() => racedController.abort());
    await expect(preparing).rejects.toMatchObject({ code: 'CANCELLED' });
    await expect(lstat(`${racedOutput}.p2prpc.lock`)).rejects.toMatchObject({ code: 'ENOENT' });

    const destination = fileDestination(output);
    await destination.prepare(manifest);
    await expect(destination.writeChunk(
      manifest,
      0,
      await source.readChunk(0, manifest.chunkSize),
      controller.signal
    )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await destination.writeChunk(manifest, 0, await source.readChunk(0, manifest.chunkSize));
    await expect(destination.finalize(manifest, finalizeContext(controller.signal)))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    await expect(lstat(output)).rejects.toMatchObject({ code: 'ENOENT' });
    await destination.abort(manifest, { discard: true });
  });

  it('keeps the 4 MiB destination default while allowing an explicit larger node chunk limit', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'p2prpc-destination-limit-'));
    temporary.push(directory);
    const manifest: FileManifest = {
      transferId: 'large-configured-chunk',
      name: 'empty.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 8 * 1024 * 1024,
      chunkCount: 0
    };
    const defaultDestination = fileDestination(join(directory, 'default.bin'));
    await expect(defaultDestination.prepare(manifest)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });

    const configuredDestination = fileDestination(join(directory, 'configured.bin'), {
      maxChunkSize: 8 * 1024 * 1024
    });
    await expect(configuredDestination.prepare(manifest)).resolves.toEqual(new Set());
    await configuredDestination.abort(manifest, { discard: true });
  });

  it('sanitizes and bounds untrusted remote rejection reasons', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new RecordingPipe()));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => context,
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'rejected.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
    await control.right.recv.readExact(1);
    await readFrame(control.right.recv);
    await writeFrame(control.right.send, TransferFrameKind.Reject, {
      code: 'REJECTED',
      reason: `Denied\n\u001b\u0085\u202e${'x'.repeat(300)}`
    });
    const error = await transfer.result.then(() => undefined, (cause: unknown) => cause);
    expect(error).toMatchObject({ code: 'REJECTED' });
    const message = (error as Error).message;
    expect(message).toContain('Denied????');
    expect([...message].some((character) => {
      const code = character.codePointAt(0)!;
      return code <= 0x1f || (code >= 0x7f && code <= 0x9f) || (code >= 0x2028 && code <= 0x202e);
    })).toBe(false);
    expect(Buffer.byteLength(message)).toBeLessThanOrEqual(256);
  });

  it('preserves an authenticated receiver OUTCOME_UNKNOWN decision', async () => {
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new RecordingPipe()));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => context,
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const transfer = await manager.sendFile({
      name: 'unknown.bin',
      size: 0,
      readChunk: async () => new Uint8Array()
    });
    await control.right.recv.readExact(1);
    await readFrame(control.right.recv);
    await writeFrame(control.right.send, TransferFrameKind.Reject, {
      code: 'OUTCOME_UNKNOWN',
      reason: 'Transfer outcome is indeterminate'
    });
    await expect(transfer.result).rejects.toMatchObject({ code: 'OUTCOME_UNKNOWN' });
  });

  it('retries an initial pull with the same hidden operation ID', async () => {
    const first = duplexPair();
    const second = duplexPair();
    const contexts = [
      testContext(testConnection(first.left, new AsyncPipe()), { sessionId: 'session-a' }),
      testContext(testConnection(second.left, new AsyncPipe()), { sessionId: 'session-b' })
    ];
    let connectionIndex = 0;
    const requestIds: string[] = [];
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => contexts[Math.min(connectionIndex++, contexts.length - 1)]!,
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const firstRemote = (async () => {
      await first.right.recv.readExact(1);
      const pull = await readFrame<Record<string, unknown>>(first.right.recv);
      requestIds.push(pull.value.requestId as string);
      await first.right.send.finish();
    })();
    const secondRemote = (async () => {
      await second.right.recv.readExact(1);
      const pull = await readFrame<Record<string, unknown>>(second.right.recv);
      const requestId = pull.value.requestId as string;
      requestIds.push(requestId);
      await writeFrame(second.right.send, TransferFrameKind.Offer, {
        transferId: requestId,
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 64 * 1024,
        chunkCount: 0
      });
      const accepted = await readFrame<Record<string, unknown>>(second.right.recv);
      await completeLocalReceiver(second.right, {
        transferId: requestId,
        attemptId: accepted.value.attemptId
      });
    })();
    let finalized = false;
    const transfer = await manager.download('a'.repeat(43), {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => {
        finalized = true;
        context.markCommitted();
      },
      abort: async () => undefined
    }, { chunkSize: 64 * 1024, lanes: 1 });
    await transfer.result;
    await Promise.all([firstRemote, secondRemote]);
    expect(requestIds).toHaveLength(2);
    expect(requestIds[0]).toBe(requestIds[1]);
    expect(finalized).toBe(true);
  });

  it('rejects changed metadata when a download reconnects', async () => {
    const first = duplexPair();
    const second = duplexPair();
    const contexts = [
      testContext(testConnection(first.left, new AsyncPipe()), { sessionId: 'session-a' }),
      testContext(testConnection(second.left, new AsyncPipe()), { sessionId: 'session-b' })
    ];
    let connectionIndex = 0;
    const manager = new TransferManager<{ classification: string }>({
      peerId: 'peer-a',
      connection: async () => contexts[Math.min(connectionIndex++, contexts.length - 1)]!,
      shares: new ShareRegistry(),
      authorize: () => undefined,
      metadataSchema: passthroughMetadataSchema<{ classification: string }>()
    });
    const firstRemote = (async () => {
      await first.right.recv.readExact(1);
      const pull = await readFrame<Record<string, unknown>>(first.right.recv);
      const requestId = pull.value.requestId as string;
      await writeFrame(first.right.send, TransferFrameKind.Offer, {
        transferId: requestId,
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 64 * 1024,
        chunkCount: 0,
        metadata: { classification: 'internal' }
      });
      await readFrame(first.right.recv);
      await first.right.send.finish();
    })();
    const secondRemote = (async () => {
      await second.right.recv.readExact(1);
      const pull = await readFrame<Record<string, unknown>>(second.right.recv);
      const requestId = pull.value.requestId as string;
      await writeFrame(second.right.send, TransferFrameKind.Offer, {
        transferId: requestId,
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 64 * 1024,
        chunkCount: 0,
        metadata: { classification: 'public' }
      });
    })();
    const transfer = await manager.download('a'.repeat(43), {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async (_manifest, context) => { context.markCommitted(); },
      abort: async () => undefined
    }, { chunkSize: 64 * 1024, lanes: 1 });
    await expect(transfer.result).rejects.toMatchObject({ code: 'INTEGRITY_FAILED' });
    await Promise.all([firstRemote, secondRemote]);
    expect((second.left.send as AsyncPipe).resetCalls).toBeGreaterThan(0);
    expect((second.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);
  });

  it('aborts connection-bound hashing and permits only the same bounded operation to reconnect', async () => {
    const firstReadStarted = deferred<void>();
    let reads = 0;
    const source = {
      name: 'reconnect.bin',
      size: 1,
      async readChunk(_index: number, _chunkSize: number, signal?: AbortSignal): Promise<Uint8Array> {
        reads += 1;
        if (reads === 1) {
          firstReadStarted.resolve();
          await new Promise<void>((_resolve, reject) => {
            if (signal?.aborted) reject(signal.reason);
            else signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
          });
        }
        return Uint8Array.of(4);
      }
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares,
      authorize: () => undefined
    });
    const first = duplexPair();
    const firstController = new AbortController();
    const firstContext = testContext(testConnection(first.left, new RecordingPipe()), {
      sessionId: 'session-a',
      signal: firstController.signal
    });
    await writePull(first.right.send, handle.token, 'stable-operation');
    const firstHandling = manager.handleControl(first.left, firstContext);
    await firstReadStarted.promise;
    firstController.abort(new P2PError('DISCONNECTED', 'Physical connection replaced'));
    await expect(firstHandling).rejects.toMatchObject({ code: 'DISCONNECTED' });

    const second = duplexPair();
    const secondContext = testContext(testConnection(second.left, new RecordingPipe()), { sessionId: 'session-b' });
    const secondHandling = manager.handleControl(second.left, secondContext);
    await acknowledgeOneChunkPull(second.right, handle.token, 'stable-operation');
    await secondHandling;
    expect(reads).toBeGreaterThanOrEqual(3);
  });

  it('cancels queued file controls when their authenticated session aborts', async () => {
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined,
      limits: { maxTransfers: 1, maxQueuedTransfers: 1 }
    });
    const first = duplexPair();
    const firstController = new AbortController();
    const firstContext = testContext(testConnection(first.left, new AsyncPipe()), { signal: firstController.signal });
    const firstHandling = manager.handleControl(first.left, firstContext);
    await (first.left.recv as AsyncPipe).waitingForBytes;

    const second = duplexPair();
    const secondController = new AbortController();
    const secondContext = testContext(testConnection(second.left, new AsyncPipe()), { signal: secondController.signal });
    const secondHandling = manager.handleControl(second.left, secondContext);
    secondController.abort(new P2PError('UNAUTHORIZED', 'Session expired'));
    await expect(secondHandling).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect((second.left.recv as AsyncPipe).stopCalls).toBeGreaterThan(0);

    firstController.abort(new P2PError('DISCONNECTED', 'Test complete'));
    await expect(firstHandling).rejects.toMatchObject({ code: 'DISCONNECTED' });
  });

  it('actively aborts an in-flight capability reservation when revoked', async () => {
    const readStarted = deferred<void>();
    let observedAbort: unknown;
    const source = {
      name: 'revoked.bin',
      size: 1,
      async readChunk(_index: number, _chunkSize: number, signal?: AbortSignal): Promise<Uint8Array> {
        readStarted.resolve();
        await new Promise<void>((_resolve, reject) => {
          if (signal?.aborted) reject(signal.reason);
          else signal?.addEventListener('abort', () => reject(signal.reason), { once: true });
        }).catch((cause: unknown) => {
          observedAbort = cause;
          throw cause;
        });
        return Uint8Array.of(1);
      }
    };
    const shares = new ShareRegistry();
    const handle = shares.shareForPeer(source, 'peer-a');
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new RecordingPipe()));
    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => context,
      shares,
      authorize: () => undefined
    });
    await writePull(control.right.send, handle.token, 'revoked-request');
    const handling = manager.handleControl(control.left, context);
    await readStarted.promise;
    expect(shares.revoke(handle)).toBe(true);
    await expect(handling).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(observedAbort).toMatchObject({ code: 'UNAUTHORIZED' });
    expect(() => shares.reserve(handle.token, {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v3:65536:1',
      operationId: 'revoked-request'
    })).toThrow(/invalid or unavailable/);
  });

  it('defensively snapshots and freezes manifest metadata', () => {
    const raw = { label: 'private', nested: { level: 3 }, binary: Uint8Array.of(1, 2, 3) };
    const manifest = validateManifest<typeof raw>({
      transferId: 'immutable-metadata',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0,
      metadata: raw
    }, DEFAULT_FILE_TRANSFER_LIMITS);
    raw.label = 'mutated';
    raw.nested.level = 99;
    raw.binary[0] = 9;
    const first = manifest.metadata!;
    expect(first).toMatchObject({ label: 'private', nested: { level: 3 } });
    expect([...first.binary]).toEqual([1, 2, 3]);
    expect(Object.isFrozen(manifest)).toBe(true);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.nested)).toBe(true);
    first.binary[0] = 8;
    expect([...(manifest.metadata?.binary ?? [])]).toEqual([1, 2, 3]);
  });

  it('rejects accessor, prototype-confusing, and exotic file metadata without evaluating it', () => {
    let getterCalls = 0;
    const accessor = Object.defineProperty({}, 'secret', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'must-not-run';
      }
    });
    const hidden = {};
    Object.defineProperty(hidden, 'secret', { value: 'hidden' });
    const symbol = { [Symbol('hidden')]: true };
    const extraArray = [1] as number[] & { extra?: number };
    extraArray.extra = 2;
    const inheritedBytes = new (class extends Uint8Array {})([1]);
    const byteAccessor = Object.defineProperty(Uint8Array.of(1), 'byteLength', {
      get() {
        getterCalls += 1;
        return 1;
      }
    });

    for (const value of [
      accessor,
      hidden,
      symbol,
      extraArray,
      inheritedBytes,
      byteAccessor,
      -0,
      Object.assign(Object.create(null), { constructor: 'confusing' })
    ]) {
      expect(() => cloneValidatedMetadata(value, 64 * 1024))
        .toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    }
    expect(getterCalls).toBe(0);
  });

  it('copies Buffer metadata instead of retaining its shared backing storage', () => {
    const source = Buffer.from([1, 2, 3]);
    const snapshot = cloneValidatedMetadata(source, 64 * 1024) as Uint8Array;
    source[0] = 9;
    expect([...snapshot]).toEqual([1, 2, 3]);
    expect(snapshot.buffer).not.toBe(source.buffer);
  });

  it('materializes accessor-free manifest wire data from the private metadata snapshot', async () => {
    const source = Buffer.from([1, 2, 3]);
    const manifest = validateManifest({
      transferId: 'wire-metadata',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0,
      metadata: { source }
    }, DEFAULT_FILE_TRANSFER_LIMITS);
    source[0] = 9;
    const wire = manifestWireValue(manifest);
    expect(Object.getOwnPropertyDescriptor(wire, 'metadata')).toHaveProperty('value');
    const metadata = wire.metadata as { source: Uint8Array };
    expect([...metadata.source]).toEqual([1, 2, 3]);

    const pipe = new RecordingPipe();
    await expect(writeFrame(pipe, TransferFrameKind.Offer, wire)).resolves.toBeUndefined();
  });

  it('rejects manifest accessors and exotic prototypes before reading fields', () => {
    let getterCalls = 0;
    const base = {
      transferId: 'safe-manifest',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0
    };
    const accessor = Object.defineProperty({ ...base }, 'name', {
      enumerable: true,
      get() {
        getterCalls += 1;
        return 'file.bin';
      }
    });
    const inherited = Object.assign(Object.create(base), {});
    expect(() => validateManifest(accessor, DEFAULT_FILE_TRANSFER_LIMITS))
      .toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(() => validateManifest(inherited, DEFAULT_FILE_TRANSFER_LIMITS))
      .toThrowError(expect.objectContaining({ code: 'INVALID_FRAME' }));
    expect(getterCalls).toBe(0);
  });

  it('rejects unknown file manifest and control fields', async () => {
    expect(() => validateManifest({
      transferId: 'unknown-manifest-field',
      name: 'file.bin',
      size: 0,
      digest: '0'.repeat(64),
      chunkSize: 64 * 1024,
      chunkCount: 0,
      privilege: 'admin'
    }, DEFAULT_FILE_TRANSFER_LIMITS)).toThrow(/unknown field/);

    const manager = new TransferManager({
      peerId: 'peer-a',
      connection: async () => { throw new Error('unused'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    const control = duplexPair();
    await writeFrame(control.right.send, TransferFrameKind.Pull, {
      token: 'a'.repeat(43),
      requestId: 'unknown-pull-field',
      options: { chunkSize: 64 * 1024, lanes: 1 },
      allowBearer: true
    });
    await expect(manager.handleControl(
      control.left,
      testContext(testConnection(control.left, new AsyncPipe()))
    )).rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('requires a runtime schema whenever metadata is transferred', async () => {
    const manager = new TransferManager<{ classification: string }>({
      peerId: 'peer-a',
      connection: async () => { throw new Error('must reject before connecting'); },
      shares: new ShareRegistry(),
      authorize: () => undefined
    });
    await expect(manager.sendFile({
      name: 'metadata.bin',
      size: 0,
      metadata: { classification: 'private' },
      readChunk: async () => new Uint8Array()
    })).rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('enforces a configured maximum peer chunk allocation', () => {
    expect(() => validateManifest({
      transferId: 'oversized-chunk',
      name: 'file.bin',
      size: 128 * 1024,
      digest: '0'.repeat(64),
      chunkSize: 128 * 1024,
      chunkCount: 1
    }, { ...DEFAULT_FILE_TRANSFER_LIMITS, maxChunkSize: 64 * 1024 })).toThrow(/Chunk size/);
  });
});

class RecordingPipe implements QuicSendStream, QuicRecvStream {
  readonly readSizes: number[] = [];
  finishCalls = 0;
  expectEndCalls = 0;
  resetCalls = 0;
  stopCalls = 0;
  private bytes: number[] = [];
  private ended = false;

  async writeAll(data: Uint8Array): Promise<void> { this.bytes.push(...data); }
  async readExact(size: number): Promise<Uint8Array> {
    this.readSizes.push(size);
    if (this.bytes.length < size) throw new Error('EOF');
    return Uint8Array.from(this.bytes.splice(0, size));
  }
  async finish(): Promise<void> { this.finishCalls += 1; this.ended = true; }
  async expectEnd(): Promise<void> {
    this.expectEndCalls += 1;
    if (!this.ended || this.bytes.length !== 0) throw new P2PError('INVALID_FRAME', 'Expected clean EOF');
  }
  async reset(): Promise<void> { this.resetCalls += 1; this.ended = true; }
  async setPriority(): Promise<void> {}
  async stop(): Promise<void> { this.stopCalls += 1; this.ended = true; }
}

class SegmentedSlowReadPipe extends RecordingPipe {
  constructor(
    private readonly segmentBytes: number,
    private readonly delayMs: number
  ) {
    super();
  }

  override async readExact(size: number): Promise<Uint8Array> {
    if (size === this.segmentBytes) await new Promise<void>((resolve) => setTimeout(resolve, this.delayMs));
    return super.readExact(size);
  }
}

function duplexPair(): { left: QuicBiStream; right: QuicBiStream } {
  const leftToRight = new AsyncPipe();
  const rightToLeft = new AsyncPipe();
  return {
    left: { send: leftToRight, recv: rightToLeft },
    right: { send: rightToLeft, recv: leftToRight }
  };
}

class AsyncPipe implements QuicSendStream, QuicRecvStream {
  finishCalls = 0;
  expectEndCalls = 0;
  resetCalls = 0;
  stopCalls = 0;
  readonly waitingForBytes: Promise<void>;
  private bytes: number[] = [];
  private waiters: Array<() => void> = [];
  private ended = false;
  private signalWaitingForBytes!: () => void;

  constructor() {
    this.waitingForBytes = new Promise<void>((resolve) => { this.signalWaitingForBytes = resolve; });
  }

  async writeAll(data: Uint8Array): Promise<void> {
    this.bytes.push(...data);
    for (const waiter of this.waiters.splice(0)) waiter();
  }

  async readExact(size: number): Promise<Uint8Array> {
    while (this.bytes.length < size) {
      if (this.ended) throw new Error('EOF');
      this.signalWaitingForBytes();
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    return Uint8Array.from(this.bytes.splice(0, size));
  }

  async finish(): Promise<void> {
    this.finishCalls += 1;
    this.ended = true;
    for (const waiter of this.waiters.splice(0)) waiter();
  }
  async expectEnd(): Promise<void> {
    this.expectEndCalls += 1;
    while (!this.ended && this.bytes.length === 0) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    if (!this.ended || this.bytes.length !== 0) throw new P2PError('INVALID_FRAME', 'Expected clean EOF');
  }
  async reset(): Promise<void> {
    this.resetCalls += 1;
    await this.finish();
  }
  async setPriority(): Promise<void> {}
  async stop(): Promise<void> {
    this.stopCalls += 1;
    await this.finish();
  }
}

class FinishFailingSend implements QuicSendStream {
  constructor(private readonly delegate: QuicSendStream) {}

  writeAll(data: Uint8Array): Promise<void> { return this.delegate.writeAll(data); }
  async finish(): Promise<void> { throw new Error('finish disconnected'); }
  reset(code: bigint): Promise<void> { return this.delegate.reset(code); }
  setPriority(priority: number): Promise<void> { return this.delegate.setPriority(priority); }
}

class CleanupRejectingPipe extends AsyncPipe {
  override async reset(): Promise<void> {
    await super.reset();
    throw new Error('reset rejected after cleanup');
  }

  override async stop(): Promise<void> {
    await super.stop();
    throw new Error('stop rejected after cleanup');
  }
}

class StalledSendStream implements QuicSendStream {
  readonly started: Promise<void>;
  resetCalls = 0;
  private signalStarted!: () => void;
  private releaseWrite?: () => void;

  constructor() {
    this.started = new Promise<void>((resolve) => { this.signalStarted = resolve; });
  }

  async writeAll(): Promise<void> {
    this.signalStarted();
    await new Promise<void>((resolve) => { this.releaseWrite = resolve; });
  }

  async finish(): Promise<void> {}

  async reset(): Promise<void> {
    this.resetCalls += 1;
    this.releaseWrite?.();
  }

  async setPriority(): Promise<void> {}
}

class ResetRejectingSendStream extends StalledSendStream {
  override async reset(): Promise<void> {
    await super.reset();
    throw new Error('reset rejected');
  }
}

class StopStalledRecvStream extends AsyncPipe {
  override async stop(): Promise<void> {
    this.stopCalls += 1;
    await new Promise<void>(() => undefined);
  }
}

class RejectingSendStream implements QuicSendStream {
  readonly writeAttempted: Promise<void>;
  resetCalls = 0;
  private signalWriteAttempted!: () => void;

  constructor() {
    this.writeAttempted = new Promise<void>((resolve) => { this.signalWriteAttempted = resolve; });
  }

  async writeAll(): Promise<void> {
    this.signalWriteAttempted();
    throw new Error('body reader dropped');
  }

  async finish(): Promise<void> {}
  async reset(): Promise<void> { this.resetCalls += 1; }
  async setPriority(): Promise<void> {}
}

class FinishStalledSendStream implements QuicSendStream {
  readonly finishStarted: Promise<void>;
  resetCalls = 0;
  private signalFinishStarted!: () => void;
  private releaseFinish?: () => void;

  constructor() {
    this.finishStarted = new Promise<void>((resolve) => { this.signalFinishStarted = resolve; });
  }

  async writeAll(): Promise<void> {}

  async finish(): Promise<void> {
    this.signalFinishStarted();
    await new Promise<void>((resolve) => { this.releaseFinish = resolve; });
  }

  async reset(): Promise<void> {
    this.resetCalls += 1;
    this.releaseFinish?.();
  }

  async setPriority(): Promise<void> {}
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function shareReservationRequest(operationId: string) {
  return {
    peerId: 'peer-a',
    principalId: 'principal-a',
    subject: 'subject-a',
    fingerprint: `v${PROTOCOL_VERSION}:65536:1`,
    operationId
  };
}

function progressFor(manifest: FileManifest, completedChunks: number): TransferProgress {
  return {
    transferId: manifest.transferId,
    direction: 'receive',
    transferredBytes: Math.min(manifest.size, completedChunks),
    totalBytes: manifest.size,
    completedChunks,
    totalChunks: manifest.chunkCount
  };
}

function passthroughMetadataSchema<T>(): FileMetadataSchema<T> {
  return {
    '~standard': {
      version: 1,
      vendor: 'p2prpc-test',
      validate: (value) => ({ value: value as T })
    }
  };
}

function testConnection(control: QuicBiStream, data: QuicSendStream): QuicConnection {
  return {
    remoteId: 'peer-a',
    side: 'client',
    openBi: async () => control,
    acceptBi: async () => { throw new Error('unused'); },
    openUni: async () => data,
    acceptUni: async () => { throw new Error('unused'); },
    closed: async () => 'closed',
    close: () => undefined,
    stats: async () => testConnectionStats()
  };
}

function recordConnectionClose(connection: QuicConnection): {
  readonly connection: QuicConnection;
  readonly calls: Array<{ readonly code: bigint; readonly reason: string }>;
  readonly firstClose: Promise<{ readonly code: bigint; readonly reason: string }>;
} {
  const calls: Array<{ readonly code: bigint; readonly reason: string }> = [];
  const firstClose = deferred<{ readonly code: bigint; readonly reason: string }>();
  return {
    connection: {
      ...connection,
      close: (code, reason) => {
        const call = Object.freeze({ code, reason: new TextDecoder().decode(reason) });
        calls.push(call);
        firstClose.resolve(call);
      }
    },
    calls,
    firstClose: firstClose.promise
  };
}

function testConnectionStats(): ConnectionStats {
  return {
    connectionId: 'test-connection',
    rttMs: 0,
    sentBytes: 0,
    receivedBytes: 0,
    lostPackets: 0,
    sentPackets: 0,
    congestionWindow: null,
    relay: null,
    relayUrl: null,
    paths: [],
    streams: {
      openedBi: 0,
      acceptedBi: 0,
      openedUni: 0,
      acceptedUni: 0,
      activeSend: 0,
      activeRecv: 0,
      sendFinished: 0,
      sendReset: 0,
      recvEof: 0,
      recvStopped: 0
    }
  };
}

async function writePull(send: QuicSendStream, token: string, requestId: string): Promise<void> {
  await writeFrame(send, TransferFrameKind.Pull, {
    token,
    requestId,
    options: { chunkSize: 64 * 1024, lanes: 1 }
  });
}

async function acknowledgeLocalSender(
  remote: QuicBiStream,
  completion: Record<string, unknown>
): Promise<void> {
  const acknowledgement = { ...completion, receiptToken: 'c'.repeat(43) };
  await writeFrame(remote.send, TransferFrameKind.Complete, acknowledgement);
  const receipt = await readFrame<Record<string, unknown>>(remote.recv);
  expect(receipt).toEqual({ kind: TransferFrameKind.Receipt, value: acknowledgement });
  await remote.recv.expectEnd();
  await remote.send.finish();
}

async function completeLocalReceiver(
  remote: QuicBiStream,
  completion: Record<string, unknown>
): Promise<void> {
  await writeFrame(remote.send, TransferFrameKind.Complete, completion);
  const acknowledgement = await readFrame<Record<string, unknown>>(remote.recv);
  expect(acknowledgement.kind).toBe(TransferFrameKind.Complete);
  await writeFrame(remote.send, TransferFrameKind.Receipt, acknowledgement.value);
  await remote.send.finish();
  await remote.recv.expectEnd();
}

async function acknowledgeEmptyPull(remote: QuicBiStream, token: string, requestId: string): Promise<void> {
  await writePull(remote.send, token, requestId);
  const offer = await readFrame<FileManifest>(remote.recv);
  expect(offer.kind).toBe(TransferFrameKind.Offer);
  await writeFrame(remote.send, TransferFrameKind.Accept, {
    transferId: requestId,
    attemptId: 'a'.repeat(22),
    laneToken: 'b'.repeat(43),
    missingRanges: [],
    missingCount: 0,
    lanes: 1
  });
  const complete = await readFrame<Record<string, unknown>>(remote.recv);
  expect(complete.kind).toBe(TransferFrameKind.Complete);
  await acknowledgeLocalSender(remote, complete.value);
}

async function acknowledgeOneChunkPull(remote: QuicBiStream, token: string, requestId: string): Promise<void> {
  await writePull(remote.send, token, requestId);
  const offer = await readFrame<FileManifest>(remote.recv);
  expect(offer.kind).toBe(TransferFrameKind.Offer);
  await writeFrame(remote.send, TransferFrameKind.Accept, {
    transferId: requestId,
    attemptId: 'a'.repeat(22),
    laneToken: 'b'.repeat(43),
    missingRanges: [[0, 1]],
    missingCount: 1,
    lanes: 1
  });
  const complete = await readFrame<Record<string, unknown>>(remote.recv);
  expect(complete.kind).toBe(TransferFrameKind.Complete);
  await acknowledgeLocalSender(remote, complete.value);
}

async function acceptAllChunks(send: QuicSendStream, manifest: FileManifest): Promise<void> {
  await writeFrame(send, TransferFrameKind.Accept, {
    transferId: manifest.transferId,
    attemptId: 'a'.repeat(22),
    laneToken: 'b'.repeat(43),
    missingRanges: [[0, manifest.chunkCount]],
    missingCount: manifest.chunkCount,
    lanes: 1
  });
}

function oneByteManifest(transferId: string): FileManifest {
  return {
    transferId,
    name: 'one-byte.bin',
    size: 1,
    digest: '0'.repeat(64),
    chunkSize: 64 * 1024,
    chunkCount: 1
  };
}

function privateReceive(manager: TransferManager, context: FileTransferConnectionContext) {
  const receive = (manager as unknown as {
    receiveAttempt(
      stream: QuicBiStream,
      manifest: FileManifest,
      destination: FileDestination,
      transfer: undefined,
      context: FileTransferConnectionContext,
      attempt: unknown
    ): Promise<
      | { readonly kind: 'success'; readonly value: unknown }
      | { readonly kind: 'retryable-transport-loss' | 'terminal-failure'; readonly error: P2PError }
    >;
  }).receiveAttempt.bind(manager);
  return async (
    stream: QuicBiStream,
    manifest: FileManifest,
    destination: FileDestination,
    transfer: undefined,
    signal: AbortSignal
  ): Promise<unknown> => {
    const internals = manager as unknown as {
      retryFiles<TResult>(
        operationSignal: AbortSignal,
        operation: (attempt: unknown) => Promise<
          | { readonly kind: 'success'; readonly value: TResult }
          | { readonly kind: 'retryable-transport-loss' | 'terminal-failure'; readonly error: P2PError }
        >
      ): Promise<TResult>;
    };
    return internals.retryFiles(signal, (attempt) => {
      const bindable = attempt as { bindConnectionSignal(connectionSignal: AbortSignal): void };
      bindable.bindConnectionSignal(context.signal);
      return receive(stream, manifest, destination, transfer, context, attempt);
    });
  };
}

async function stalledLane(manifest: FileManifest, acceptance: Record<string, unknown>): Promise<AsyncPipe> {
  const lane = new AsyncPipe();
  await writeFrame(lane, TransferFrameKind.Accept, {
    transferId: manifest.transferId,
    attemptId: acceptance.attemptId,
    laneToken: acceptance.laneToken,
    laneId: 0,
    count: 1
  });
  await writeFrame(lane, TransferFrameKind.ChunkHeader, {
    index: 0,
    size: 1,
    digest: '0'.repeat(64)
  });
  return lane;
}

async function completedChunkLane(
  manifest: FileManifest,
  acceptance: Record<string, unknown>,
  laneId: number,
  index: number,
  data: Uint8Array
): Promise<AsyncPipe> {
  const lane = new AsyncPipe();
  await writeFrame(lane, TransferFrameKind.Accept, {
    transferId: manifest.transferId,
    attemptId: acceptance.attemptId,
    laneToken: acceptance.laneToken,
    laneId,
    count: 1
  });
  await writeFrame(lane, TransferFrameKind.ChunkHeader, {
    index,
    size: data.byteLength,
    digest: chunkDigest(data)
  });
  await lane.writeAll(data);
  await lane.finish();
  return lane;
}

function testContext(
  connection: QuicConnection,
  overrides: { readonly sessionId?: string; readonly signal?: AbortSignal } = {}
): FileTransferConnectionContext {
  return Object.freeze({
    connection,
    security: Object.freeze({
      sessionId: overrides.sessionId ?? 'test-session',
      principal: Object.freeze({
      id: 'principal-a',
      subject: 'subject-a',
      expiresAt: Date.now() + 60_000,
      scopes: new Set(['p2prpc:*']),
      claims: {}
      })
    }),
    signal: overrides.signal ?? new AbortController().signal
  });
}

function finalizeContext(signal?: AbortSignal): FileDestinationFinalizeContext {
  return Object.freeze({
    ...(signal === undefined ? {} : { signal }),
    markCommitted: () => undefined
  });
}
