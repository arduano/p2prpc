import { lstat, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, describe, expect, it } from 'vitest';
import { chunkDigest, createManifest, fileDestination, fileSource } from '../src/files/fs.js';
import { TransferManager, type FileTransferConnectionContext } from '../src/files/manager.js';
import { ShareRegistry } from '../src/files/share.js';
import { Transfer } from '../src/files/transfer.js';
import type { FileDestination, FileManifest } from '../src/files/types.js';
import { TransferFrameKind, readFrame, writeFrame } from '../src/protocol.js';
import type { QuicBiStream, QuicConnection, QuicRecvStream, QuicSendStream } from '../src/transport/types.js';
import { DEFAULT_FILE_TRANSFER_LIMITS, validateManifest } from '../src/files/validation.js';
import { P2PError } from '../src/errors.js';

const temporary: string[] = [];
afterEach(async () => Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true }))));

describe('filesystem transfers', () => {
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
    await destination.finalize(manifest);
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

    const resumed = fileDestination(output);
    expect(await resumed.prepare(manifest)).toEqual(new Set([0]));
    for (let index = 1; index < manifest.chunkCount; index += 1) {
      await resumed.writeChunk(manifest, index, await source.readChunk(index, manifest.chunkSize));
    }
    await resumed.finalize(manifest);
    expect(await readFile(output)).toEqual(bytes);
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
    await destination.finalize(manifest);
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
      fingerprint: 'v2:65536:1',
      operationId
    });
    expect(() => registry.share(source, {} as never)).toThrow(/peer-bound/);
    const handle = registry.shareForPeer(source, 'peer-a');
    expect(handle.expiresAt).toBe(1_100);
    const entries = (registry as unknown as { entries: Map<string, unknown> }).entries;
    expect(entries.has(handle.token)).toBe(false);
    expect(() => registry.reserve(handle.token, request('peer-b', 'request-a'))).toThrow(/invalid or unavailable/);
    const initial = registry.reserve(handle.token, request('peer-a', 'request-a'));
    expect(initial.source).toBe(source);
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-b'))).toThrow(/invalid or unavailable/);
    initial.release();
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a', 'subject-a', 'principal-b')))
      .toThrow(/invalid or unavailable/);
    expect(() => registry.reserve(handle.token, { ...request('peer-a', 'request-a'), fingerprint: 'v2:131072:1' }))
      .toThrow(/invalid or unavailable/);
    const resumed = registry.reserve(handle.token, request('peer-a', 'request-a'));
    resumed.complete();
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);
    now = 1_101;
    expect(() => registry.reserve(handle.token, request('peer-a', 'request-a'))).toThrow(/invalid or unavailable/);

    const bearer = registry.share(source, { allowBearer: true });
    expect(registry.reserve(bearer.token, request('any-peer', 'request-c')).source).toBe(source);

    const subjectBound = registry.share(source, { allowedPeerIds: ['peer-a'], allowedSubjects: ['subject-a'] });
    expect(() => registry.reserve(subjectBound.token, request('peer-a', 'request-d', 'subject-b')))
      .toThrow(/invalid or unavailable/);
    expect(registry.reserve(subjectBound.token, request('peer-a', 'request-d')).source).toBe(source);
    expect(() => registry.reserve(subjectBound.token, request('peer-a', 'request-d', 'subject-b')))
      .toThrow(/invalid or unavailable/);

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
      { allowBearer: true, maxDownloads: null }
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
      { now: null }
    ]) {
      expect(() => new ShareRegistry(options as never)).toThrow();
    }
  });

  it('bounds reconnects with a non-sliding lease and an attempt cap', () => {
    const source = { name: 'x', size: 0, readChunk: async () => new Uint8Array() };
    let now = 1_000;
    const request = {
      peerId: 'peer-a',
      principalId: 'principal-a',
      subject: 'subject-a',
      fingerprint: 'v2:65536:1',
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
      fingerprint: 'v2:65536:1',
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

  it('terminalizes an acknowledged pull before a fallible stream finish', async () => {
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
    await acknowledgeEmptyPull(first.right, handle.token, 'request-a');
    await expect(handling).rejects.toMatchObject({ code: 'DISCONNECTED' });

    const replay = duplexPair();
    await writePull(replay.right.send, handle.token, 'request-a');
    const replayHandling = manager.handleControl(replay.left, testContext(testConnection(replay.left, new AsyncPipe())));
    expect((await readFrame(replay.right.recv)).kind).toBe(TransferFrameKind.Reject);
    await expect(replayHandling).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
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
      finalize: async () => undefined,
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
      finalize: async () => undefined,
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
    expect((control.left.send as AsyncPipe).resetCalls).toBeGreaterThan(0);
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
      finalize: async () => undefined,
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
    expect((control.left.send as AsyncPipe).resetCalls).toBeGreaterThan(0);
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
    expect((await stat(`${output}.p2prpc.part`)).mode & 0o777).toBe(0o600);
    await destination.writeChunk(manifest, 0, bytes);
    await writeFile(output, 'winner');
    await expect(destination.finalize(manifest)).rejects.toMatchObject({ code: 'REJECTED' });
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
    await destination.finalize(manifest);
    expect(await readFile(victim, 'utf8')).toBe('do-not-touch');
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
      finalize: async () => undefined,
      abort: async () => { aborted = true; }
    };
    const control = duplexPair();
    const context = testContext(testConnection(control.left, new AsyncPipe()));
    const receive = (manager as unknown as {
      receiveAttempt(
        stream: QuicBiStream,
        manifest: FileManifest,
        destination: FileDestination,
        transfer: undefined,
        context: FileTransferConnectionContext,
        signal: AbortSignal
      ): Promise<unknown>;
    }).receiveAttempt.bind(manager);
    const receiving = receive(control.left, manifest, destination, undefined, context, new AbortController().signal);
    const accepted = await readFrame<Record<string, unknown>>(control.right.recv);
    expect(accepted.kind).toBe(TransferFrameKind.Accept);

    const duplicate = duplexPair();
    await expect(receive(duplicate.left, manifest, destination, undefined, context, new AbortController().signal))
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
      incoming: () => { incomingCalled = true; }
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
      finalize: async () => { finalized = true; },
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
    await manager.handleData(lane, context);
    await writeFrame(control.right.send, TransferFrameKind.Complete, {
      transferId: manifest.transferId,
      attemptId: accepted.value.attemptId
    });
    await receiving;
    expect(writes).toEqual([byte]);
    expect(finalized).toBe(true);
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
    await writeFrame(control.right.send, TransferFrameKind.Complete, complete.value);
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
      finalize: async () => undefined,
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
    const releaseWrite = deferred<void>();
    const events: string[] = [];
    const destination: FileDestination = {
      prepare: async () => new Set(),
      writeChunk: async () => {
        events.push('write-started');
        writeStarted.resolve();
        await releaseWrite.promise;
        events.push('write-finished');
      },
      finalize: async () => undefined,
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
    for (let turn = 0; turn < 20 && lane.stopCalls === 0; turn += 1) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    expect(lane.stopCalls).toBeGreaterThan(0);
    expect(receivingSettled).toBe(false);
    expect(events).toEqual(['write-started']);

    releaseWrite.resolve();
    await handlingLane;
    expect(await observed).toMatchObject({ code: 'INVALID_FRAME' });
    expect(events).toEqual(['write-started', 'write-finished', 'abort']);
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
      finalize: async (_manifest, signal) => {
        finalizeStarted.resolve();
        await new Promise<void>((resolve) => {
          if (signal?.aborted) resolve();
          else signal?.addEventListener('abort', () => resolve(), { once: true });
        });
        finalizeAborted.resolve();
        await releaseFinalize.promise;
        if (signal?.aborted) throw signal.reason;
        published = true;
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
    await expect(destination.finalize(manifest, controller.signal))
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
      await writeFrame(second.right.send, TransferFrameKind.Complete, {
        transferId: requestId,
        attemptId: accepted.value.attemptId
      });
      await readFrame(second.right.recv);
    })();
    let finalized = false;
    const transfer = await manager.download('a'.repeat(43), {
      prepare: async () => new Set(),
      writeChunk: async () => undefined,
      finalize: async () => { finalized = true; },
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
      authorize: () => undefined
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
      finalize: async () => undefined,
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
      fingerprint: 'v2:65536:1',
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
  private bytes: number[] = [];

  async writeAll(data: Uint8Array): Promise<void> { this.bytes.push(...data); }
  async readExact(size: number): Promise<Uint8Array> {
    this.readSizes.push(size);
    if (this.bytes.length < size) throw new Error('EOF');
    return Uint8Array.from(this.bytes.splice(0, size));
  }
  async finish(): Promise<void> {}
  async reset(): Promise<void> {}
  async setPriority(): Promise<void> {}
  async stop(): Promise<void> {}
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
    this.ended = true;
    for (const waiter of this.waiters.splice(0)) waiter();
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
    stats: async () => ({ rttMs: 0, sentBytes: 0, receivedBytes: 0, lostPackets: 0 }),
    configure: () => undefined
  };
}

async function writePull(send: QuicSendStream, token: string, requestId: string): Promise<void> {
  await writeFrame(send, TransferFrameKind.Pull, {
    token,
    requestId,
    options: { chunkSize: 64 * 1024, lanes: 1 }
  });
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
  await writeFrame(remote.send, TransferFrameKind.Complete, complete.value);
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
  await writeFrame(remote.send, TransferFrameKind.Complete, complete.value);
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
      signal: AbortSignal
    ): Promise<unknown>;
  }).receiveAttempt.bind(manager);
  return (
    stream: QuicBiStream,
    manifest: FileManifest,
    destination: FileDestination,
    transfer: undefined,
    signal: AbortSignal
  ): Promise<unknown> => receive(stream, manifest, destination, transfer, context, signal);
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
