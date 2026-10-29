import { createTRPCProxyClient, type CreateTRPCClient } from '@trpc/client';
import { initTRPC, type AnyTRPCRouter } from '@trpc/server';
import { P2PError, asP2PError } from '../errors.js';
import { ReceiverOperationLedger, TransferManager, type FileTransferConnectionContext } from '../files/manager.js';
import { ShareRegistry } from '../files/share.js';
import type { FileSource, FileTransfer, SharedFileHandle } from '../files/types.js';
import { resolveFileTransferLimits } from '../files/validation.js';
import { byteLength, unrefTimer, utf8Bytes } from '../platform.js';
import { DEFAULT_FRAME_LIMITS, readStreamKind, StreamKind } from '../protocol.js';
import { DEFAULT_RPC_HEADER_LIMITS } from '../rpc/portable-headers.js';
import { irohLink } from '../rpc/portable-link.js';
import { RpcServer, type RpcServerRequest } from '../rpc/portable-server.js';
import { ManagedConnection } from '../runtime/managed-connection.js';
import { ResourceScheduler, type ResourceLease, type ResourceLimits } from '../runtime/resources.js';
import { TaskGroup } from '../runtime/task-group.js';
import { authorizationAllowed, freezePrincipal, type AuthorizationAction } from '../security/types.js';
import { containsUnsafeDisplayCharacters, sanitizeBoundedDisplayText } from '../text.js';
import type { QuicBiStream, QuicConnection, QuicRecvStream } from '../transport/types.js';
import type { BridgeContext, BridgeFiles, BridgePeer, BridgePeerLimits, BridgePeerOptions, BridgeSession, BridgeShareOptions } from './contracts.js';

const emptyRouter = initTRPC.create({ allowOutsideOfServer: true }).router({});
const DEFAULT_LIMITS: BridgePeerLimits = {
  maxStreams: 64, maxBufferedBytes: 32 * 1024 * 1024, maxCallbacks: 32,
  maxQueuedOperations: 128, setupTimeoutMs: 5_000, ioTimeoutMs: 30_000, shutdownTimeoutMs: 5_000
};
interface Epoch {
  readonly raw: QuicConnection;
  readonly connection: ManagedConnection;
  readonly session: BridgeSession;
  readonly controller: AbortController;
  readonly files: FileTransferConnectionContext;
  readonly proof: Promise<void>;
  timer?: ReturnType<typeof setTimeout>;
  closed: boolean;
}

/** One portable logical Peer runtime. Authentication belongs to admission. */
export function createBridgePeer<RemoteRouter extends AnyTRPCRouter, LocalRouter extends AnyTRPCRouter = AnyTRPCRouter, M = unknown>(
  options: BridgePeerOptions<LocalRouter, M>
): BridgePeer<RemoteRouter, M> {
  return new LogicalPeer<RemoteRouter, LocalRouter, M>(options);
}

class LogicalPeer<R extends AnyTRPCRouter, L extends AnyTRPCRouter, M> implements BridgePeer<R, M> {
  readonly rpc: CreateTRPCClient<R>;
  readonly files: BridgeFiles<M>;
  private readonly tasks = new TaskGroup('Bridge Peer');
  private readonly shares: ShareRegistry<M>;
  private readonly receiver: ReceiverOperationLedger;
  private readonly transfers: TransferManager<M>;
  private readonly resources: ResourceScheduler;
  private readonly limits: BridgePeerLimits;
  private epoch: Epoch | undefined;
  private closed = false;

  constructor(private readonly options: BridgePeerOptions<L, M>) {
    validId(options.localId); validId(options.remoteId);
    if (typeof options.connection !== 'function' || typeof options.authorize !== 'function') {
      throw new P2PError('INVALID_FRAME', 'Bridge connection and authorization are required');
    }
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    for (const [name, value] of Object.entries(this.limits)) {
      if (!Number.isSafeInteger(value) || value < 1 || value > (name === 'maxBufferedBytes' ? 1024 ** 3 : 600_000)) {
        throw new P2PError('RESOURCE_LIMIT', `Invalid Bridge limit ${name}`);
      }
    }
    const fileLimits = resolveFileTransferLimits(options.fileLimits);
    const frameBytes = (options.frameLimits ?? DEFAULT_FRAME_LIMITS).maxControlFrameBytes;
    this.resources = new ResourceScheduler(resourceLimits(this.limits, fileLimits.maxChunkSize, frameBytes, fileLimits.maxTransfers));
    this.shares = new ShareRegistry(options.shares);
    this.receiver = new ReceiverOperationLedger({ maxOperationRecords: 1_024, maxReplayTombstones: 1_024, operationRecordTtlMs: 15 * 60_000 });
    this.transfers = new TransferManager<M>({
      peerId: options.remoteId,
      connection: async () => this.fileContext(await this.connection()),
      shares: this.shares, receiverOperations: this.receiver, limits: fileLimits,
      frameLimits: options.frameLimits ?? DEFAULT_FRAME_LIMITS,
      idleTimeoutMs: Math.max(1_000, this.limits.ioTimeoutMs),
      authorize: (action, security, signal) => {
        const epoch = this.current();
        if (epoch.session.id !== security.sessionId || epoch.session.principal !== security.principal) throw new P2PError('UNAUTHORIZED', 'Stale Bridge file session');
        return this.authorize(epoch, action, signal);
      },
      ...(options.fileMetadataSchema ? { metadataSchema: options.fileMetadataSchema } : {}),
      ...(options.incoming ? { incoming: (offer) => this.callback(this.current(), offer.signal, () => options.incoming!(offer)) } : {}),
      acquireTransfer: async (direction, signal) => {
        signal.throwIfAborted();
        const epoch = direction === 'inbound' ? this.current() : await this.connection();
        signal.throwIfAborted();
        const lease = await this.resources.acquire(this.owner(epoch), direction === 'outbound' ? { outboundTransfers: 1 } : { inboundTransfers: 1 }, signal);
        return () => lease.release();
      }
    });
    this.rpc = createTRPCProxyClient<R>({ links: [irohLink({
      connection: async () => (await this.connection()).connection,
      frameLimits: options.frameLimits ?? DEFAULT_FRAME_LIMITS,
      headerLimits: options.headerLimits ?? DEFAULT_RPC_HEADER_LIMITS,
      ioTimeoutMs: this.limits.ioTimeoutMs,
      ...(options.getRequestHeaders ? { getRequestHeaders: async (request) => this.callback(await this.connection(), request.signal, () => options.getRequestHeaders!(request)) } : {})
    })] });
    this.files = Object.freeze<BridgeFiles<M>>({
      sendFile: (source, sendOptions) => this.trackTransfer(this.transfers.sendFile(source, sendOptions)),
      download: (handle, destination, downloadOptions) => this.trackTransfer(this.transfers.download(handle.token, destination, downloadOptions)),
      share: (source, policy) => this.share(this.current(), source, policy),
      revoke: (handle) => this.shares.revoke(handle)
    });
  }

  attach(raw: QuicConnection, session: BridgeSession): void {
    this.assertOpen();
    if (raw.remoteId !== this.options.remoteId) throw new P2PError('UNAUTHORIZED', 'Bridge carrier peer mismatch');
    if (this.epoch && (!this.epoch.closed || this.epoch.raw === raw)) throw new P2PError('REJECTED', 'Previous Bridge carrier has not positively closed or was reused');
    const principal = freezePrincipal(session.principal);
    const via = Object.freeze({ peerId: session.via.peerId, principal: freezePrincipal(session.via.principal) });
    validId(session.id); validId(via.peerId);
    if (!Number.isSafeInteger(session.expiresAt) || session.expiresAt <= Date.now() || session.expiresAt > Math.min(principal.expiresAt, via.principal.expiresAt)) {
      throw new P2PError('UNAUTHORIZED', 'Bridge admission is expired or exceeds authenticated lifetime');
    }
    const checked = Object.freeze({ id: session.id, principal, via, expiresAt: session.expiresAt });
    const controller = new AbortController();
    const owner = { peerId: this.options.remoteId, principalId: principal.id };
    const connection = new ManagedConnection(raw, this.resources, owner, controller.signal,
      (this.options.frameLimits ?? DEFAULT_FRAME_LIMITS).maxControlFrameBytes,
      resolveFileTransferLimits(this.options.fileLimits).maxChunkSize + 1024);
    let prove!: () => void;
    const proof = new Promise<void>((resolve) => { prove = resolve; });
    const epoch: Epoch = { raw, connection, session: checked, controller, proof, closed: false,
      // The existing file protocol binds control and data lanes to this exact
      // context object, as well as its authenticated session and attempt IDs.
      files: { connection, security: { sessionId: checked.id, principal }, signal: controller.signal,
        quarantine: (reason) => this.quarantine(epoch, reason) } };
    this.epoch = epoch;
    this.tasks.track(proof);
    void Promise.resolve().then(() => raw.closed()).then(() => {
      epoch.closed = true;
      controller.abort(new P2PError('DISCONNECTED', 'Bridge carrier closed'));
      if (epoch.timer) clearTimeout(epoch.timer);
      prove();
    }, (cause: unknown) => {
      controller.abort(new P2PError('DISCONNECTED', 'Bridge carrier closure is unproved'));
      this.report(cause);
    });
    const expire = (): void => {
      const remaining = checked.expiresAt - Date.now();
      if (remaining > 0) { epoch.timer = setTimeout(expire, Math.min(remaining, 2_147_483_647)); unrefTimer(epoch.timer); }
      else this.quarantine(epoch, 'Bridge admission expired');
    };
    expire();
    this.tasks.track(this.acceptBi(epoch));
    this.tasks.track(this.acceptUni(epoch));
  }

  diagnostics() {
    return Object.freeze({ connected: this.epoch !== undefined && !this.epoch.controller.signal.aborted && !this.closed,
      closed: this.closed, sessionId: this.epoch?.session.id ?? null, tasks: this.tasks.size,
      resources: this.resources.snapshot(), shares: this.shares.diagnostics(), files: this.transfers.diagnostics() });
  }

  async close(reason = 'Bridge Peer closed'): Promise<void> {
    this.closed = true;
    const failure = new P2PError('DISCONNECTED', sanitizeBoundedDisplayText(reason, 256, 'Bridge Peer closed'));
    this.transfers.close(failure); this.shares.close(failure); this.resources.close(failure);
    if (this.epoch && !this.epoch.closed) this.quarantine(this.epoch, failure.message);
    this.tasks.track(this.resources.whenIdle());
    await this.tasks.close(failure, { timeoutMs: this.limits.shutdownTimeoutMs });
    this.receiver.close();
  }

  private current(): Epoch {
    this.assertOpen();
    const epoch = this.epoch;
    if (!epoch) throw new P2PError('DISCONNECTED', 'Bridge has no admitted carrier');
    this.active(epoch);
    return epoch;
  }
  private assertOpen(): void { if (this.closed) throw new P2PError('DISCONNECTED', 'Bridge Peer is closed'); }
  private active(epoch: Epoch): void {
    this.assertOpen();
    if (this.epoch !== epoch || epoch.controller.signal.aborted || epoch.session.expiresAt <= Date.now()) {
      throw new P2PError('UNAUTHORIZED', 'Bridge session is not active');
    }
  }
  private async connection(): Promise<Epoch> {
    this.assertOpen();
    if (this.epoch && !this.epoch.controller.signal.aborted) return this.current();
    const lease = await this.resources.acquire({ peerId: this.options.remoteId }, { callbacks: 1 }, this.tasks.signal);
    if (this.epoch && !this.epoch.controller.signal.aborted && !this.closed) { lease.release(); return this.current(); }
    const raw = await this.tasks.track(Promise.resolve().then(() => { this.assertOpen(); return this.options.connection(); }).finally(() => lease.release()));
    const epoch = this.current();
    if (raw !== epoch.raw && raw !== epoch.connection) throw new P2PError('UNAUTHORIZED', 'Bridge connection was not admitted by attach');
    return epoch;
  }
  private owner(epoch: Epoch) { return { peerId: this.options.remoteId, principalId: epoch.session.principal.id }; }
  private fileContext(epoch: Epoch): FileTransferConnectionContext {
    this.active(epoch);
    return epoch.files;
  }
  private share(epoch: Epoch, source: FileSource<M>, policy: BridgeShareOptions = {}): SharedFileHandle {
    this.active(epoch);
    return this.shares.shareForPeer(source, this.options.remoteId, policy, epoch.session.principal);
  }
  private async trackTransfer(task: Promise<FileTransfer<M>>): Promise<FileTransfer<M>> {
    const transfer = await this.tasks.track(task);
    this.tasks.track(transfer.result);
    return transfer;
  }
  private callback<T>(epoch: Epoch, signal: AbortSignal, action: () => T | Promise<T>): Promise<T> {
    const admitted = this.resources.acquire(this.owner(epoch), { callbacks: 1 }, signal).then((lease) => {
      const work = Promise.resolve().then(() => { this.active(epoch); signal.throwIfAborted(); return action(); });
      return this.tasks.track(work.finally(() => lease.release()));
    });
    this.tasks.track(admitted);
    return aborted(admitted, signal);
  }
  private async authorize(epoch: Epoch, action: AuthorizationAction<M>, signal: AbortSignal): Promise<void> {
    this.active(epoch);
    const decision = authorizationAllowed(await this.callback(epoch, signal, () => this.options.authorize(Object.freeze({
      principal: epoch.session.principal, localPeerId: this.options.localId, remotePeerId: this.options.remoteId,
      sessionId: epoch.session.id, via: epoch.session.via, action, signal
    }))));
    this.active(epoch); signal.throwIfAborted();
    if (!decision.allowed) throw new P2PError('UNAUTHORIZED', 'Bridge operation is not authorized');
  }
  private async context(epoch: Epoch, request: RpcServerRequest) {
    this.active(epoch);
    const bridge: BridgeContext<M>['bridge'] = Object.freeze({ peerId: this.options.remoteId,
      principal: epoch.session.principal, via: epoch.session.via, request,
      files: Object.freeze({
        share: (source: FileSource<M>, policy?: BridgeShareOptions) => { request.signal.throwIfAborted(); return this.share(epoch, source, policy); },
        revoke: (handle: SharedFileHandle) => { request.signal.throwIfAborted(); this.active(epoch); return this.shares.revoke(handle); }
      }) });
    const seed = Object.freeze({ bridge });
    const app = this.options.local ? await this.callback(epoch, request.signal, () => this.options.local!.createContext(seed)) : {};
    if (!app || typeof app !== 'object' || (Object.getPrototypeOf(app) !== Object.prototype && Object.getPrototypeOf(app) !== null)) {
      throw new P2PError('INTERNAL', 'Bridge context must be a plain object');
    }
    if (Object.hasOwn(app, 'bridge') && Reflect.get(app, 'bridge') !== bridge) throw new P2PError('UNAUTHORIZED', 'Application cannot replace Bridge context');
    return Object.freeze({ ...app, bridge });
  }

  private async acceptBi(epoch: Epoch): Promise<void> {
    const server = new RpcServer({ router: this.options.local?.router ?? emptyRouter,
      createContext: (request) => this.context(epoch, request),
      authorize: (request, signal) => this.authorize(epoch, { kind: 'rpc', path: request.path, type: request.type, headers: request.headers }, signal),
      headerLimits: this.options.headerLimits ?? DEFAULT_RPC_HEADER_LIMITS, maxPathBytes: this.options.maxPathBytes ?? 1024,
      frameLimits: this.options.frameLimits ?? DEFAULT_FRAME_LIMITS, setupTimeoutMs: this.limits.setupTimeoutMs,
      ioTimeoutMs: this.limits.ioTimeoutMs, sessionSignal: epoch.controller.signal, assertActive: () => this.active(epoch),
      onError: (error) => this.report(error) });
    while (!epoch.controller.signal.aborted && !this.closed) {
      let stream: QuicBiStream | undefined;
      try {
        stream = await this.accept(epoch, () => epoch.raw.acceptBi(), (late) => this.resetBi(epoch, late));
        const kind = await deadline(readStreamKind(stream.recv), this.limits.setupTimeoutMs, epoch.controller.signal);
        this.active(epoch);
        if (kind !== StreamKind.Rpc && kind !== StreamKind.TransferControl) throw new P2PError('INVALID_FRAME', 'Invalid logical bidirectional stream kind');
        const lease = this.resources.tryAcquire(this.owner(epoch), { streams: 1,
          bufferedBytes: (this.options.frameLimits ?? DEFAULT_FRAME_LIMITS).maxControlFrameBytes,
          ...(kind === StreamKind.TransferControl ? { fileControl: 'inbound' as const } : {}) });
        if (!lease) throw new P2PError('RESOURCE_LIMIT', 'Bridge stream capacity unavailable');
        const owned = stream; stream = undefined;
        this.dispatch(epoch, lease, async (track) => {
          if (kind === StreamKind.Rpc) await server.handle(owned, track);
          else await this.transfers.handleControl(owned, this.fileContext(epoch), track);
        }, () => this.resetBi(epoch, owned));
      } catch (cause) {
        if (stream) await this.resetBi(epoch, stream);
        if (!epoch.controller.signal.aborted) { this.report(cause); if (!stream) this.quarantine(epoch, 'Bridge accept failed'); }
      }
    }
  }
  private async acceptUni(epoch: Epoch): Promise<void> {
    while (!epoch.controller.signal.aborted && !this.closed) {
      let stream: QuicRecvStream | undefined;
      let lease: ResourceLease | undefined;
      try {
        stream = await this.accept(epoch, () => epoch.raw.acceptUni(), (late) => this.stopUni(epoch, late));
        lease = await this.resources.acquire(this.owner(epoch), { streams: 1,
          bufferedBytes: resolveFileTransferLimits(this.options.fileLimits).maxChunkSize + 1024, fileData: 'inbound' }, epoch.controller.signal);
        const owned = stream; const admission = lease; stream = undefined; lease = undefined;
        this.dispatch(epoch, admission, async () => {
          if (await deadline(readStreamKind(owned), this.limits.setupTimeoutMs, epoch.controller.signal) !== StreamKind.TransferData) throw new P2PError('INVALID_FRAME', 'Invalid logical unidirectional stream kind');
          this.active(epoch);
          await this.transfers.handleData(owned, this.fileContext(epoch));
        }, () => this.stopUni(epoch, owned));
      } catch (cause) {
        if (stream) await this.stopUni(epoch, stream);
        lease?.release();
        if (!epoch.controller.signal.aborted) { this.report(cause); if (!stream) this.quarantine(epoch, 'Bridge accept failed'); }
      }
    }
  }
  private dispatch(epoch: Epoch, lease: ResourceLease, run: (track: (work: Promise<unknown>) => void) => Promise<void>, cleanup: () => Promise<void>): void {
    let owners = 1;
    let released = false;
    const release = (): void => { owners -= 1; if (owners === 0 && !released) { released = true; lease.release(); } };
    const track = (work: Promise<unknown>): void => {
      if (released) throw new P2PError('INTERNAL', 'Cannot register Bridge work after releasing admission');
      owners += 1; this.tasks.track(work); void work.then(release, release);
    };
    this.tasks.track(Promise.resolve().then(() => { this.active(epoch); return run(track); }).catch(async (cause: unknown) => {
      this.report(cause); await cleanup();
    }).finally(release));
  }
  private async accept<T>(epoch: Epoch, open: () => Promise<T>, cleanup: (value: T) => Promise<void>): Promise<T> {
    let adopted = false;
    const pending = Promise.resolve().then(open);
    try {
      const value = await aborted(pending, epoch.controller.signal);
      adopted = true;
      return value;
    } finally {
      if (!adopted) this.tasks.track(Promise.race([pending.then(cleanup, () => undefined), epoch.proof]));
    }
  }
  private async resetBi(epoch: Epoch, stream: QuicBiStream): Promise<void> {
    await this.settle(epoch, Promise.all([Promise.resolve().then(() => stream.send.reset(1n)), Promise.resolve().then(() => stream.recv.stop(1n))]));
  }
  private async stopUni(epoch: Epoch, stream: QuicRecvStream): Promise<void> { await this.settle(epoch, Promise.resolve().then(() => stream.stop(1n))); }
  private async settle(epoch: Epoch, work: Promise<unknown>): Promise<void> {
    try { await deadline(work, this.limits.setupTimeoutMs); }
    catch { this.quarantine(epoch, 'Bridge stream cleanup is unproved'); await epoch.proof; }
  }
  private quarantine(epoch: Epoch, reason: string): void {
    epoch.controller.abort(new P2PError('DISCONNECTED', reason));
    try { epoch.connection.close(1n, utf8Bytes(sanitizeBoundedDisplayText(reason, 256, 'Bridge disconnected'))); }
    catch (cause) { this.report(cause); }
  }
  private report(cause: unknown): void { try { this.options.onError?.(asP2PError(cause)); } catch { /* notification only */ } }
}

function validId(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || byteLength(value) > 2048 || containsUnsafeDisplayCharacters(value)) throw new P2PError('INVALID_FRAME', 'Invalid logical peer identity');
}
function resourceLimits(limits: BridgePeerLimits, chunkBytes: number, frameBytes: number, transfers: number): ResourceLimits {
  // Scheduler capacities are positive; this slot is never used for native auth.
  const capacity = { handshakes: 1, streams: limits.maxStreams, bufferedBytes: limits.maxBufferedBytes,
    callbacks: limits.maxCallbacks, queued: limits.maxQueuedOperations, inboundTransfers: transfers, outboundTransfers: transfers };
  const data = { outbound: { streams: 1, bufferedBytes: chunkBytes + 1024 }, inbound: { streams: 1, bufferedBytes: chunkBytes + 1024 } };
  const control = { outbound: { streams: 1, bufferedBytes: frameBytes }, inbound: { streams: 1, bufferedBytes: frameBytes } };
  const general = { streams: 1, bufferedBytes: frameBytes };
  return { global: capacity, perPeer: capacity, perPrincipal: capacity,
    fileDataReserve: { global: data, perPeer: data, perPrincipal: data },
    fileControlReserve: { global: control, perPeer: control, perPrincipal: control },
    generalReserve: { global: general, perPeer: general, perPrincipal: general } };
}
function aborted<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const abort = (): void => reject(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    void work.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}
async function deadline<T>(work: Promise<T>, ms: number, signal?: AbortSignal): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new P2PError('TIMEOUT', 'Bridge stream operation timed out')), ms); unrefTimer(timer); });
    const pending = Promise.race([work, timeout]);
    return await (signal ? aborted(pending, signal) : pending);
  } finally { if (timer) clearTimeout(timer); }
}
