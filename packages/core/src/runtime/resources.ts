import { P2PError } from '../errors.js';

export interface ResourceRequest {
  readonly handshakes?: number;
  readonly streams?: number;
  /** Locally initiated file operations. Kept separate to prevent cross-dial deadlock. */
  readonly outboundTransfers?: number;
  /** Remotely initiated file controls. Reserved independently from outbound work. */
  readonly inboundTransfers?: number;
  readonly bufferedBytes?: number;
  readonly callbacks?: number;
  /** Internal admission class for a bidirectional file-control stream. */
  readonly fileControl?: 'outbound' | 'inbound';
  /** Internal admission class for a unidirectional file-data lane. */
  readonly fileData?: 'outbound' | 'inbound';
}

export type ResourceAmounts = Required<Omit<ResourceRequest, 'fileControl' | 'fileData'>>;

export interface ResourceCapacity {
  readonly streams: number;
  readonly bufferedBytes: number;
}

export interface FileDataReserve {
  readonly outbound: ResourceCapacity;
  readonly inbound: ResourceCapacity;
}

type ResourceLimit = ResourceAmounts & { readonly queued: number };

export interface ResourceOwner {
  readonly peerId: string;
  /** Stable authenticated principal ID. Omit only before authentication. */
  readonly principalId?: string;
}

export interface ResourceLimits {
  readonly global: ResourceLimit;
  readonly perPeer: ResourceLimit;
  /** Aggregate quota shared by every endpoint key authenticated as one principal. */
  readonly perPrincipal: ResourceLimit;
  /** Capacity unavailable to general streams, so one file lane can always make progress. */
  readonly fileDataReserve: {
    readonly global: FileDataReserve;
    readonly perPeer: FileDataReserve;
    readonly perPrincipal: FileDataReserve;
  };
  /** Capacity unavailable to RPC/data streams, so symmetric controls cannot deadlock. */
  readonly fileControlReserve: {
    readonly global: FileDataReserve;
    readonly perPeer: FileDataReserve;
    readonly perPrincipal: FileDataReserve;
  };
  /** Capacity which file-class overflow can never borrow. */
  readonly generalReserve: {
    readonly global: ResourceCapacity;
    readonly perPeer: ResourceCapacity;
    readonly perPrincipal: ResourceCapacity;
  };
}

export interface ResourceSnapshot {
  readonly active: Readonly<ResourceAmounts>;
  readonly queued: number;
  readonly peers: number;
  readonly principals: number;
  readonly closed: boolean;
}

export interface ResourceLease {
  readonly request: Readonly<ResourceAmounts>;
  release(): void;
}

type MutableResourceAmounts = {
  -readonly [Name in keyof ResourceAmounts]: ResourceAmounts[Name];
};

type ResourceCounter = MutableResourceAmounts & {
  /** Subset of streams admitted from the file-data reserve. */
  outboundFileDataStreams: number;
  inboundFileDataStreams: number;
  /** Subset of bufferedBytes admitted from the file-data reserve. */
  outboundFileDataBufferedBytes: number;
  inboundFileDataBufferedBytes: number;
  outboundFileControlStreams: number;
  inboundFileControlStreams: number;
  outboundFileControlBufferedBytes: number;
  inboundFileControlBufferedBytes: number;
};

interface Waiter {
  readonly peerId: string;
  readonly principalId?: string;
  readonly request: ResourceCounter;
  readonly resolve: (lease: ResourceLease) => void;
  readonly reject: (error: unknown) => void;
  readonly signal?: AbortSignal;
  removeAbort?: () => void;
}

interface PeerState {
  readonly active: ResourceCounter;
  readonly queue: Waiter[];
  scheduled: boolean;
}

interface PrincipalState {
  readonly active: ResourceCounter;
  queued: number;
}

interface LeaseState {
  readonly peerId: string;
  readonly peer: PeerState;
  readonly principalId?: string;
  readonly principal?: PrincipalState;
  readonly request: ResourceCounter;
  released: boolean;
}

interface OwnerIdleWaiter {
  readonly owner: Readonly<ResourceOwner>;
  readonly resolve: () => void;
}

const ZERO = (): ResourceCounter => ({
  handshakes: 0,
  streams: 0,
  outboundTransfers: 0,
  inboundTransfers: 0,
  bufferedBytes: 0,
  callbacks: 0,
  outboundFileDataStreams: 0,
  inboundFileDataStreams: 0,
  outboundFileDataBufferedBytes: 0,
  inboundFileDataBufferedBytes: 0,
  outboundFileControlStreams: 0,
  inboundFileControlStreams: 0,
  outboundFileControlBufferedBytes: 0,
  inboundFileControlBufferedBytes: 0
});

/**
 * Node-wide, peer-fair admission. Peers are round-robin; within a peer the
 * oldest request which can currently make progress is selected. Skipping a
 * quota-blocked heterogeneous request is essential: a queued new transfer
 * must never sit ahead of the stream required by an active transfer to finish.
 */
export class ResourceScheduler {
  private readonly active = ZERO();
  private readonly peers = new Map<string, PeerState>();
  private readonly principals = new Map<string, PrincipalState>();
  private readonly leases = new Set<LeaseState>();
  private readonly idleWaiters = new Set<() => void>();
  private readonly ownerIdleWaiters = new Set<OwnerIdleWaiter>();
  private readonly ready: string[] = [];
  private queued = 0;
  private closed?: P2PError;

  constructor(readonly limits: ResourceLimits) {
    validateLimits(limits);
  }

  snapshot(): ResourceSnapshot {
    return Object.freeze({
      active: Object.freeze(publicAmounts(this.active)),
      queued: this.queued,
      peers: this.peers.size,
      principals: this.principals.size,
      closed: this.closed !== undefined
    });
  }

  /**
   * Resolve only when no queued or active owner remains. Closing admission does
   * not manufacture idleness; a timed-out caller may wait on this again later.
   */
  whenIdle(): Promise<void> {
    if (this.queued === 0 && this.leases.size === 0) return Promise.resolve();
    return new Promise<void>((resolve) => this.idleWaiters.add(resolve));
  }

  /**
   * Resolve when work for one exact owner has settled. Omitting principalId
   * waits for every principal associated with that endpoint key; supplying it
   * waits only for that endpoint/principal pair.
   */
  whenOwnerIdle(ownerInput: string | ResourceOwner): Promise<void> {
    const owner = normalizeOwner(ownerInput);
    if (this.isOwnerIdle(owner)) return Promise.resolve();
    return new Promise<void>((resolve) => {
      this.ownerIdleWaiters.add({ owner, resolve });
    });
  }

  tryAcquire(ownerInput: string | ResourceOwner, input: ResourceRequest): ResourceLease | undefined {
    this.assertOpen();
    const owner = normalizeOwner(ownerInput);
    const request = normalizeRequest(input);
    this.assertRequestFits(request, owner.principalId !== undefined);
    const peer = this.peer(owner.peerId);
    const principal = owner.principalId === undefined ? undefined : this.principal(owner.principalId);
    // A blocked heterogeneous waiter must not hide a directional reserve from
    // work which can make progress now. drain() eagerly grants every fitting
    // queued waiter after each state transition, so any waiter still queued at
    // this point cannot be overtaken for capacity it could currently use.
    if (!this.fits(peer, principal, request)) {
      this.compactOwner(owner.peerId, peer, owner.principalId, principal);
      return undefined;
    }
    return this.grant(owner.peerId, peer, owner.principalId, principal, request);
  }

  acquire(
    ownerInput: string | ResourceOwner,
    input: ResourceRequest,
    signal?: AbortSignal
  ): Promise<ResourceLease> {
    let owner: Readonly<ResourceOwner>;
    try {
      owner = normalizeOwner(ownerInput);
      if (signal?.aborted) {
        return Promise.reject(signal.reason ?? new P2PError('CANCELLED', 'Resource admission was cancelled'));
      }
      const immediate = this.tryAcquire(owner, input);
      if (immediate) return Promise.resolve(immediate);
    } catch (cause) {
      return Promise.reject(cause);
    }
    const peer = this.peer(owner.peerId);
    const principal = owner.principalId === undefined ? undefined : this.principal(owner.principalId);
    if (
      this.queued >= this.limits.global.queued ||
      peer.queue.length >= this.limits.perPeer.queued ||
      (principal !== undefined && principal.queued >= this.limits.perPrincipal.queued)
    ) {
      this.compactOwner(owner.peerId, peer, owner.principalId, principal);
      return Promise.reject(new P2PError('RESOURCE_LIMIT', 'Resource admission queue is full'));
    }
    return new Promise<ResourceLease>((resolve, reject) => {
      const waiter: Waiter = {
        peerId: owner.peerId,
        ...(owner.principalId !== undefined ? { principalId: owner.principalId } : {}),
        request: normalizeRequest(input),
        resolve,
        reject,
        ...(signal ? { signal } : {})
      };
      if (signal) {
        const onAbort = (): void => {
          const index = peer.queue.indexOf(waiter);
          if (index >= 0) {
            peer.queue.splice(index, 1);
            this.queued -= 1;
            if (principal) principal.queued -= 1;
            this.compactOwner(owner.peerId, peer, owner.principalId, principal);
            // Remove this peer's stale round-robin entry immediately. Waiting
            // for an unrelated lease release would let repeated cancelled
            // admissions grow `ready` while every public counter stayed zero.
            this.drain();
          }
          reject(signal.reason ?? new P2PError('CANCELLED', 'Resource admission was cancelled'));
          this.notifyIdle();
        };
        signal.addEventListener('abort', onAbort, { once: true });
        waiter.removeAbort = () => signal.removeEventListener('abort', onAbort);
      }
      peer.queue.push(waiter);
      this.queued += 1;
      if (principal) principal.queued += 1;
      this.schedule(owner.peerId, peer);
      this.drain();
    });
  }

  close(reason = new P2PError('DISCONNECTED', 'Resource scheduler is closed')): void {
    if (this.closed) return;
    this.closed = reason;
    for (const peer of this.peers.values()) {
      for (const waiter of peer.queue.splice(0)) {
        this.queued -= 1;
        if (waiter.principalId !== undefined) {
          const principal = this.principals.get(waiter.principalId);
          if (principal) principal.queued -= 1;
        }
        waiter.removeAbort?.();
        waiter.reject(reason);
      }
      peer.scheduled = false;
    }
    this.ready.length = 0;
    // Closing rejects new and queued work, but it cannot revoke ownership of
    // native resources or application promises which have not actually
    // settled. Keep those leases visible until their owners release them.
    // Otherwise a zero ledger would be a false leak-free-shutdown signal.
    for (const [peerId, peer] of this.peers) this.compactOwner(peerId, peer);
    for (const [principalId, principal] of this.principals) {
      if (principal.queued === 0 && empty(principal.active)) this.principals.delete(principalId);
    }
    this.notifyIdle();
  }

  private grant(
    peerId: string,
    peer: PeerState,
    principalId: string | undefined,
    principal: PrincipalState | undefined,
    request: ResourceCounter
  ): ResourceLease {
    add(this.active, request, 1);
    add(peer.active, request, 1);
    if (principal) add(principal.active, request, 1);
    const state: LeaseState = {
      peerId,
      peer,
      ...(principalId !== undefined ? { principalId } : {}),
      ...(principal !== undefined ? { principal } : {}),
      request,
      released: false
    };
    this.leases.add(state);
    return Object.freeze({
      request: Object.freeze(publicAmounts(request)),
      release: () => this.releaseLease(state)
    });
  }

  private releaseLease(state: LeaseState): void {
    if (state.released) return;
    state.released = true;
    this.leases.delete(state);
    add(this.active, state.request, -1);
    add(state.peer.active, state.request, -1);
    if (state.principal) add(state.principal.active, state.request, -1);
    this.compactOwner(state.peerId, state.peer, state.principalId, state.principal);
    this.drain();
    this.notifyIdle();
  }

  private drain(): void {
    if (this.closed) return;
    let progressed: boolean;
    do {
      progressed = false;
      let visits = this.ready.length;
      while (visits > 0 && this.ready.length > 0) {
        visits -= 1;
        const peerId = this.ready.shift()!;
        const peer = this.peers.get(peerId);
        if (!peer) continue;
        peer.scheduled = false;
        if (peer.queue.length === 0) {
          this.compactOwner(peerId, peer);
          continue;
        }
        let waiterIndex = -1;
        let principal: PrincipalState | undefined;
        for (let index = 0; index < peer.queue.length; index += 1) {
          const candidate = peer.queue[index]!;
          const candidatePrincipal = candidate.principalId === undefined
            ? undefined
            : this.principals.get(candidate.principalId);
          if (this.fits(peer, candidatePrincipal, candidate.request)) {
            waiterIndex = index;
            principal = candidatePrincipal;
            break;
          }
        }
        if (waiterIndex >= 0) {
          const [waiter] = peer.queue.splice(waiterIndex, 1);
          if (!waiter) throw new P2PError('INTERNAL', 'Resource admission queue became inconsistent');
          this.queued -= 1;
          if (principal) principal.queued -= 1;
          waiter.removeAbort?.();
          waiter.resolve(this.grant(peerId, peer, waiter.principalId, principal, waiter.request));
          progressed = true;
          if (peer.queue.length > 0) this.schedule(peerId, peer);
          else this.compactOwner(peerId, peer, waiter.principalId, principal);
        } else {
          this.schedule(peerId, peer);
        }
      }
      // Continue only after at least one grant. If no request fits, a future
      // release or cancellation will trigger the next bounded round.
    } while (progressed && this.ready.length > 0);
  }

  private fits(peer: PeerState, principal: PrincipalState | undefined, request: ResourceCounter): boolean {
    return fits(
      this.active,
      request,
      this.limits.global,
      this.limits.fileDataReserve.global,
      this.limits.fileControlReserve.global,
      this.limits.generalReserve.global
    ) && fits(
      peer.active,
      request,
      this.limits.perPeer,
      this.limits.fileDataReserve.perPeer,
      this.limits.fileControlReserve.perPeer,
      this.limits.generalReserve.perPeer
    ) &&
      (principal === undefined || fits(
        principal.active,
        request,
        this.limits.perPrincipal,
        this.limits.fileDataReserve.perPrincipal,
        this.limits.fileControlReserve.perPrincipal,
        this.limits.generalReserve.perPrincipal
      ));
  }

  private assertRequestFits(request: ResourceCounter, hasPrincipal: boolean): void {
    if (
      !fits(
        ZERO(), request, this.limits.global,
        this.limits.fileDataReserve.global,
        this.limits.fileControlReserve.global,
        this.limits.generalReserve.global
      ) ||
      !fits(
        ZERO(), request, this.limits.perPeer,
        this.limits.fileDataReserve.perPeer,
        this.limits.fileControlReserve.perPeer,
        this.limits.generalReserve.perPeer
      ) ||
      (hasPrincipal && !fits(
        ZERO(),
        request,
        this.limits.perPrincipal,
        this.limits.fileDataReserve.perPrincipal,
        this.limits.fileControlReserve.perPrincipal,
        this.limits.generalReserve.perPrincipal
      ))
    ) {
      throw new P2PError('RESOURCE_LIMIT', 'Resource request exceeds configured admission limits');
    }
  }

  private peer(peerId: string): PeerState {
    let peer = this.peers.get(peerId);
    if (!peer) {
      peer = { active: ZERO(), queue: [], scheduled: false };
      this.peers.set(peerId, peer);
    }
    return peer;
  }

  private principal(principalId: string): PrincipalState {
    let principal = this.principals.get(principalId);
    if (!principal) {
      principal = { active: ZERO(), queued: 0 };
      this.principals.set(principalId, principal);
    }
    return principal;
  }

  private schedule(peerId: string, peer: PeerState): void {
    if (peer.scheduled) return;
    peer.scheduled = true;
    this.ready.push(peerId);
  }

  private compactOwner(
    peerId: string,
    peer: PeerState,
    principalId?: string,
    principal?: PrincipalState
  ): void {
    if (peer.queue.length === 0 && empty(peer.active)) this.peers.delete(peerId);
    if (principalId !== undefined && principal && principal.queued === 0 && empty(principal.active)) {
      this.principals.delete(principalId);
    }
  }

  private assertOpen(): void {
    if (this.closed) throw this.closed;
  }

  private notifyIdle(): void {
    if (this.queued === 0 && this.leases.size === 0) {
      for (const resolve of this.idleWaiters) resolve();
      this.idleWaiters.clear();
    }
    for (const waiter of [...this.ownerIdleWaiters]) {
      if (!this.isOwnerIdle(waiter.owner)) continue;
      this.ownerIdleWaiters.delete(waiter);
      waiter.resolve();
    }
  }

  private isOwnerIdle(owner: Readonly<ResourceOwner>): boolean {
    const peer = this.peers.get(owner.peerId);
    if (!peer) return true;
    if (owner.principalId === undefined) {
      return peer.queue.length === 0 && empty(peer.active);
    }
    if (peer.queue.some((waiter) => waiter.principalId === owner.principalId)) return false;
    for (const lease of this.leases) {
      if (lease.peerId === owner.peerId && lease.principalId === owner.principalId) return false;
    }
    return true;
  }
}

export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = Object.freeze({
  global: Object.freeze({ handshakes: 32, streams: 256, outboundTransfers: 16, inboundTransfers: 16, bufferedBytes: 128 * 1024 * 1024, callbacks: 128, queued: 128 }),
  perPeer: Object.freeze({ handshakes: 1, streams: 32, outboundTransfers: 4, inboundTransfers: 4, bufferedBytes: 32 * 1024 * 1024, callbacks: 16, queued: 16 }),
  perPrincipal: Object.freeze({ handshakes: 32, streams: 64, outboundTransfers: 8, inboundTransfers: 8, bufferedBytes: 64 * 1024 * 1024, callbacks: 32, queued: 32 }),
  fileDataReserve: Object.freeze({
    global: fileDataReserve(4 * 1024 * 1024 + 64 * 1024),
    perPeer: fileDataReserve(4 * 1024 * 1024 + 64 * 1024),
    perPrincipal: fileDataReserve(4 * 1024 * 1024 + 64 * 1024)
  }),
  fileControlReserve: Object.freeze({
    global: fileDataReserve(1024 * 1024),
    perPeer: fileDataReserve(1024 * 1024),
    perPrincipal: fileDataReserve(1024 * 1024)
  }),
  generalReserve: Object.freeze({
    global: Object.freeze({ streams: 1, bufferedBytes: 1024 * 1024 }),
    perPeer: Object.freeze({ streams: 1, bufferedBytes: 1024 * 1024 }),
    perPrincipal: Object.freeze({ streams: 1, bufferedBytes: 1024 * 1024 })
  })
});

function normalizeOwner(value: string | ResourceOwner): Readonly<ResourceOwner> {
  const peerId = typeof value === 'string' ? value : value?.peerId;
  const principalId = typeof value === 'string' ? undefined : value?.principalId;
  if (!validOwnerId(peerId)) throw new P2PError('INVALID_FRAME', 'Invalid resource peer ID');
  if (principalId !== undefined && !validOwnerId(principalId)) {
    throw new P2PError('INVALID_FRAME', 'Invalid resource principal ID');
  }
  return Object.freeze({ peerId, ...(principalId !== undefined ? { principalId } : {}) });
}

function validOwnerId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= 2048;
}

function normalizeRequest(input: ResourceRequest): ResourceCounter {
  const output = {
    handshakes: input.handshakes ?? 0,
    streams: input.streams ?? 0,
    outboundTransfers: input.outboundTransfers ?? 0,
    inboundTransfers: input.inboundTransfers ?? 0,
    bufferedBytes: input.bufferedBytes ?? 0,
    callbacks: input.callbacks ?? 0,
    outboundFileDataStreams: input.fileData === 'outbound' ? input.streams ?? 0 : 0,
    inboundFileDataStreams: input.fileData === 'inbound' ? input.streams ?? 0 : 0,
    outboundFileDataBufferedBytes: input.fileData === 'outbound' ? input.bufferedBytes ?? 0 : 0,
    inboundFileDataBufferedBytes: input.fileData === 'inbound' ? input.bufferedBytes ?? 0 : 0,
    outboundFileControlStreams: input.fileControl === 'outbound' ? input.streams ?? 0 : 0,
    inboundFileControlStreams: input.fileControl === 'inbound' ? input.streams ?? 0 : 0,
    outboundFileControlBufferedBytes: input.fileControl === 'outbound' ? input.bufferedBytes ?? 0 : 0,
    inboundFileControlBufferedBytes: input.fileControl === 'inbound' ? input.bufferedBytes ?? 0 : 0
  };
  for (const [name, value] of Object.entries(output)) {
    if (!Number.isSafeInteger(value) || value < 0) throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} resource request`);
  }
  if (input.fileData !== undefined && input.fileData !== 'outbound' && input.fileData !== 'inbound') {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid file-data resource class');
  }
  if (input.fileControl !== undefined && input.fileControl !== 'outbound' && input.fileControl !== 'inbound') {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid file-control resource class');
  }
  if (input.fileControl !== undefined && input.fileData !== undefined) {
    throw new P2PError('RESOURCE_LIMIT', 'A stream cannot be both file control and file data');
  }
  if (input.fileControl !== undefined && ((input.streams ?? 0) === 0 || (input.bufferedBytes ?? 0) === 0)) {
    throw new P2PError('RESOURCE_LIMIT', 'File-control admission must reserve a stream and buffered bytes');
  }
  if (input.fileData !== undefined && ((input.streams ?? 0) === 0 || (input.bufferedBytes ?? 0) === 0)) {
    throw new P2PError('RESOURCE_LIMIT', 'File-data admission must reserve a stream and buffered bytes');
  }
  if (empty(output)) throw new P2PError('RESOURCE_LIMIT', 'Resource request must reserve at least one resource');
  return output;
}

function validateLimits(limits: ResourceLimits): void {
  for (const level of [limits.global, limits.perPeer, limits.perPrincipal]) {
    for (const [name, value] of Object.entries(level)) {
      if (!Number.isSafeInteger(value) || value < 1) throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} resource limit`);
    }
  }
  for (const name of ['handshakes', 'streams', 'outboundTransfers', 'inboundTransfers', 'bufferedBytes', 'callbacks', 'queued'] as const) {
    if (limits.perPeer[name] > limits.global[name]) throw new P2PError('RESOURCE_LIMIT', `Per-peer ${name} exceeds global limit`);
    if (limits.perPrincipal[name] > limits.global[name]) {
      throw new P2PError('RESOURCE_LIMIT', `Per-principal ${name} exceeds global limit`);
    }
  }
  for (const [name, level, dataReserve, controlReserve, generalReserve] of [
    [
      'global', limits.global, limits.fileDataReserve.global,
      limits.fileControlReserve.global, limits.generalReserve.global
    ],
    [
      'per-peer', limits.perPeer, limits.fileDataReserve.perPeer,
      limits.fileControlReserve.perPeer, limits.generalReserve.perPeer
    ],
    [
      'per-principal', limits.perPrincipal, limits.fileDataReserve.perPrincipal,
      limits.fileControlReserve.perPrincipal, limits.generalReserve.perPrincipal
    ]
  ] as const) {
    for (const [kind, reserve] of [['file-data', dataReserve], ['file-control', controlReserve]] as const) {
      for (const [direction, capacity] of Object.entries(reserve)) {
        if (!Number.isSafeInteger(capacity.streams) || capacity.streams < 1) {
          throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} ${direction} ${kind} stream reserve`);
        }
        if (!Number.isSafeInteger(capacity.bufferedBytes) || capacity.bufferedBytes < 1) {
          throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} ${direction} ${kind} buffer reserve`);
        }
      }
    }
    for (const [field, value] of Object.entries(generalReserve)) {
      if (!Number.isSafeInteger(value) || value < 1) {
        throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} general ${field} reserve`);
      }
    }
    if (
      reserveTotal(dataReserve, 'streams') +
      reserveTotal(controlReserve, 'streams') +
      generalReserve.streams > level.streams
    ) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} stream reserves`);
    }
    if (
      reserveTotal(dataReserve, 'bufferedBytes') +
      reserveTotal(controlReserve, 'bufferedBytes') +
      generalReserve.bufferedBytes >
      level.bufferedBytes
    ) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid ${name} buffer reserves`);
    }
  }
}

function fits(
  active: ResourceCounter,
  request: ResourceCounter,
  limit: ResourceLimit,
  dataReserve: FileDataReserve,
  controlReserve: FileDataReserve,
  generalReserve: ResourceCapacity
): boolean {
  const nextStreams = active.streams + request.streams;
  const nextOutboundStreams = active.outboundFileDataStreams + request.outboundFileDataStreams;
  const nextInboundStreams = active.inboundFileDataStreams + request.inboundFileDataStreams;
  const nextOutboundControlStreams = active.outboundFileControlStreams + request.outboundFileControlStreams;
  const nextInboundControlStreams = active.inboundFileControlStreams + request.inboundFileControlStreams;
  const nextGeneralStreams = nextStreams - nextOutboundStreams - nextInboundStreams -
    nextOutboundControlStreams - nextInboundControlStreams;
  const nextBufferedBytes = active.bufferedBytes + request.bufferedBytes;
  const nextOutboundBufferedBytes = active.outboundFileDataBufferedBytes + request.outboundFileDataBufferedBytes;
  const nextInboundBufferedBytes = active.inboundFileDataBufferedBytes + request.inboundFileDataBufferedBytes;
  const nextOutboundControlBufferedBytes = active.outboundFileControlBufferedBytes + request.outboundFileControlBufferedBytes;
  const nextInboundControlBufferedBytes = active.inboundFileControlBufferedBytes + request.inboundFileControlBufferedBytes;
  const nextGeneralBufferedBytes = nextBufferedBytes - nextOutboundBufferedBytes - nextInboundBufferedBytes -
    nextOutboundControlBufferedBytes - nextInboundControlBufferedBytes;
  const streamReserves = reserveTotal(dataReserve, 'streams') + reserveTotal(controlReserve, 'streams');
  const bufferReserves = reserveTotal(dataReserve, 'bufferedBytes') + reserveTotal(controlReserve, 'bufferedBytes');
  // Each directional class owns only its configured reserve. All use above a
  // class reserve is summed into one borrowable pool; it can compete with
  // active general work but cannot spend the protected general reserve.
  // Pairwise checks are insufficient because deficits in two idle classes can
  // otherwise hide simultaneous overflow and spend the same capacity twice.
  const fileStreamOverflow =
    overflow(nextOutboundStreams, dataReserve.outbound.streams) +
    overflow(nextInboundStreams, dataReserve.inbound.streams) +
    overflow(nextOutboundControlStreams, controlReserve.outbound.streams) +
    overflow(nextInboundControlStreams, controlReserve.inbound.streams);
  const sharedStreamUse = nextGeneralStreams + fileStreamOverflow;
  const fileBufferOverflow =
    overflow(nextOutboundBufferedBytes, dataReserve.outbound.bufferedBytes) +
    overflow(nextInboundBufferedBytes, dataReserve.inbound.bufferedBytes) +
    overflow(nextOutboundControlBufferedBytes, controlReserve.outbound.bufferedBytes) +
    overflow(nextInboundControlBufferedBytes, controlReserve.inbound.bufferedBytes);
  const sharedBufferUse = nextGeneralBufferedBytes + fileBufferOverflow;
  return active.handshakes + request.handshakes <= limit.handshakes &&
    nextStreams <= limit.streams &&
    sharedStreamUse <= limit.streams - streamReserves &&
    fileStreamOverflow <= limit.streams - streamReserves - generalReserve.streams &&
    active.outboundTransfers + request.outboundTransfers <= limit.outboundTransfers &&
    active.inboundTransfers + request.inboundTransfers <= limit.inboundTransfers &&
    nextBufferedBytes <= limit.bufferedBytes &&
    sharedBufferUse <= limit.bufferedBytes - bufferReserves &&
    fileBufferOverflow <= limit.bufferedBytes - bufferReserves - generalReserve.bufferedBytes &&
    active.callbacks + request.callbacks <= limit.callbacks;
}

function overflow(usage: number, reserve: number): number {
  return Math.max(0, usage - reserve);
}

function add(target: ResourceCounter, value: ResourceCounter, direction: 1 | -1): void {
  target.handshakes += direction * value.handshakes;
  target.streams += direction * value.streams;
  target.outboundTransfers += direction * value.outboundTransfers;
  target.inboundTransfers += direction * value.inboundTransfers;
  target.bufferedBytes += direction * value.bufferedBytes;
  target.callbacks += direction * value.callbacks;
  target.outboundFileDataStreams += direction * value.outboundFileDataStreams;
  target.inboundFileDataStreams += direction * value.inboundFileDataStreams;
  target.outboundFileDataBufferedBytes += direction * value.outboundFileDataBufferedBytes;
  target.inboundFileDataBufferedBytes += direction * value.inboundFileDataBufferedBytes;
  target.outboundFileControlStreams += direction * value.outboundFileControlStreams;
  target.inboundFileControlStreams += direction * value.inboundFileControlStreams;
  target.outboundFileControlBufferedBytes += direction * value.outboundFileControlBufferedBytes;
  target.inboundFileControlBufferedBytes += direction * value.inboundFileControlBufferedBytes;
}

function empty(value: ResourceCounter): boolean {
  return value.handshakes === 0 && value.streams === 0 && value.outboundTransfers === 0 && value.inboundTransfers === 0 && value.bufferedBytes === 0 && value.callbacks === 0;
}

function publicAmounts(value: ResourceCounter): ResourceAmounts {
  return {
    handshakes: value.handshakes,
    streams: value.streams,
    outboundTransfers: value.outboundTransfers,
    inboundTransfers: value.inboundTransfers,
    bufferedBytes: value.bufferedBytes,
    callbacks: value.callbacks
  };
}

function fileDataReserve(bufferedBytes: number): FileDataReserve {
  return Object.freeze({
    outbound: Object.freeze({ streams: 1, bufferedBytes }),
    inbound: Object.freeze({ streams: 1, bufferedBytes })
  });
}

function reserveTotal(reserve: FileDataReserve, field: keyof ResourceCapacity): number {
  return reserve.outbound[field] + reserve.inbound[field];
}
