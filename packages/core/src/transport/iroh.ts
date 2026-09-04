import { createPrivateKey, randomBytes, sign as signBytes } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { createNode, PublicKey, type IrohNode, type NodeOptions } from '@momics/iroh-http-node';
import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';
import { createRelaylessIrohNode } from './iroh-relayless-networking.js';
import {
  consumeIrohWriterCleanupProof,
  installIrohWriterCleanup
} from './iroh-writer-cleanup.js';
import type {
  ConnectionStats,
  ConnectionPath,
  EndpointAddress,
  EndpointDiagnostics,
  EndpointDiscoveryEvent,
  EndpointDiscoveryOptions,
  EndpointLocator,
  QuicBiStream,
  QuicConnection,
  QuicEndpoint,
  QuicRecvStream,
  QuicSendStream,
  StreamLifecycleStats
} from './types.js';

export type IrohRelayConfiguration =
  | { readonly mode: 'default' }
  | { readonly mode: 'disabled' }
  | { readonly mode: 'custom'; readonly urls: readonly string[] };

export interface IrohDiscoveryConfiguration {
  /**
   * Endpoint-wide Iroh DNS/PKARR lookup. Disabled unless explicitly enabled.
   * When enabled, native Iroh may use it as fallback for any dial, including
   * one initially supplied signed-ticket or mDNS route hints.
   */
  readonly dns?: boolean | { readonly serverUrl?: string };
  /** LAN mDNS lookup/advertisement. Disabled unless explicitly enabled. */
  readonly mdns?: boolean | {
    readonly serviceName?: string;
    /** Advertise this endpoint for its lifetime. Defaults to true. */
    readonly advertise?: boolean;
  };
}

export interface IrohEndpointOptions {
  readonly secretKey?: Uint8Array;
  readonly bindAddress?: string | readonly string[];
  readonly relay?: IrohRelayConfiguration;
  readonly discovery?: IrohDiscoveryConfiguration;
  /** @deprecated Use `relay`. */
  readonly relayMode?: 'default' | 'disabled';
  /** @deprecated Use `relay: { mode: 'custom', urls }`. */
  readonly relayUrls?: readonly string[];
  /** Lifetime of each freshly generated signed locator ticket. Defaults to 24 hours. */
  readonly ticketTtlMs?: number;
  /** Filter local addresses before publishing them in signed tickets. */
  readonly allowAdvertisedAddress?: (address: string) => boolean;
  /**
   * Required egress policy for signed-ticket direct-address candidates.
   * Without one, a ticket containing direct routes is rejected before dial.
   * Unsigned mDNS candidates default to private, link-local, and loopback
   * ranges, although enterprise deployments should supply a narrower policy.
   * Cannot be combined with endpoint-wide DNS because the pinned wrapper does
   * not expose DNS-resolved candidates before dialing them.
   */
  readonly allowDirectAddress?: (address: string) => boolean;
  /**
   * Egress policy for untrusted mDNS or signed-ticket relay candidates.
   * Default-relay signed-ticket hints require it; custom-relay membership is
   * itself an explicit allowlist. Local/default relay selection and explicit
   * custom relay configuration are deployment inputs, not remote candidates.
   * Membership and disabled-relay rejection cannot be overridden.
   */
  readonly allowRelayUrl?: (origin: string) => boolean;
}

interface TicketPayload {
  readonly version: 3;
  readonly peerId: string;
  readonly directAddresses: string[];
  readonly relayUrl: string | null;
  readonly protocol: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

interface RelayEgressPolicy {
  readonly mode: IrohRelayConfiguration['mode'];
  readonly customOrigins: ReadonlySet<string>;
}

type RelayCandidateSource = 'local' | 'ticket' | 'mdns';

type IrohSession = Awaited<ReturnType<IrohNode['dial']>>;

const TICKET_SIGNATURE_DOMAIN = Buffer.from('p2prpc-signed-ticket-v3\0', 'utf8');
const DISCOVERY_CLEANUP_TIMEOUT_MS = 1_000;

/** @internal Exported only for transport lifecycle conformance tests. */
export class WebSendStream implements QuicSendStream {
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;
  private readonly lifecycleScope: SendLifecycleScope;
  private terminal?: Promise<void>;
  private activeWrite: Promise<void> | undefined;
  private writeFailed = false;
  private provenWriteFailure: unknown;
  private hasProvenWriteFailure = false;

  constructor(
    stream: WritableStream<Uint8Array>,
    lifecycle: StreamLifecycle
  ) {
    this.writer = stream.getWriter();
    this.lifecycleScope = lifecycle.openSend();
  }

  async writeAll(data: Uint8Array): Promise<void> {
    if (this.terminal) throw new P2PError('CANCELLED', 'Stream send side is already closed');
    if (this.hasProvenWriteFailure) throw this.provenWriteFailure;
    const writing = this.writer.write(data);
    this.activeWrite = writing;
    try {
      await writing;
    } catch (cause) {
      // Once a WHATWG writable is errored, a later abort may fulfill without
      // invoking the underlying sink. The pinned Iroh compatibility seam tries
      // native cleanup on write failure, but deliberately cannot claim it
      // succeeded. Only physical connection closure is proof in that case.
      this.writeFailed = true;
      const proof = consumeIrohWriterCleanupProof(cause);
      if (proof.terminal) {
        // The pinned adapter synchronously finalized this exact opaque writer
        // handle before rethrowing. Account terminality now; a later WHATWG
        // abort is a no-op on an errored stream and carries no proof itself.
        this.hasProvenWriteFailure = true;
        this.provenWriteFailure = proof.cause;
        this.lifecycleScope.settle('reset');
        try { this.writer.releaseLock(); } catch { /* native terminality is already proven */ }
      }
      throw proof.cause;
    } finally {
      if (this.activeWrite === writing) this.activeWrite = undefined;
    }
  }

  async finish(): Promise<void> {
    if (this.hasProvenWriteFailure) throw this.provenWriteFailure;
    this.terminal ??= this.terminalize('finish');
    await this.terminal;
  }

  async reset(): Promise<void> {
    // A cancellation can race the adapter's sendChunk rejection. Wait for the
    // started native write to expose its terminal proof before asking WHATWG
    // to abort; otherwise the queued abort can call finishBody a second time
    // and turn known cleanup into a false quarantine.
    const writing = this.activeWrite;
    if (writing) await writing.catch(() => undefined);
    if (this.hasProvenWriteFailure) return;
    this.terminal ??= this.terminalize('reset');
    await this.terminal;
  }

  async setPriority(priority: number): Promise<void> {
    // WebTransport's stream priority API is not yet exposed by iroh-http.
    void priority;
  }

  private async terminalize(mode: 'finish' | 'reset'): Promise<void> {
    try {
      if (mode === 'finish') await this.writer.close();
      else await this.writer.abort(new P2PError('CANCELLED', 'Stream reset'));
      if (this.writeFailed && !this.hasProvenWriteFailure) {
        // WHATWG abort of an already-errored stream may fulfill without calling
        // the native sink. Propagate uncertainty so ManagedConnection retains
        // its admission lease and the caller quarantines this connection.
        throw new P2PError('INTERNAL', 'Native send cleanup requires physical connection closure');
      }
      this.lifecycleScope.settle(mode);
    } finally {
      // Releasing a JS lock is not native terminal proof and must not replace
      // the close/abort outcome if a defective stream implementation throws.
      try { this.writer.releaseLock(); } catch { /* diagnostic scope remains fail-closed */ }
    }
  }
}

/** @internal Exported only for transport lifecycle conformance tests. */
export class WebRecvStream implements QuicRecvStream {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private readonly lifecycleScope: RecvLifecycleScope;
  private buffered: Uint8Array<ArrayBufferLike> = new Uint8Array();
  private terminal?: Promise<void>;
  private released = false;

  constructor(
    stream: ReadableStream<Uint8Array>,
    lifecycle: StreamLifecycle
  ) {
    this.reader = stream.getReader();
    this.lifecycleScope = lifecycle.openRecv();
  }

  async readExact(size: number): Promise<Uint8Array> {
    if (this.terminal) throw new P2PError('CANCELLED', 'Stream receive side is already closed');
    if (!Number.isSafeInteger(size) || size < 0 || size > 0xffff_ffff) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid read size: ${size}`);
    }
    if (size === 0) return new Uint8Array();
    const result = new Uint8Array(size);
    let offset = 0;
    while (offset < size) {
      if (this.buffered.byteLength === 0) {
        const next = await this.reader.read();
        if (next.done) {
          await this.release('eof');
          throw new P2PError('DISCONNECTED', `Stream ended with ${size - offset} bytes remaining`);
        }
        this.buffered = next.value;
      }
      const count = Math.min(size - offset, this.buffered.byteLength);
      result.set(this.buffered.subarray(0, count), offset);
      // Do not retain an exhausted native chunk's backing allocation for the
      // remaining stream lifetime through a zero-length subarray view.
      this.buffered = count === this.buffered.byteLength
        ? new Uint8Array()
        : this.buffered.subarray(count);
      offset += count;
    }
    return result;
  }

  async expectEnd(): Promise<void> {
    this.terminal ??= this.expectCleanEnd();
    await this.terminal;
  }

  async stop(): Promise<void> {
    // readExact() releases its native reader when it observes premature EOF.
    // That path is already physically terminal even though it did not begin a
    // terminal operation. Treat later defensive cleanup as idempotent instead
    // of cancelling a detached WHATWG reader and quarantining a healthy QUIC
    // connection on ERR_INVALID_STATE.
    if (this.released) return;
    this.terminal ??= this.cancel();
    await this.terminal;
  }

  private async expectCleanEnd(): Promise<void> {
    try {
      if (this.buffered.byteLength > 0) {
        throw new P2PError('INVALID_FRAME', 'Stream contains trailing bytes');
      }
      while (true) {
        const next = await this.reader.read();
        if (next.done) {
          await this.release('eof');
          return;
        }
        if (next.value.byteLength > 0) {
          throw new P2PError('INVALID_FRAME', 'Stream contains trailing bytes');
        }
      }
    } catch (cause) {
      try {
        await this.reader.cancel(new P2PError('CANCELLED', 'Invalid stream ending'));
        await this.release('stop');
      } catch {
        // Preserve the framing failure. A rejected cancel is not native
        // terminal proof; connection closure will settle diagnostics.
        try { this.reader.releaseLock(); } catch { /* best-effort JS cleanup */ }
      }
      throw cause;
    }
  }

  private async cancel(): Promise<void> {
    try {
      await this.reader.cancel(new P2PError('CANCELLED', 'Stream stopped'));
      await this.release('stop');
    } catch (cause) {
      try { this.reader.releaseLock(); } catch { /* best-effort JS cleanup */ }
      throw cause;
    }
  }

  private async release(mode: 'eof' | 'stop'): Promise<void> {
    if (this.released) return;
    this.released = true;
    try { this.reader.releaseLock(); } catch { /* native terminality is already proven */ }
    this.lifecycleScope.settle(mode);
  }
}

interface MutableStreamLifecycleStats {
  openedBi: number;
  acceptedBi: number;
  openedUni: number;
  acceptedUni: number;
  activeSend: number;
  activeRecv: number;
  sendFinished: number;
  sendReset: number;
  recvEof: number;
  recvStopped: number;
}

interface SendLifecycleScope {
  settle(mode: 'finish' | 'reset'): void;
}

interface RecvLifecycleScope {
  settle(mode: 'eof' | 'stop'): void;
}

/**
 * Connection-owned native-half ledger. A rejected stream terminal operation
 * stays active until fulfilled session closure proves every native half gone.
 */
/** @internal Exported only for transport lifecycle conformance tests. */
export class StreamLifecycle {
  private readonly counters = emptyStreamStats();
  private readonly sends = new Set<object>();
  private readonly recvs = new Set<object>();
  private physicallyClosed = false;

  recordOpenedBi(): void { this.counters.openedBi += 1; }
  recordAcceptedBi(): void { this.counters.acceptedBi += 1; }
  recordOpenedUni(): void { this.counters.openedUni += 1; }
  recordAcceptedUni(): void { this.counters.acceptedUni += 1; }

  openSend(): SendLifecycleScope {
    const token = Object.freeze({});
    if (this.physicallyClosed) {
      this.counters.sendReset += 1;
      return Object.freeze({ settle: () => undefined });
    }
    this.sends.add(token);
    this.counters.activeSend += 1;
    return Object.freeze({
      settle: (mode: 'finish' | 'reset'): void => {
        if (!this.sends.delete(token)) return;
        this.counters.activeSend -= 1;
        if (mode === 'finish') this.counters.sendFinished += 1;
        else this.counters.sendReset += 1;
      }
    });
  }

  openRecv(): RecvLifecycleScope {
    const token = Object.freeze({});
    if (this.physicallyClosed) {
      this.counters.recvStopped += 1;
      return Object.freeze({ settle: () => undefined });
    }
    this.recvs.add(token);
    this.counters.activeRecv += 1;
    return Object.freeze({
      settle: (mode: 'eof' | 'stop'): void => {
        if (!this.recvs.delete(token)) return;
        this.counters.activeRecv -= 1;
        if (mode === 'eof') this.counters.recvEof += 1;
        else this.counters.recvStopped += 1;
      }
    });
  }

  closePhysical(): void {
    if (this.physicallyClosed) return;
    this.physicallyClosed = true;
    const activeSend = this.sends.size;
    const activeRecv = this.recvs.size;
    this.sends.clear();
    this.recvs.clear();
    this.counters.activeSend -= activeSend;
    this.counters.activeRecv -= activeRecv;
    this.counters.sendReset += activeSend;
    this.counters.recvStopped += activeRecv;
  }

  snapshot(): StreamLifecycleStats {
    return Object.freeze({ ...this.counters });
  }
}

function emptyStreamStats(): MutableStreamLifecycleStats {
  return {
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
  };
}

/** @internal Exported only for transport lifecycle conformance tests. */
export class WebSessionConnection implements QuicConnection {
  readonly remoteId: string;
  readonly connectionId = randomBytes(16).toString('hex');
  private readonly incomingBi: ReadableStreamDefaultReader<Awaited<ReturnType<IrohSession['createBidirectionalStream']>>>;
  private readonly incomingUni: ReadableStreamDefaultReader<ReadableStream<Uint8Array>>;
  private readonly lifecycle = new StreamLifecycle();
  private readonly physicalClosure: IrohSession['closed'];

  constructor(
    private readonly session: IrohSession,
    private readonly node: IrohNode,
    readonly side: 'client' | 'server'
  ) {
    this.remoteId = session.remoteId.toString();
    this.incomingBi = session.incomingBidirectionalStreams.getReader();
    this.incomingUni = session.incomingUnidirectionalStreams.getReader();
    this.physicalClosure = session.closed;
    // Fulfillment is the only adapter-level proof that every native stream is
    // terminal. Rejection deliberately leaves diagnostics non-quiescent.
    void this.physicalClosure.then(
      () => this.lifecycle.closePhysical(),
      () => undefined
    );
  }

  async openBi(): Promise<QuicBiStream> {
    const stream = await this.session.createBidirectionalStream();
    this.lifecycle.recordOpenedBi();
    return {
      send: new WebSendStream(stream.writable, this.lifecycle),
      recv: new WebRecvStream(stream.readable, this.lifecycle)
    };
  }

  async acceptBi(): Promise<QuicBiStream> {
    const result = await this.incomingBi.read();
    if (result.done) throw new P2PError('DISCONNECTED', 'Connection closed while accepting a stream');
    this.lifecycle.recordAcceptedBi();
    return {
      send: new WebSendStream(result.value.writable, this.lifecycle),
      recv: new WebRecvStream(result.value.readable, this.lifecycle)
    };
  }

  async openUni(): Promise<QuicSendStream> {
    const stream = await this.session.createUnidirectionalStream();
    this.lifecycle.recordOpenedUni();
    return new WebSendStream(stream, this.lifecycle);
  }

  async acceptUni(): Promise<QuicRecvStream> {
    const result = await this.incomingUni.read();
    if (result.done) throw new P2PError('DISCONNECTED', 'Connection closed while accepting a stream');
    this.lifecycle.recordAcceptedUni();
    return new WebRecvStream(result.value, this.lifecycle);
  }

  async closed(): Promise<string> {
    const info = await this.physicalClosure;
    return info.reason;
  }

  close(code: bigint, reason: Uint8Array): void {
    this.session.close({ closeCode: Number(code), reason: new TextDecoder().decode(reason) });
  }

  async stats(): Promise<ConnectionStats> {
    const stats = await this.node.peerStats(this.remoteId);
    return {
      connectionId: this.connectionId,
      rttMs: stats?.rttMs ?? null,
      sentBytes: stats?.bytesSent ?? 0,
      receivedBytes: stats?.bytesReceived ?? 0,
      lostPackets: stats?.lostPackets ?? 0,
      sentPackets: stats?.sentPackets ?? null,
      congestionWindow: stats?.congestionWindow ?? null,
      relay: stats?.relay ?? null,
      relayUrl: stats?.relayUrl ?? null,
      paths: Object.freeze((stats?.paths ?? []).map((path) => Object.freeze({
        relay: path.relay,
        address: path.addr,
        active: path.active
      }))),
      streams: this.lifecycle.snapshot()
    };
  }

  async *pathChanges(signal?: AbortSignal): AsyncIterable<ConnectionPath> {
    const cleanupController = new AbortController();
    const subscriptionSignal = signal
      ? AbortSignal.any([signal, cleanupController.signal])
      : cleanupController.signal;
    const iterator = this.node.pathChanges(this.remoteId, { signal: subscriptionSignal })[Symbol.asyncIterator]();
    try {
      while (true) {
        const path = await abortable(iterator.next(), subscriptionSignal);
        if (path.done) return;
        yield Object.freeze({
          relay: path.value.relay,
          address: path.value.addr,
          active: path.value.active
        });
      }
    } finally {
      cleanupController.abort(new P2PError('CANCELLED', 'Path subscription completed'));
      await closeAsyncIterator(iterator, DISCOVERY_CLEANUP_TIMEOUT_MS);
    }
  }

}

export class IrohEndpoint implements QuicEndpoint {
  readonly id: string;
  private incoming: AsyncIterator<IrohSession>;
  private locator: Omit<TicketPayload, 'issuedAt' | 'expiresAt'>;

  private constructor(
    private readonly node: IrohNode,
    private readonly protocol: string,
    locator: Omit<TicketPayload, 'issuedAt' | 'expiresAt'>,
    private readonly ticketKey: Uint8Array,
    private readonly ticketTtlMs: number,
    private readonly dnsEnabled: boolean,
    private readonly mdnsEnabled: boolean,
    private readonly mdnsServiceName: string | undefined,
    private readonly relayEgressPolicy: RelayEgressPolicy,
    private readonly allowAdvertisedAddress?: (address: string) => boolean,
    private readonly allowDirectAddress?: (address: string) => boolean,
    private readonly allowRelayUrl?: (origin: string) => boolean
  ) {
    this.id = node.publicKey.toString();
    this.locator = locator;
    this.incoming = node.incoming()[Symbol.asyncIterator]();
  }

  get address(): EndpointAddress {
    const issuedAt = Date.now();
    return {
      id: this.id,
      ticket: encodeTicket({ ...this.locator, issuedAt, expiresAt: issuedAt + this.ticketTtlMs }, this.ticketKey)
    };
  }

  async createTicket(): Promise<string> {
    const discovery = await this.node.discoveryInfo();
    const locator = Object.freeze({
      version: 3,
      peerId: this.id,
      directAddresses: filterAdvertisedAddresses(discovery.directAddresses, this.allowAdvertisedAddress),
      relayUrl: discovery.relayUrl === null
        ? null
        : validateRelayCandidate(discovery.relayUrl, this.relayEgressPolicy, 'local'),
      protocol: this.protocol
    } satisfies Omit<TicketPayload, 'issuedAt' | 'expiresAt'>);
    this.locator = locator;
    return this.address.ticket;
  }

  static async create(alpn: Uint8Array, options: IrohEndpointOptions = {}): Promise<IrohEndpoint> {
    validateIrohOptions(options);
    const ticketTtlMs = options.ticketTtlMs === undefined ? 24 * 60 * 60_000 : options.ticketTtlMs;
    if (!Number.isSafeInteger(ticketTtlMs) || ticketTtlMs < 60_000 || ticketTtlMs > 30 * 24 * 60 * 60_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Ticket lifetime must be between one minute and 30 days');
    }
    const secretKey = options.secretKey === undefined ? randomBytes(32) : Uint8Array.from(options.secretKey);
    if (secretKey.byteLength !== 32) throw new P2PError('INVALID_FRAME', 'Iroh secret key must be 32 bytes');
    const relay = resolveRelayConfiguration(options);
    const relayUrls = relay.mode === 'custom'
      ? normalizeConfiguredRelayUrls(relay.urls)
      : undefined;
    const relayEgressPolicy: RelayEgressPolicy = Object.freeze({
      mode: relay.mode,
      customOrigins: new Set(relayUrls?.map((value) => new URL(value).origin) ?? [])
    });
    const discoveryOptions = resolveDiscoveryConfiguration(options.discovery);
    if (
      discoveryOptions.dns !== false &&
      (
        relay.mode === 'custom' ||
        options.allowDirectAddress !== undefined ||
        options.allowRelayUrl !== undefined
      )
    ) {
      throw new P2PError(
        'UNAUTHORIZED',
        'DNS/PKARR discovery cannot satisfy restricted resolved-route egress policy'
      );
    }
    const nodeOptions: NodeOptions = {
      relay: relayUrls
        ? { urls: relayUrls }
        : { mode: relay.mode },
      discovery: {
        dns: discoveryOptions.dns,
        mdns: false
      },
      internals: {
        maxChunkSizeBytes: 1024 * 1024,
        // iroh-http's blanket slab sweep includes live WebTransport session
        // handles. Session lookups do not refresh the slab timestamp, so its
        // five-minute default removes an otherwise healthy connection on the
        // next one-minute sweep. Long-running RPC subscriptions then end at
        // six minutes and every later stream open fails with "unknown handle".
        //
        // p2prpc already owns every native stream half until explicit terminal
        // cleanup or fulfilled physical connection closure. Disable the lower
        // layer's time-based reclamation so transport resources follow those
        // lifecycle proofs instead of wall-clock age.
        handleTtl: 0
      },
      key: secretKey
    };
    if (options.bindAddress) nodeOptions.bindAddr = typeof options.bindAddress === 'string'
      ? options.bindAddress
      : [...options.bindAddress];
    // Keep compatibility hardening at the actual native construction boundary.
    // This remains effective even when a consumer tree-shakes module side effects.
    installIrohWriterCleanup(PublicKey);
    const node = await (relay.mode === 'disabled'
      ? createRelaylessIrohNode(createNode, PublicKey, nodeOptions)
      : createNode(nodeOptions));
    try {
      const discovery = await node.discoveryInfo();
      const protocol = Buffer.from(alpn).toString('base64url');
      const locator: Omit<TicketPayload, 'issuedAt' | 'expiresAt'> = {
        version: 3,
        peerId: node.publicKey.toString(),
        directAddresses: filterAdvertisedAddresses(discovery.directAddresses, options.allowAdvertisedAddress),
        relayUrl: discovery.relayUrl === null
          ? null
          : validateRelayCandidate(discovery.relayUrl, relayEgressPolicy, 'local'),
        protocol
      };
      const endpoint = new IrohEndpoint(
        node,
        protocol,
        locator,
        secretKey,
        ticketTtlMs,
        discoveryOptions.dns !== false,
        discoveryOptions.mdnsServiceName !== undefined,
        discoveryOptions.mdnsServiceName,
        relayEgressPolicy,
        options.allowAdvertisedAddress,
        options.allowDirectAddress,
        options.allowRelayUrl
      );
      if (discoveryOptions.mdnsAdvertise && discoveryOptions.mdnsServiceName) {
        await node.advertisePeer({ serviceName: discoveryOptions.mdnsServiceName });
      }
      return endpoint;
    } catch (cause) {
      await node.close().catch(() => undefined);
      throw cause;
    }
  }

  connect(ticket: string, alpn: Uint8Array, expectedPeerId: string): Promise<QuicConnection> {
    return this.connectLocator({ kind: 'ticket', ticket }, alpn, expectedPeerId);
  }

  async connectLocator(
    locator: EndpointLocator,
    alpn: Uint8Array,
    expectedPeerId: string,
    signal?: AbortSignal
  ): Promise<QuicConnection> {
    validateEndpointLocator(locator);
    validateExpectedPeerId(expectedPeerId);
    const parsed = await this.resolveLocator(locator, expectedPeerId, signal);
    const protocol = Buffer.from(alpn).toString('base64url');
    if (protocol !== this.protocol || (parsed.protocol !== undefined && parsed.protocol !== protocol)) {
      throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Peer ticket uses a different application contract');
    }
    signal?.throwIfAborted();
    const pending = this.node.dial(expectedPeerId, {
      ...(parsed.directAddresses.length > 0 ? { directAddrs: parsed.directAddresses } : {}),
      ...(parsed.relayUrl ? { relayUrl: parsed.relayUrl } : {})
    });
    let session: IrohSession | undefined;
    try {
      session = await abortable(pending, signal);
      await abortable(session.ready, signal);
      return new WebSessionConnection(session, this.node, 'client');
    } catch (cause) {
      // Do not let this adapter promise settle while a late native dial can
      // still materialize an unowned session. P2PNode keeps the handshake
      // admission charged to this promise after its public connect deadline;
      // settlement therefore proves either dial rejection or physical close.
      if (session) await closeDialSession(session);
      else await pending.then(closeDialSession, () => undefined);
      throw cause;
    }
  }

  private async resolveLocator(
    locator: EndpointLocator,
    expectedPeerId: string,
    signal?: AbortSignal
  ): Promise<{ directAddresses: string[]; relayUrl: string | null; protocol?: string }> {
    if (locator.kind === 'ticket') {
      const parsed = await decodeTicket(
        locator.ticket,
        this.relayEgressPolicy,
        this.allowDirectAddress,
        this.allowRelayUrl
      );
      if (parsed.peerId !== expectedPeerId) {
        throw new P2PError('UNAUTHORIZED', 'Ticket endpoint does not match the expected peer ID');
      }
      return {
        directAddresses: parsed.directAddresses,
        relayUrl: parsed.relayUrl,
        protocol: parsed.protocol
      };
    }
    if (locator.kind === 'dns') {
      if (!this.dnsEnabled) throw new P2PError('REJECTED', 'DNS/PKARR discovery is not enabled');
      if (this.allowDirectAddress || this.allowRelayUrl) {
        throw new P2PError(
          'UNAUTHORIZED',
          'DNS/PKARR discovery cannot satisfy application-level resolved-route egress policy'
        );
      }
      return { directAddresses: [], relayUrl: null };
    }
    if (!this.mdnsEnabled) throw new P2PError('REJECTED', 'mDNS discovery is not enabled');
    const serviceName = locator.serviceName ?? this.mdnsServiceName ?? 'p2prpc';
    const cleanupController = new AbortController();
    const browseSignal = signal
      ? AbortSignal.any([signal, cleanupController.signal])
      : cleanupController.signal;
    const iterator = this.node.browsePeers({
      serviceName,
      signal: browseSignal
    })[Symbol.asyncIterator]();
    try {
      while (true) {
        const event = await abortable(iterator.next(), browseSignal);
        if (event.done) throw new P2PError('NOT_FOUND', `mDNS peer ${expectedPeerId} was not found`);
        if (!event.value.isActive || event.value.nodeId !== expectedPeerId) continue;
        if (event.value.addrs.length > 33) {
          throw new P2PError('RESOURCE_LIMIT', 'mDNS record has too many route candidates');
        }
        const directCandidates: string[] = [];
        let relayUrl: string | null = null;
        for (const address of event.value.addrs) {
          if (address.startsWith('https://')) {
            const validated = validateRelayCandidate(
              address,
              this.relayEgressPolicy,
              'mdns',
              this.allowRelayUrl
            );
            if (relayUrl !== null && relayUrl !== validated) {
              throw new P2PError('INVALID_FRAME', 'mDNS record has multiple relay candidates');
            }
            relayUrl = validated;
          } else {
            directCandidates.push(address);
          }
        }
        const directAddresses = validateDirectAddresses(
          [...new Set(directCandidates)],
          this.allowDirectAddress ?? allowLanDirectAddress
        );
        if (directAddresses.length === 0 && relayUrl === null) continue;
        return { directAddresses, relayUrl };
      }
    } finally {
      // Native discovery is a subscription. Abort it before asking the
      // iterator to return, and never let a broken adapter make connect()
      // or cancellation wait forever. A timed-out return remains observed;
      // endpoint shutdown is the final native cleanup boundary.
      cleanupController.abort(new P2PError('CANCELLED', 'mDNS lookup completed'));
      await closeAsyncIterator(iterator, DISCOVERY_CLEANUP_TIMEOUT_MS);
    }
  }

  async accept(): Promise<QuicConnection | null> {
    while (true) {
      try {
        const result = await this.incoming.next();
        return result.done ? null : new WebSessionConnection(result.value, this.node, 'server');
      } catch (cause) {
        if (String(cause).includes('accept session: timed out')) {
          // The wrapper documents this timeout as a refresh signal. Do not let
          // a defective old iterator block installation of its replacement.
          void closeAsyncIterator(this.incoming, DISCOVERY_CLEANUP_TIMEOUT_MS);
          this.incoming = this.node.incoming()[Symbol.asyncIterator]();
          continue;
        }
        throw cause;
      }
    }
  }

  async advertise(options: EndpointDiscoveryOptions = {}): Promise<void> {
    if (!this.mdnsEnabled) throw new P2PError('REJECTED', 'mDNS discovery is not enabled');
    validateDiscoveryOptions(options);
    await this.node.advertisePeer({
      serviceName: options.serviceName ?? this.mdnsServiceName ?? 'p2prpc',
      ...(options.signal ? { signal: options.signal } : {})
    });
  }

  async *browse(options: EndpointDiscoveryOptions = {}): AsyncIterable<EndpointDiscoveryEvent> {
    if (!this.mdnsEnabled) throw new P2PError('REJECTED', 'mDNS discovery is not enabled');
    validateDiscoveryOptions(options);
    const cleanupController = new AbortController();
    const browseSignal = options.signal
      ? AbortSignal.any([options.signal, cleanupController.signal])
      : cleanupController.signal;
    const iterator = this.node.browsePeers({
      serviceName: options.serviceName ?? this.mdnsServiceName ?? 'p2prpc',
      signal: browseSignal
    })[Symbol.asyncIterator]();
    try {
      while (true) {
        const event = await abortable(iterator.next(), browseSignal);
        if (event.done) return;
        yield Object.freeze({
          peerId: event.value.nodeId,
          addresses: Object.freeze([...event.value.addrs]),
          active: event.value.isActive
        });
      }
    } finally {
      cleanupController.abort(new P2PError('CANCELLED', 'mDNS browse completed'));
      await closeAsyncIterator(iterator, DISCOVERY_CLEANUP_TIMEOUT_MS);
    }
  }

  async diagnostics(): Promise<EndpointDiagnostics> {
    const stats = await this.node.stats();
    return Object.freeze({ ...stats });
  }

  async close(): Promise<void> {
    const stopIncoming = closeAsyncIterator(this.incoming, DISCOVERY_CLEANUP_TIMEOUT_MS);
    await this.node.close();
    await stopIncoming;
  }
}

async function closeAsyncIterator<T>(iterator: AsyncIterator<T>, timeoutMs: number): Promise<void> {
  const returned = iterator.return;
  if (!returned) return;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const task = Promise.resolve()
    .then(() => returned.call(iterator))
    .then(() => undefined, () => undefined);
  try {
    await Promise.race([
      task,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Cancel a dial result without surrendering ownership before native closure is
 * positively observed. A throwing close() or a rejected/throwing `closed`
 * observation is adapter failure, not evidence that the QUIC session is gone.
 */
async function closeDialSession(opened: IrohSession): Promise<void> {
  try {
    opened.close({ closeCode: 4, reason: 'Dial cancelled' });
  } catch {
    // Still wait for the independent native closure observation below.
  }
  await Promise.resolve()
    .then(() => opened.closed)
    .then(
      () => undefined,
      () => new Promise<void>(() => undefined)
    );
}

function validateIrohOptions(options: IrohEndpointOptions): void {
  if (!isPlainRecord(options as unknown)) throw new P2PError('INVALID_FRAME', 'Iroh options must be a plain object');
  assertOnlyKeys(options, [
    'secretKey',
    'bindAddress',
    'relay',
    'discovery',
    'relayMode',
    'relayUrls',
    'ticketTtlMs',
    'allowAdvertisedAddress',
    'allowDirectAddress',
    'allowRelayUrl'
  ], 'Iroh options');
  if (options.secretKey !== undefined && !(options.secretKey instanceof Uint8Array)) {
    throw new P2PError('INVALID_FRAME', 'Iroh secret key must be a Uint8Array');
  }
  if (options.bindAddress !== undefined) {
    const addresses = Array.isArray(options.bindAddress) ? options.bindAddress : [options.bindAddress];
    if (addresses.length < 1 || addresses.length > 16) {
      throw new P2PError('RESOURCE_LIMIT', 'Configure between one and 16 Iroh bind addresses');
    }
    for (const address of addresses) {
      if (
        typeof address !== 'string' ||
        address.length < 1 ||
        address.length > 512 ||
        address.includes(' ') ||
        containsUnsafeDisplayCharacters(address) ||
        !validSocketAddress(address, true)
      ) {
        throw new P2PError('INVALID_FRAME', 'Iroh bind address is invalid');
      }
    }
  }
  if (
    options.relayMode !== undefined &&
    options.relayMode !== 'default' &&
    options.relayMode !== 'disabled'
  ) {
    throw new P2PError('INVALID_FRAME', 'Iroh relay mode must be default or disabled');
  }
  for (const [name, callback] of [
    ['allowAdvertisedAddress', options.allowAdvertisedAddress],
    ['allowDirectAddress', options.allowDirectAddress],
    ['allowRelayUrl', options.allowRelayUrl]
  ] as const) {
    if (callback !== undefined && typeof callback !== 'function') {
      throw new P2PError('UNAUTHORIZED', `Iroh ${name} policy must be a function`);
    }
  }
  if (options.relayUrls !== undefined && !Array.isArray(options.relayUrls)) {
    throw new P2PError('INVALID_FRAME', 'Iroh relay URLs must be an array');
  }
  if (options.relayUrls !== undefined && options.relayMode !== undefined) {
    throw new P2PError('INVALID_FRAME', 'Configure either Iroh relayUrls or relayMode, not both');
  }
  if (options.relay !== undefined && (options.relayUrls !== undefined || options.relayMode !== undefined)) {
    throw new P2PError('INVALID_FRAME', 'Configure either Iroh relay or legacy relay options, not both');
  }
}

function resolveRelayConfiguration(options: IrohEndpointOptions): IrohRelayConfiguration {
  if (options.relay) {
    if (!isPlainRecord(options.relay)) throw new P2PError('INVALID_FRAME', 'Iroh relay options must be a plain object');
    assertOnlyKeys(options.relay, ['mode', 'urls'], 'Iroh relay options');
    if (options.relay.mode === 'custom') {
      if (!Array.isArray(options.relay.urls)) {
        throw new P2PError('INVALID_FRAME', 'Custom Iroh relay URLs must be an array');
      }
      return { mode: 'custom', urls: [...options.relay.urls] };
    }
    if (options.relay.mode !== 'default' && options.relay.mode !== 'disabled') {
      throw new P2PError('INVALID_FRAME', 'Iroh relay mode is invalid');
    }
    if ('urls' in options.relay) throw new P2PError('INVALID_FRAME', 'Only custom relay mode accepts URLs');
    return { mode: options.relay.mode };
  }
  if (options.relayUrls !== undefined) return { mode: 'custom', urls: [...options.relayUrls] };
  return { mode: options.relayMode ?? 'default' };
}

function resolveDiscoveryConfiguration(value: IrohDiscoveryConfiguration | undefined): {
  dns: boolean | { serverUrl?: string };
  mdnsServiceName?: string;
  mdnsAdvertise: boolean;
} {
  if (value === undefined) return { dns: false, mdnsAdvertise: false };
  if (!isPlainRecord(value)) throw new P2PError('INVALID_FRAME', 'Iroh discovery options must be a plain object');
  assertOnlyKeys(value, ['dns', 'mdns'], 'Iroh discovery options');
  let dns: boolean | { serverUrl?: string } = value.dns ?? false;
  if (typeof dns === 'object') {
    if (!isPlainRecord(dns)) throw new P2PError('INVALID_FRAME', 'Iroh DNS discovery options must be a plain object');
    assertOnlyKeys(dns, ['serverUrl'], 'Iroh DNS discovery options');
    if (dns.serverUrl !== undefined) {
      if (typeof dns.serverUrl !== 'string') {
        throw new P2PError('INVALID_FRAME', 'Iroh DNS discovery server must be an HTTPS URL');
      }
      let url: URL;
      try {
        url = new URL(dns.serverUrl);
      } catch (cause) {
        throw new P2PError('INVALID_FRAME', 'Iroh DNS discovery server must be an HTTPS URL', { cause });
      }
      if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
        throw new P2PError('INVALID_FRAME', 'Iroh DNS discovery server must be an HTTPS URL');
      }
      dns = { serverUrl: url.toString() };
    } else {
      dns = {};
    }
  } else if (typeof dns !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'Iroh DNS discovery configuration is invalid');
  }
  if (value.mdns === undefined || value.mdns === false) return { dns, mdnsAdvertise: false };
  if (value.mdns === true) return { dns, mdnsServiceName: 'p2prpc', mdnsAdvertise: true };
  if (!isPlainRecord(value.mdns)) {
    throw new P2PError('INVALID_FRAME', 'Iroh mDNS discovery configuration is invalid');
  }
  assertOnlyKeys(value.mdns, ['serviceName', 'advertise'], 'Iroh mDNS discovery options');
  const serviceName = value.mdns.serviceName ?? 'p2prpc';
  if (!validServiceName(serviceName)) throw new P2PError('INVALID_FRAME', 'Iroh mDNS service name is invalid');
  if (value.mdns.advertise !== undefined && typeof value.mdns.advertise !== 'boolean') {
    throw new P2PError('INVALID_FRAME', 'Iroh mDNS advertise option must be a boolean');
  }
  return { dns, mdnsServiceName: serviceName, mdnsAdvertise: value.mdns.advertise ?? true };
}

function validServiceName(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(value);
}

function validateEndpointLocator(value: unknown): asserts value is EndpointLocator {
  if (!isPlainRecord(value)) throw new P2PError('INVALID_FRAME', 'Iroh locator must be a plain object');
  if (value.kind === 'ticket') {
    assertOnlyKeys(value, ['kind', 'ticket'], 'Iroh ticket locator');
    if (typeof value.ticket !== 'string' || value.ticket.length < 1 || Buffer.byteLength(value.ticket) > 64 * 1024) {
      throw new P2PError('INVALID_FRAME', 'Iroh ticket locator is invalid');
    }
    return;
  }
  if (value.kind === 'dns') {
    assertOnlyKeys(value, ['kind'], 'Iroh DNS locator');
    return;
  }
  if (value.kind === 'mdns') {
    assertOnlyKeys(value, ['kind', 'serviceName'], 'Iroh mDNS locator');
    if (value.serviceName !== undefined && !validServiceName(value.serviceName)) {
      throw new P2PError('INVALID_FRAME', 'Iroh mDNS service name is invalid');
    }
    return;
  }
  throw new P2PError('INVALID_FRAME', 'Iroh locator kind is invalid');
}

function validateExpectedPeerId(value: unknown): asserts value is string {
  if (typeof value !== 'string') throw new P2PError('INVALID_FRAME', 'Expected Iroh peer ID is invalid');
  try {
    if (PublicKey.fromString(value).toString() !== value) throw new Error('Non-canonical peer ID');
  } catch (cause) {
    throw new P2PError('INVALID_FRAME', 'Expected Iroh peer ID is invalid', { cause });
  }
}

function validateDiscoveryOptions(value: unknown): asserts value is EndpointDiscoveryOptions {
  if (!isPlainRecord(value)) throw new P2PError('INVALID_FRAME', 'Iroh mDNS options must be a plain object');
  assertOnlyKeys(value, ['serviceName', 'signal'], 'Iroh mDNS options');
  if (value.serviceName !== undefined && !validServiceName(value.serviceName)) {
    throw new P2PError('INVALID_FRAME', 'Iroh mDNS service name is invalid');
  }
  if (value.signal !== undefined && !(value.signal instanceof AbortSignal)) {
    throw new P2PError('INVALID_FRAME', 'Iroh mDNS signal is invalid');
  }
}

function assertOnlyKeys(value: object, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new P2PError('INVALID_FRAME', `${label} contains unknown field ${key}`);
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeConfiguredRelayUrls(values: readonly string[]): string[] {
  if (values.length < 1 || values.length > 32) {
    throw new P2PError('RESOURCE_LIMIT', 'Configure between one and 32 Iroh relay URLs');
  }
  const output: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== 'string') throw new P2PError('INVALID_FRAME', 'Iroh relay URL must be a string');
    const normalized = canonicalRelayUrl(value);
    if (seen.has(normalized)) throw new P2PError('INVALID_FRAME', 'Iroh relay URLs must not be duplicated');
    seen.add(normalized);
    output.push(normalized);
  }
  return output;
}

function encodeTicket(payload: TicketPayload, secretKey: Uint8Array): string {
  const body = Buffer.from(JSON.stringify(payload));
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(secretKey)]),
    format: 'der',
    type: 'pkcs8'
  });
  const signature = signBytes(null, ticketSignaturePayload(body), privateKey);
  return `p2prpc3.${body.toString('base64url')}.${signature.toString('base64url')}`;
}

async function decodeTicket(
  ticket: string,
  relayEgressPolicy: RelayEgressPolicy,
  allowDirectAddress?: (address: string) => boolean,
  allowRelayUrl?: (origin: string) => boolean
): Promise<TicketPayload> {
  try {
    if (Buffer.byteLength(ticket) > 64 * 1024 || !ticket.startsWith('p2prpc3.')) throw new Error('Invalid prefix or length');
    const parts = ticket.split('.');
    if (parts.length !== 3) throw new Error('Invalid ticket segments');
    const encodedBody = parts[1]!;
    const encodedSignature = parts[2]!;
    const body = Buffer.from(encodedBody, 'base64url');
    const signature = Buffer.from(encodedSignature, 'base64url');
    if (body.toString('base64url') !== encodedBody || signature.toString('base64url') !== encodedSignature || signature.byteLength !== 64) {
      throw new Error('Non-canonical ticket encoding');
    }
    const decoded: unknown = JSON.parse(body.toString('utf8'));
    if (!isPlainRecord(decoded)) throw new Error('Invalid ticket object');
    assertOnlyKeys(
      decoded,
      ['version', 'peerId', 'directAddresses', 'relayUrl', 'protocol', 'issuedAt', 'expiresAt'],
      'Ticket'
    );
    const value = decoded as unknown as TicketPayload;
    if (
      value.version !== 3 ||
      typeof value.peerId !== 'string' ||
      !Array.isArray(value.directAddresses) ||
      typeof value.protocol !== 'string' ||
      value.protocol.length < 1 ||
      value.protocol.length > 512 ||
      typeof value.issuedAt !== 'number' ||
      !Number.isSafeInteger(value.issuedAt) ||
      typeof value.expiresAt !== 'number' ||
      !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= Date.now() ||
      value.issuedAt > value.expiresAt ||
      value.issuedAt > Date.now() + 60_000 ||
      value.expiresAt - value.issuedAt > 30 * 24 * 60 * 60_000 ||
      (value.relayUrl !== null && typeof value.relayUrl !== 'string')
    ) {
      throw new Error('Invalid fields');
    }
    const publicKey = PublicKey.fromString(value.peerId);
    if (!await publicKey.verify(ticketSignaturePayload(body), signature)) throw new Error('Invalid ticket signature');
    if (value.directAddresses.length > 0 && allowDirectAddress === undefined) {
      throw new P2PError(
        'UNAUTHORIZED',
        'Signed-ticket direct routes require an explicit egress policy'
      );
    }
    const directAddresses = validateDirectAddresses(value.directAddresses, allowDirectAddress);
    const relayUrl = value.relayUrl === null
      ? null
      : validateRelayCandidate(value.relayUrl, relayEgressPolicy, 'ticket', allowRelayUrl);
    return { ...value, directAddresses, relayUrl };
  } catch (cause) {
    if (cause instanceof P2PError && cause.code === 'UNAUTHORIZED') throw cause;
    throw new P2PError('INVALID_FRAME', 'Invalid p2prpc endpoint ticket', { cause });
  }
}

function ticketSignaturePayload(body: Uint8Array): Buffer {
  return Buffer.concat([TICKET_SIGNATURE_DOMAIN, Buffer.from(body)]);
}

function validateDirectAddresses(
  addresses: readonly unknown[],
  allowDirectAddress?: (address: string) => boolean
): string[] {
  if (addresses.length > 32) throw new P2PError('INVALID_FRAME', 'Route has too many direct addresses');
  return addresses.map((value) => {
    if (typeof value !== 'string' || value.length < 3 || value.length > 512 || !validSocketAddress(value)) {
      throw new P2PError('INVALID_FRAME', 'Route contains an invalid direct address');
    }
    if (allowDirectAddress) {
      try {
        if (allowDirectAddress(value) !== true) {
          throw new P2PError('UNAUTHORIZED', 'Route direct address was rejected by egress policy');
        }
      } catch {
        throw new P2PError('UNAUTHORIZED', 'Route direct address was rejected by egress policy');
      }
    }
    return value;
  });
}

function filterAdvertisedAddresses(
  addresses: readonly unknown[],
  allowAdvertisedAddress?: (address: string) => boolean
): string[] {
  const validated = validateDirectAddresses(addresses);
  return allowAdvertisedAddress
    ? validated.filter((address) => allowAdvertisedAddress(address) === true)
    : validated;
}

function validSocketAddress(value: string, allowZeroPort = false): boolean {
  let host: string;
  let portText: string;
  if (value.startsWith('[')) {
    const match = /^\[([^\]]+)\]:(\d{1,5})$/.exec(value);
    if (!match) return false;
    const [address, scope, ...extra] = match[1]!.split('%');
    if (extra.length > 0 || (scope !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(scope))) return false;
    host = address!;
    portText = match[2]!;
    if (isIP(host) !== 6) return false;
  } else {
    const separator = value.lastIndexOf(':');
    if (separator < 1) return false;
    host = value.slice(0, separator);
    portText = value.slice(separator + 1);
    if (isIP(host) !== 4) return false;
  }
  const port = Number(portText);
  return (
    !containsUnsafeDisplayCharacters(value) &&
    !value.includes(' ') &&
    Number.isSafeInteger(port) &&
    port >= (allowZeroPort ? 0 : 1) &&
    port <= 65_535
  );
}

const LAN_DIRECT_ADDRESSES = new BlockList();
LAN_DIRECT_ADDRESSES.addSubnet('10.0.0.0', 8, 'ipv4');
LAN_DIRECT_ADDRESSES.addSubnet('172.16.0.0', 12, 'ipv4');
LAN_DIRECT_ADDRESSES.addSubnet('192.168.0.0', 16, 'ipv4');
LAN_DIRECT_ADDRESSES.addSubnet('169.254.0.0', 16, 'ipv4');
LAN_DIRECT_ADDRESSES.addSubnet('127.0.0.0', 8, 'ipv4');
LAN_DIRECT_ADDRESSES.addSubnet('fc00::', 7, 'ipv6');
LAN_DIRECT_ADDRESSES.addSubnet('fe80::', 10, 'ipv6');
LAN_DIRECT_ADDRESSES.addAddress('::1', 'ipv6');

function allowLanDirectAddress(value: string): boolean {
  let host: string;
  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    host = value.slice(1, close).split('%', 1)[0]!;
  } else {
    host = value.slice(0, value.lastIndexOf(':'));
  }
  const family = isIP(host);
  return family === 4
    ? LAN_DIRECT_ADDRESSES.check(host, 'ipv4')
    : family === 6 && LAN_DIRECT_ADDRESSES.check(host, 'ipv6');
}

function canonicalRelayUrl(value: string): string {
  const url = validateRelayUrl(value);
  return url.toString();
}

function validateRelayUrl(value: string): URL {
  if (
    value.length < 1 ||
    value.length > 2048 ||
    value !== value.trim() ||
    containsUnsafeDisplayCharacters(value)
  ) {
    throw new P2PError('INVALID_FRAME', 'Relay URL is not a bounded safe string');
  }
  const originSyntax = /^https:\/\/([^/?#\\]+)\/?$/iu.exec(value);
  const authority = originSyntax?.[1];
  if (!authority || authority.includes('@') || authority.includes('%') || authority.endsWith(':')) {
    throw new P2PError(
      'INVALID_FRAME',
      'Relay URL must use an unambiguous credential-free HTTPS origin syntax'
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new P2PError('INVALID_FRAME', 'Relay URL is invalid', { cause });
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.port === '0' ||
    url.hash ||
    url.search ||
    (url.pathname !== '' && url.pathname !== '/')
  ) {
    throw new P2PError(
      'INVALID_FRAME',
      'Relay URL must be an HTTPS origin without credentials, path, query, or fragment'
    );
  }
  if (!url.hostname.startsWith('[') && url.hostname.endsWith('.')) {
    if (url.hostname.endsWith('..')) {
      throw new P2PError('INVALID_FRAME', 'Relay DNS name may contain at most one trailing root dot');
    }
    const hostname = url.hostname.slice(0, -1);
    if (!hostname) throw new P2PError('INVALID_FRAME', 'Relay URL hostname is invalid');
    url.hostname = hostname;
    if (url.hostname !== hostname) {
      throw new P2PError('INVALID_FRAME', 'Relay URL hostname could not be canonicalized');
    }
  }
  const hostname = url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
  if (isIP(hostname) === 0) {
    const labels = hostname.split('.');
    if (
      hostname.length > 253 ||
      labels.some((label) =>
        label.length < 1 ||
        label.length > 63 ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
      )
    ) {
      throw new P2PError('INVALID_FRAME', 'Relay DNS name contains an invalid label');
    }
  }
  return url;
}

function validateRelayCandidate(
  value: string,
  policy: RelayEgressPolicy,
  source: RelayCandidateSource,
  allowRelayUrl?: (origin: string) => boolean
): string {
  const url = validateRelayUrl(value);
  const normalized = url.toString();
  if (policy.mode === 'disabled') {
    throw new P2PError('UNAUTHORIZED', 'Relay route hints are disabled for this endpoint');
  }
  if (policy.mode === 'custom' && !policy.customOrigins.has(url.origin)) {
    throw new P2PError('UNAUTHORIZED', 'Relay route hint is outside the configured custom relay origins');
  }
  if (source === 'mdns' && policy.mode === 'default' && allowRelayUrl === undefined) {
    throw new P2PError('UNAUTHORIZED', 'mDNS relay route hints require an explicit egress policy');
  }
  if (source === 'ticket' && policy.mode === 'default' && allowRelayUrl === undefined) {
    throw new P2PError('UNAUTHORIZED', 'Signed-ticket relay route hints require an explicit egress policy');
  }
  if (source !== 'local') enforceRelayPolicy(normalized, allowRelayUrl);
  return normalized;
}

function enforceRelayPolicy(canonical: string, policy?: (origin: string) => boolean): void {
  if (!policy) return;
  const origin = new URL(canonical).origin;
  try {
    // Strings are immutable and only the canonical origin is exposed.
    if (policy(origin) !== true) {
      throw new P2PError('UNAUTHORIZED', 'Relay URL was rejected by egress policy');
    }
  } catch {
    throw new P2PError('UNAUTHORIZED', 'Relay URL was rejected by egress policy');
  }
}

async function abortable<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  signal?.throwIfAborted();
  if (!signal) return promise;
  let detach: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        const abort = (): void => reject(
          signal.reason ?? new P2PError('CANCELLED', 'Operation cancelled')
        );
        signal.addEventListener('abort', abort, { once: true });
        detach = () => signal.removeEventListener('abort', abort);
      })
    ]);
  } finally {
    detach?.();
  }
}
