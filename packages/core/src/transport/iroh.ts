import { createPrivateKey, randomBytes, sign as signBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { createNode, PublicKey, type IrohNode, type NodeOptions } from '@momics/iroh-http-node';
import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';
import type {
  ConnectionStats,
  EndpointAddress,
  QuicBiStream,
  QuicConnection,
  QuicEndpoint,
  QuicRecvStream,
  QuicSendStream
} from './types.js';

export interface IrohEndpointOptions {
  readonly secretKey?: Uint8Array;
  readonly bindAddress?: string;
  readonly relayMode?: 'default' | 'disabled';
  readonly relayUrls?: readonly string[];
  /** Lifetime of each freshly generated signed locator ticket. Defaults to 24 hours. */
  readonly ticketTtlMs?: number;
  /** Optional egress policy for signed direct-address candidates. */
  readonly allowDirectAddress?: (address: string) => boolean;
  /** Optional egress policy for the signed relay candidate. */
  readonly allowRelayUrl?: (url: URL) => boolean;
}

interface TicketPayload {
  readonly version: 2;
  readonly peerId: string;
  readonly directAddresses: string[];
  readonly relayUrl: string | null;
  readonly protocol: string;
  readonly issuedAt: number;
  readonly expiresAt: number;
}

type IrohSession = Awaited<ReturnType<IrohNode['dial']>>;

const TICKET_SIGNATURE_DOMAIN = Buffer.from('p2prpc-signed-ticket-v2\0', 'utf8');

class WebSendStream implements QuicSendStream {
  private readonly writer: WritableStreamDefaultWriter<Uint8Array>;

  constructor(stream: WritableStream<Uint8Array>) {
    this.writer = stream.getWriter();
  }

  async writeAll(data: Uint8Array): Promise<void> {
    await this.writer.write(data);
  }

  async finish(): Promise<void> {
    await this.writer.close();
  }

  async reset(): Promise<void> {
    await this.writer.abort(new P2PError('CANCELLED', 'Stream reset'));
  }

  async setPriority(priority: number): Promise<void> {
    // WebTransport's stream priority API is not yet exposed by iroh-http.
    void priority;
  }
}

class WebRecvStream implements QuicRecvStream {
  private readonly reader: ReadableStreamDefaultReader<Uint8Array>;
  private buffered: Uint8Array<ArrayBufferLike> = new Uint8Array();

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  async readExact(size: number): Promise<Uint8Array> {
    if (!Number.isSafeInteger(size) || size < 0 || size > 0xffff_ffff) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid read size: ${size}`);
    }
    if (size === 0) return new Uint8Array();
    const result = new Uint8Array(size);
    let offset = 0;
    while (offset < size) {
      if (this.buffered.byteLength === 0) {
        const next = await this.reader.read();
        if (next.done) throw new P2PError('DISCONNECTED', `Stream ended with ${size - offset} bytes remaining`);
        this.buffered = next.value;
      }
      const count = Math.min(size - offset, this.buffered.byteLength);
      result.set(this.buffered.subarray(0, count), offset);
      this.buffered = this.buffered.subarray(count);
      offset += count;
    }
    return result;
  }

  async stop(): Promise<void> {
    await this.reader.cancel(new P2PError('CANCELLED', 'Stream stopped'));
  }
}

class WebSessionConnection implements QuicConnection {
  readonly remoteId: string;
  private readonly incomingBi: ReadableStreamDefaultReader<Awaited<ReturnType<IrohSession['createBidirectionalStream']>>>;
  private readonly incomingUni: ReadableStreamDefaultReader<ReadableStream<Uint8Array>>;

  constructor(
    private readonly session: IrohSession,
    private readonly node: IrohNode,
    readonly side: 'client' | 'server'
  ) {
    this.remoteId = session.remoteId.toString();
    this.incomingBi = session.incomingBidirectionalStreams.getReader();
    this.incomingUni = session.incomingUnidirectionalStreams.getReader();
  }

  async openBi(): Promise<QuicBiStream> {
    const stream = await this.session.createBidirectionalStream();
    return { send: new WebSendStream(stream.writable), recv: new WebRecvStream(stream.readable) };
  }

  async acceptBi(): Promise<QuicBiStream> {
    const result = await this.incomingBi.read();
    if (result.done) throw new P2PError('DISCONNECTED', 'Connection closed while accepting a stream');
    return { send: new WebSendStream(result.value.writable), recv: new WebRecvStream(result.value.readable) };
  }

  async openUni(): Promise<QuicSendStream> {
    return new WebSendStream(await this.session.createUnidirectionalStream());
  }

  async acceptUni(): Promise<QuicRecvStream> {
    const result = await this.incomingUni.read();
    if (result.done) throw new P2PError('DISCONNECTED', 'Connection closed while accepting a stream');
    return new WebRecvStream(result.value);
  }

  async closed(): Promise<string> {
    const info = await this.session.closed;
    return info.reason;
  }

  close(code: bigint, reason: Uint8Array): void {
    this.session.close({ closeCode: Number(code), reason: new TextDecoder().decode(reason) });
  }

  async stats(): Promise<ConnectionStats> {
    const stats = await this.node.peerStats(this.remoteId);
    return {
      rttMs: stats?.rttMs ?? null,
      sentBytes: stats?.bytesSent ?? 0,
      receivedBytes: stats?.bytesReceived ?? 0,
      lostPackets: stats?.lostPackets ?? 0
    };
  }

  configure(options: { maxBiStreams: bigint; maxUniStreams: bigint; receiveWindow: bigint }): void {
    // Flow control is managed in the native Iroh session implementation.
    void options;
  }
}

export class IrohEndpoint implements QuicEndpoint {
  readonly id: string;
  private incoming: AsyncIterator<IrohSession>;

  private constructor(
    private readonly node: IrohNode,
    private readonly protocol: string,
    private readonly locator: Omit<TicketPayload, 'issuedAt' | 'expiresAt'>,
    private readonly ticketKey: Uint8Array,
    private readonly ticketTtlMs: number,
    private readonly allowDirectAddress?: (address: string) => boolean,
    private readonly allowRelayUrl?: (url: URL) => boolean
  ) {
    this.id = node.publicKey.toString();
    this.incoming = node.incoming()[Symbol.asyncIterator]();
  }

  get address(): EndpointAddress {
    const issuedAt = Date.now();
    return {
      id: this.id,
      ticket: encodeTicket({ ...this.locator, issuedAt, expiresAt: issuedAt + this.ticketTtlMs }, this.ticketKey)
    };
  }

  static async create(alpn: Uint8Array, options: IrohEndpointOptions = {}): Promise<IrohEndpoint> {
    validateIrohOptions(options);
    const ticketTtlMs = options.ticketTtlMs === undefined ? 24 * 60 * 60_000 : options.ticketTtlMs;
    if (!Number.isSafeInteger(ticketTtlMs) || ticketTtlMs < 60_000 || ticketTtlMs > 30 * 24 * 60 * 60_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Ticket lifetime must be between one minute and 30 days');
    }
    const secretKey = options.secretKey === undefined ? randomBytes(32) : Uint8Array.from(options.secretKey);
    if (secretKey.byteLength !== 32) throw new P2PError('INVALID_FRAME', 'Iroh secret key must be 32 bytes');
    const relayUrls = options.relayUrls === undefined
      ? undefined
      : normalizeConfiguredRelayUrls(options.relayUrls, options.allowRelayUrl);
    const nodeOptions: NodeOptions = {
      relay: relayUrls
        ? { urls: relayUrls }
        : { mode: options.relayMode ?? 'default' },
      // A p2prpc locator already carries signed route candidates. Disable
      // implicit discovery so dialing cannot silently add destinations which
      // bypass allowDirectAddress/allowRelayUrl egress policy.
      discovery: { dns: false, mdns: false },
      internals: { maxChunkSizeBytes: 1024 * 1024 },
      key: secretKey
    };
    if (options.bindAddress) nodeOptions.bindAddr = options.bindAddress;
    const node = await createNode(nodeOptions);
    const discovery = await node.discoveryInfo();
    const protocol = Buffer.from(alpn).toString('base64url');
    const locator: Omit<TicketPayload, 'issuedAt' | 'expiresAt'> = {
      version: 2,
      peerId: node.publicKey.toString(),
      directAddresses: validateDirectAddresses(discovery.directAddresses, options.allowDirectAddress),
      relayUrl: discovery.relayUrl,
      protocol
    };
    if (locator.relayUrl !== null) validateRelayUrl(locator.relayUrl, options.allowRelayUrl);
    return new IrohEndpoint(
      node,
      protocol,
      locator,
      secretKey,
      ticketTtlMs,
      options.allowDirectAddress,
      options.allowRelayUrl
    );
  }

  async connect(ticket: string, alpn: Uint8Array, expectedPeerId: string): Promise<QuicConnection> {
    const parsed = await decodeTicket(ticket, this.allowDirectAddress, this.allowRelayUrl);
    if (parsed.peerId !== expectedPeerId) {
      throw new P2PError('UNAUTHORIZED', 'Ticket endpoint does not match the expected peer ID');
    }
    const protocol = Buffer.from(alpn).toString('base64url');
    if (parsed.protocol !== protocol || parsed.protocol !== this.protocol) {
      throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Peer ticket uses a different application contract');
    }
    // iroh-http 0.6 can stall when mixed IPv4/IPv6 candidates carry the
    // endpoint's distinct family-specific ports. Prefer the IPv4 race when
    // available and retain IPv6-only support.
    const ipv4 = parsed.directAddresses.filter((address) => !address.startsWith('['));
    const session = await this.node.dial(parsed.peerId, {
      directAddrs: ipv4.length > 0 ? ipv4 : parsed.directAddresses,
      ...(parsed.relayUrl ? { relayUrl: parsed.relayUrl } : {})
    });
    await session.ready;
    return new WebSessionConnection(session, this.node, 'client');
  }

  async accept(): Promise<QuicConnection | null> {
    while (true) {
      try {
        const result = await this.incoming.next();
        return result.done ? null : new WebSessionConnection(result.value, this.node, 'server');
      } catch (cause) {
        if (String(cause).includes('accept session: timed out')) {
          this.incoming = this.node.incoming()[Symbol.asyncIterator]();
          continue;
        }
        throw cause;
      }
    }
  }

  async close(): Promise<void> {
    const stopIncoming = this.incoming.return?.();
    await this.node.close();
    await stopIncoming;
  }
}

function validateIrohOptions(options: IrohEndpointOptions): void {
  if (options.secretKey !== undefined && !(options.secretKey instanceof Uint8Array)) {
    throw new P2PError('INVALID_FRAME', 'Iroh secret key must be a Uint8Array');
  }
  if (options.bindAddress !== undefined && (
    typeof options.bindAddress !== 'string' ||
    options.bindAddress.length < 1 ||
    options.bindAddress.length > 512 ||
    options.bindAddress.includes(' ') ||
    containsUnsafeDisplayCharacters(options.bindAddress)
  )) {
    throw new P2PError('INVALID_FRAME', 'Iroh bind address is invalid');
  }
  if (
    options.relayMode !== undefined &&
    options.relayMode !== 'default' &&
    options.relayMode !== 'disabled'
  ) {
    throw new P2PError('INVALID_FRAME', 'Iroh relay mode must be default or disabled');
  }
  for (const [name, callback] of [
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
  if (
    options.allowRelayUrl !== undefined &&
    options.relayUrls === undefined &&
    options.relayMode !== 'disabled'
  ) {
    throw new P2PError(
      'UNAUTHORIZED',
      'Iroh relay egress policy requires explicit relayUrls or disabled relays'
    );
  }
}

function normalizeConfiguredRelayUrls(
  values: readonly string[],
  allowRelayUrl?: (url: URL) => boolean
): string[] {
  if (values.length < 1 || values.length > 32) {
    throw new P2PError('RESOURCE_LIMIT', 'Configure between one and 32 Iroh relay URLs');
  }
  const output: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    if (typeof value !== 'string') throw new P2PError('INVALID_FRAME', 'Iroh relay URL must be a string');
    validateRelayUrl(value, allowRelayUrl);
    if (seen.has(value)) throw new P2PError('INVALID_FRAME', 'Iroh relay URLs must not be duplicated');
    seen.add(value);
    output.push(value);
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
  return `p2prpc2.${body.toString('base64url')}.${signature.toString('base64url')}`;
}

async function decodeTicket(
  ticket: string,
  allowDirectAddress?: (address: string) => boolean,
  allowRelayUrl?: (url: URL) => boolean
): Promise<TicketPayload> {
  try {
    if (Buffer.byteLength(ticket) > 64 * 1024 || !ticket.startsWith('p2prpc2.')) throw new Error('Invalid prefix or length');
    const parts = ticket.split('.');
    if (parts.length !== 3) throw new Error('Invalid ticket segments');
    const encodedBody = parts[1]!;
    const encodedSignature = parts[2]!;
    const body = Buffer.from(encodedBody, 'base64url');
    const signature = Buffer.from(encodedSignature, 'base64url');
    if (body.toString('base64url') !== encodedBody || signature.toString('base64url') !== encodedSignature || signature.byteLength !== 64) {
      throw new Error('Non-canonical ticket encoding');
    }
    const value = JSON.parse(body.toString('utf8')) as TicketPayload;
    if (
      value.version !== 2 ||
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
    validateDirectAddresses(value.directAddresses, allowDirectAddress);
    if (value.relayUrl !== null) validateRelayUrl(value.relayUrl, allowRelayUrl);
    return value;
  } catch (cause) {
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
  if (addresses.length > 32) throw new P2PError('INVALID_FRAME', 'Ticket has too many direct addresses');
  return addresses.map((value) => {
    if (typeof value !== 'string' || value.length < 3 || value.length > 512 || !validSocketAddress(value)) {
      throw new P2PError('INVALID_FRAME', 'Ticket contains an invalid direct address');
    }
    if (allowDirectAddress && allowDirectAddress(value) !== true) {
      throw new P2PError('UNAUTHORIZED', 'Ticket direct address was rejected by egress policy');
    }
    return value;
  });
}

function validSocketAddress(value: string): boolean {
  let host: string;
  let portText: string;
  if (value.startsWith('[')) {
    const match = /^\[([^\]]+)\]:(\d{1,5})$/.exec(value);
    if (!match) return false;
    host = match[1]!.split('%', 1)[0]!;
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
  return Number.isSafeInteger(port) && port > 0 && port <= 65_535;
}

function validateRelayUrl(value: string, allowRelayUrl?: (url: URL) => boolean): void {
  if (value.length > 2048) throw new P2PError('INVALID_FRAME', 'Relay URL is too long');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new P2PError('INVALID_FRAME', 'Relay URL must be HTTPS and cannot include credentials or a fragment');
  }
  if (allowRelayUrl && allowRelayUrl(url) !== true) {
    throw new P2PError('UNAUTHORIZED', 'Ticket relay URL was rejected by egress policy');
  }
}
