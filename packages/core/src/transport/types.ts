export interface QuicSendStream {
  writeAll(data: Uint8Array): Promise<void>;
  finish(): Promise<void>;
  reset(code: bigint): Promise<void>;
  setPriority(priority: number): Promise<void>;
}

export interface QuicRecvStream {
  readExact(size: number): Promise<Uint8Array>;
  /** Consume and verify the peer's clean FIN. Trailing bytes are invalid. */
  expectEnd(): Promise<void>;
  stop(code: bigint): Promise<void>;
}

export interface QuicBiStream {
  readonly send: QuicSendStream;
  readonly recv: QuicRecvStream;
}

export interface ConnectionStats {
  /** Opaque identifier for this physical transport connection. */
  readonly connectionId?: string;
  readonly rttMs: number | null;
  readonly sentBytes: number;
  readonly receivedBytes: number;
  readonly lostPackets: number;
  readonly sentPackets?: number | null;
  readonly congestionWindow?: number | null;
  readonly relay?: boolean | null;
  readonly relayUrl?: string | null;
  readonly paths?: readonly ConnectionPath[];
  readonly streams?: StreamLifecycleStats;
}

export interface ConnectionPath {
  readonly relay: boolean;
  readonly address: string;
  readonly active: boolean;
}

export interface StreamLifecycleStats {
  readonly openedBi: number;
  readonly acceptedBi: number;
  readonly openedUni: number;
  readonly acceptedUni: number;
  readonly activeSend: number;
  readonly activeRecv: number;
  readonly sendFinished: number;
  readonly sendReset: number;
  readonly recvEof: number;
  readonly recvStopped: number;
}

export interface EndpointDiagnostics {
  readonly activeReaders: number;
  readonly activeWriters: number;
  readonly activeSessions: number;
  readonly totalHandles: number;
  readonly poolSize: number;
  readonly activeConnections: number;
  readonly activeRequests: number;
  readonly activePathSubscriptions: number;
  readonly activePathWatchers: number;
}

/**
 * Route bootstrap strategy for an outbound dial; never an identity source.
 * A transport may have endpoint-wide discovery fallback. In particular, the
 * Iroh adapter may fall back to DNS/PKARR for any locator when DNS is enabled
 * on that endpoint.
 */
export type EndpointLocator =
  | { readonly kind: 'ticket'; readonly ticket: string }
  | { readonly kind: 'dns' }
  | { readonly kind: 'mdns'; readonly serviceName?: string };

export interface EndpointDiscoveryEvent {
  readonly peerId: string;
  readonly addresses: readonly string[];
  readonly active: boolean;
}

export interface EndpointDiscoveryOptions {
  readonly serviceName?: string;
  readonly signal?: AbortSignal;
}

export interface QuicConnection {
  readonly remoteId: string;
  readonly side: 'client' | 'server';
  openBi(): Promise<QuicBiStream>;
  acceptBi(): Promise<QuicBiStream>;
  openUni(): Promise<QuicSendStream>;
  acceptUni(): Promise<QuicRecvStream>;
  closed(): Promise<string>;
  close(code: bigint, reason: Uint8Array): void;
  stats(): Promise<ConnectionStats>;
  pathChanges?(signal?: AbortSignal): AsyncIterable<ConnectionPath>;
  configure(options: { maxBiStreams: bigint; maxUniStreams: bigint; receiveWindow: bigint }): void;
}

export interface EndpointAddress {
  readonly id: string;
  readonly ticket: string;
}

export interface QuicEndpoint {
  readonly id: string;
  readonly address: EndpointAddress;
  createTicket?(): Promise<string>;
  /** @deprecated Alternate transports may implement ticket-only dialing. */
  connect(ticket: string, alpn: Uint8Array, expectedPeerId: string): Promise<QuicConnection>;
  connectLocator?(
    locator: EndpointLocator,
    alpn: Uint8Array,
    expectedPeerId: string,
    signal?: AbortSignal
  ): Promise<QuicConnection>;
  accept(): Promise<QuicConnection | null>;
  advertise?(options?: EndpointDiscoveryOptions): Promise<void>;
  browse?(options?: EndpointDiscoveryOptions): AsyncIterable<EndpointDiscoveryEvent>;
  diagnostics?(): Promise<EndpointDiagnostics>;
  close(): Promise<void>;
}
