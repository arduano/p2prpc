export interface QuicSendStream {
  writeAll(data: Uint8Array): Promise<void>;
  finish(): Promise<void>;
  reset(code: bigint): Promise<void>;
  setPriority(priority: number): Promise<void>;
}

export interface QuicRecvStream {
  readExact(size: number): Promise<Uint8Array>;
  stop(code: bigint): Promise<void>;
}

export interface QuicBiStream {
  readonly send: QuicSendStream;
  readonly recv: QuicRecvStream;
}

export interface ConnectionStats {
  readonly rttMs: number | null;
  readonly sentBytes: number;
  readonly receivedBytes: number;
  readonly lostPackets: number;
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
  configure(options: { maxBiStreams: bigint; maxUniStreams: bigint; receiveWindow: bigint }): void;
}

export interface EndpointAddress {
  readonly id: string;
  readonly ticket: string;
}

export interface QuicEndpoint {
  readonly id: string;
  readonly address: EndpointAddress;
  connect(ticket: string, alpn: Uint8Array): Promise<QuicConnection>;
  accept(): Promise<QuicConnection | null>;
  close(): Promise<void>;
}
