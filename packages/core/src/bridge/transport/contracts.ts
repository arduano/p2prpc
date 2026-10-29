import type { QuicConnection } from '../../transport/types.js';

/** One owned logical channel. Its closure says nothing about a borrowed outer
 * Peer, Iroh endpoint, native agent, or another viewer's channel. */
export interface ByteDuplex {
  readonly readable: AsyncIterable<Uint8Array>;
  /** Backpressured write; retain the bytes until this promise settles. */
  write(bytes: Uint8Array): Promise<void>;
  close(reason?: Error): void | Promise<void>;
  /** Fulfill only after this carrier's actual resources are terminal. Closing
   * must also settle its pending iterator reads and write promises. */
  readonly closed: Promise<void>;
}

export interface LogicalConnectionLimits {
  readonly maxStreams: number;
  readonly maxPendingIncoming: number;
  readonly maxReadBytes: number;
  readonly maxBufferedBytes: number;
  /** Maximum wait for an incoming header or second BI direction. */
  readonly pairTimeoutMs: number;
}

export interface LogicalConnectionOptions {
  /** Already authorized logical peer identity. The adapter does not authenticate
   * it and must never present it as proof of a physical Iroh endpoint. */
  readonly remoteId: string;
  readonly side: 'client' | 'server';
  readonly limits?: Partial<LogicalConnectionLimits>;
}

/** The existing stream API, scoped to one logical channel. closed() proves this
 * channel and its owned streams terminal, not the shared physical connection. */
export type LogicalConnection = QuicConnection;
// Standard Yamux has no numeric reset reason or priority scheduler. reset/stop
// retain independent direction cancellation; numeric codes are not transported.
// setPriority is advisory only. No physical-path or physical-endpoint proof is
// inferred from this QuicConnection-shaped logical API.

/** Common DOM WebSocket/Node ws surface; no runtime dependency on either. */
export interface BinaryWebSocket {
  readonly readyState: number;
  readonly bufferedAmount: number;
  binaryType: string;
  send(bytes: Uint8Array<ArrayBuffer>): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
  removeEventListener(type: 'message', listener: (event: { data: unknown }) => void): void;
  removeEventListener(type: 'open' | 'close' | 'error', listener: () => void): void;
}

export interface WebSocketCarrierLimits {
  readonly maxBufferedBytes?: number;
  readonly maxMessageBytes?: number;
  readonly maxPendingWrites?: number;
  readonly writeTimeoutMs?: number;
}
