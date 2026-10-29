import type { CreateTRPCClient } from '@trpc/client';
import type { AnyTRPCRouter, inferRouterContext } from '@trpc/server';
import type { FileTransferDiagnostics } from '../files/manager.js';
import type { ShareRegistryDiagnostics, ShareRegistryOptions } from '../files/share.js';
import type { FileMetadataSchema, IncomingFileHandler, PeerFiles, PeerFileShareOptions } from '../files/types.js';
import type { FileTransferLimits } from '../files/validation.js';
import type { FrameLimits } from '../protocol.js';
import type { RpcHeaderInput, RpcHeaderLimits } from '../rpc/portable-headers.js';
import type { RpcServerRequest } from '../rpc/portable-server.js';
import type { ResourceSnapshot } from '../runtime/resources.js';
import type { AuthorizationContext, AuthorizationResult, SessionPrincipal } from '../security/types.js';
import type { QuicConnection } from '../transport/types.js';

/** Already verified admission facts. This is not an Iroh authentication proof. */
export interface BridgeSession {
  readonly id: string;
  readonly principal: SessionPrincipal;
  readonly expiresAt: number;
  readonly via: { readonly peerId: string; readonly principal: SessionPrincipal };
}

export type BridgeShareOptions = PeerFileShareOptions;
export type BridgeRequestFiles<M = unknown> = Pick<PeerFiles<M>, 'share' | 'revoke'>;
export type BridgeFiles<M = unknown> = PeerFiles<M>;

export interface BridgeContext<M = unknown> {
  readonly bridge: {
    readonly peerId: string;
    readonly principal: SessionPrincipal;
    readonly via: BridgeSession['via'];
    readonly request: RpcServerRequest;
    readonly files: BridgeRequestFiles<M>;
  };
}

export interface BridgePeerLimits {
  readonly maxStreams: number;
  readonly maxBufferedBytes: number;
  readonly maxCallbacks: number;
  readonly maxQueuedOperations: number;
  readonly setupTimeoutMs: number;
  readonly ioTimeoutMs: number;
  readonly shutdownTimeoutMs: number;
}

export interface BridgePeerOptions<LocalRouter extends AnyTRPCRouter, M = unknown> {
  readonly localId: string;
  readonly remoteId: string;
  /** Establish/admit a carrier, call attach(), then return that exact carrier.
   * The engine never redials or replays a failed RPC itself. */
  readonly connection: () => Promise<QuicConnection>;
  readonly authorize: (context: AuthorizationContext<M> & { readonly via: BridgeSession['via'] }) => AuthorizationResult | Promise<AuthorizationResult>;
  readonly local?: {
    readonly router: LocalRouter;
    readonly createContext: (context: BridgeContext<M>) => inferRouterContext<LocalRouter> | Promise<inferRouterContext<LocalRouter>>;
  };
  readonly incoming?: IncomingFileHandler<M>;
  readonly fileMetadataSchema?: FileMetadataSchema<M>;
  readonly getRequestHeaders?: (request: {
    readonly path: string; readonly type: 'query' | 'mutation' | 'subscription'; readonly signal: AbortSignal;
  }) => RpcHeaderInput | undefined | Promise<RpcHeaderInput | undefined>;
  readonly frameLimits?: FrameLimits;
  readonly headerLimits?: RpcHeaderLimits;
  readonly maxPathBytes?: number;
  readonly fileLimits?: Partial<FileTransferLimits>;
  readonly shares?: ShareRegistryOptions;
  readonly limits?: Partial<BridgePeerLimits>;
  readonly onError?: (error: Error) => void;
}

export interface BridgePeerDiagnostics {
  readonly connected: boolean;
  readonly closed: boolean;
  readonly sessionId: string | null;
  readonly tasks: number;
  readonly resources: ResourceSnapshot;
  readonly shares: ShareRegistryDiagnostics;
  readonly files: FileTransferDiagnostics;
}

export interface BridgePeer<RemoteRouter extends AnyTRPCRouter, M = unknown> {
  readonly rpc: CreateTRPCClient<RemoteRouter>;
  readonly files: BridgeFiles<M>;
  /** Refuses replacement until the preceding logical carrier positively closed. */
  attach(connection: QuicConnection, session: BridgeSession): void;
  /** Closes only the owned logical carrier, never its borrowed outer Peer. */
  close(reason?: string): Promise<void>;
  diagnostics(): BridgePeerDiagnostics;
}
