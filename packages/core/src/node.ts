import { createTRPCProxyClient, type CreateTRPCClient } from '@trpc/client';
import type { AnyTRPCRouter, inferRouterContext } from '@trpc/server';
import { P2PError, asP2PError } from './errors.js';
import {
  FILE_DATA_SEGMENT_BYTES,
  ReceiverOperationLedger,
  TransferManager,
  type FileTransferConnectionContext,
  type FileTransferDiagnostics
} from './files/manager.js';
import { ShareRegistry, type ShareRegistryDiagnostics } from './files/share.js';
import type {
  DownloadFileOptions,
  FileDestination,
  FileMetadataSchema,
  FileSource,
  FileTransfer,
  IncomingFileHandler,
  SendFileOptions,
  PeerSharePolicy,
  SharedFileHandle,
  TransferProgress
} from './files/types.js';
import { PROTOCOL_VERSION, StreamKind, readStreamKind, type FrameLimits } from './protocol.js';
import { irohLink } from './rpc/link.js';
import type { RpcHeaderInput } from './rpc/headers.js';
import { RpcServer, type RpcServerRequest } from './rpc/server.js';
import { HandshakeRateLimiter } from './runtime/rate-limit.js';
import { ManagedConnection } from './runtime/managed-connection.js';
import {
  ResourceScheduler,
  type ResourceLease,
  type ResourceLimits,
  type ResourceSnapshot
} from './runtime/resources.js';
import { TaskGroup } from './runtime/task-group.js';
import { RuntimeSlotRegistry, type RuntimeSlotClaim } from './runtime/runtime-slots.js';
import { authenticateConnection } from './security/handshake.js';
import { dangerouslyAllowInsecureSessions } from './security/shared-secret.js';
import {
  authorizationAllowed,
  isPeerBoundSessionSecurity,
  type AuthenticatedSession,
  type AuthorizationAction,
  type AuthorizationContext,
  type CredentialRequestContext,
  type SessionAuthenticationContext,
  type SessionCredential,
  type SessionPrincipal,
  type SessionSecurity,
  type PeerBoundSessionSecurity
} from './security/types.js';
import { IrohEndpoint, type IrohEndpointOptions } from './transport/iroh.js';
import { assertTransportAdapterShape } from './transport/conformance.js';
import type {
  ConnectionPath,
  ConnectionStats,
  EndpointDiagnostics,
  EndpointDiscoveryEvent,
  EndpointDiscoveryOptions,
  EndpointLocator,
  QuicConnection,
  QuicEndpoint
} from './transport/types.js';
import { containsUnsafeDisplayCharacters, sanitizeBoundedDisplayText } from './text.js';

export interface PeerIdentity {
  readonly id: string;
  readonly direction: 'inbound' | 'outbound';
}

export interface P2PRequestFiles<TFileMetadata = unknown> {
  /** Issue a capability bound to this request's endpoint and complete authenticated principal. */
  share(source: FileSource<TFileMetadata>, policy?: PeerFileShareOptions): SharedFileHandle;
  /** Revoke a capability issued by this local node. */
  revoke(handle: SharedFileHandle): boolean;
}

export interface P2PRequestContext<TFileMetadata = unknown> {
  readonly peer: PeerIdentity;
  /** Trusted identity established by the mandatory application handshake. */
  readonly auth: AuthenticatedSession;
  /** Untrusted, normalized metadata for this individual RPC. */
  readonly request: RpcServerRequest;
  readonly connection: {
    stats(): Promise<ConnectionStats>;
  };
  /** Session-bound file-capability facade safe to call from tRPC procedures. */
  readonly files: P2PRequestFiles<TFileMetadata>;
}

/** Seed passed to createContext; verified transport/session data exists only under this reserved namespace. */
export interface PeerContext<TFileMetadata = unknown> {
  readonly p2p: P2PRequestContext<TFileMetadata>;
}

export interface ProtocolIdentity {
  readonly applicationId: string;
  readonly contractVersion: string;
}

/**
 * Exact authenticated application identity expected from an outbound target.
 * `null` requires an optional principal field to be absent. The field names
 * are identity-provider neutral: custom authenticators and shared-secret
 * deployments use the same canonical SessionPrincipal shape as OIDC.
 */
export interface PrincipalMatcher {
  /** Optional additional check of the authenticator's canonical stable ID. */
  readonly id?: string;
  readonly subject: string;
  readonly issuer: string | null;
  readonly clientId: string | null;
  readonly tenantId: string | null;
}

export type PeerLocator = EndpointLocator;

interface ConnectExpectations {
  readonly expectedPeerId: string;
  readonly expectedPrincipal: PrincipalMatcher;
}

/**
 * An outbound route plus independently trusted transport and application
 * identity expectations. Discovery information never supplies expectations.
 */
export type ConnectOptions = ConnectExpectations & {
  readonly locator: PeerLocator;
};

interface NormalizedConnectOptions extends ConnectExpectations {
  readonly locator: PeerLocator;
  readonly expectedPrincipal: Readonly<PrincipalMatcher>;
}

export type SecurityAuditEvent =
  | {
      readonly type: 'session.authenticated';
      readonly timestamp: number;
      readonly peerId: string;
      readonly direction: PeerIdentity['direction'];
      readonly sessionId: string;
      readonly principalId: string;
      readonly expiresAt: number;
    }
  | {
      readonly type: 'session.rejected';
      readonly timestamp: number;
      readonly peerId: string;
      readonly direction: PeerIdentity['direction'];
      readonly code: P2PError['code'];
    }
  | {
      readonly type: 'authorization';
      readonly timestamp: number;
      readonly peerId: string;
      readonly sessionId: string;
      readonly principalId: string;
      readonly action: Readonly<Record<string, string | number>>;
      readonly allowed: boolean;
      readonly reason?: string;
    }
  | {
      readonly type: 'session.expired';
      readonly timestamp: number;
      readonly peerId: string;
      readonly sessionId: string;
      readonly principalId: string;
    };

export interface P2PNodeLimits {
  readonly maxControlFrameBytes: number;
  readonly maxControlFrameItems: number;
  readonly maxControlFrameDepth: number;
  readonly fileChunkSize: number;
  /** Maximum peer-selected chunk size accepted for inbound files. */
  readonly maxFileChunkSize: number;
  readonly fileLanes: number;
  readonly maxFileLanes: number;
  /** Maximum concurrent file operations per peer, applied independently in each direction. */
  readonly maxFileTransfers: number;
  /** Maximum concurrent file operations across all peers, independently in each direction. */
  readonly maxGlobalFileTransfers: number;
  readonly maxFileSize: number;
  readonly maxFileChunks: number;
  readonly maxFileNameBytes: number;
  /** Maximum live local file capabilities. */
  readonly maxFileShares: number;
  /** Maximum capability-operation records across all local shares. */
  readonly maxFileCapabilityOperations: number;
  /** Maximum active or outcome-ambiguous receiver operations per peer. */
  readonly maxFileReconciliationRecords: number;
  /** Maximum active or outcome-ambiguous receiver operations per principal across endpoint keys. */
  readonly maxPrincipalFileReconciliationRecords: number;
  /** Maximum active or outcome-ambiguous receiver operations across the node. */
  readonly maxGlobalFileReconciliationRecords: number;
  /** Maximum recent acknowledged/rejected replay tombstones per peer. */
  readonly maxFileReplayTombstones: number;
  /** Maximum replay tombstones per principal across endpoint keys. */
  readonly maxPrincipalFileReplayTombstones: number;
  /** Maximum replay tombstones across the node. */
  readonly maxGlobalFileReplayTombstones: number;
  readonly fileReconciliationTtlMs: number;
  readonly maxRpcHeaders: number;
  readonly maxRpcHeaderBytes: number;
  readonly maxRpcPathBytes: number;
  /** Per-peer total stream ceiling; directional file-control/data slots plus one RPC slot are reserved. */
  readonly maxInboundStreams: number;
  /** Node-wide total stream ceiling with the same directional reserves. */
  readonly maxGlobalInboundStreams: number;
  /** Aggregate stream quota across one principal, including all directional reserves. */
  readonly maxPrincipalInboundStreams: number;
  readonly maxPeers: number;
  readonly maxPendingHandshakes: number;
  /** Aggregate buffers; includes independent directional file-control/data reserves. */
  readonly maxBufferedBytes: number;
  /** Per-peer buffer ceiling with the same directional reserves. */
  readonly maxPeerBufferedBytes: number;
  /** Per-principal buffer ceiling with the same directional reserves. */
  readonly maxPrincipalBufferedBytes: number;
  readonly maxQueuedOperations: number;
  readonly maxPeerQueuedOperations: number;
  readonly maxPrincipalQueuedOperations: number;
  readonly maxCallbacks: number;
  readonly maxPeerCallbacks: number;
  readonly maxPrincipalCallbacks: number;
  /** Aggregate per-principal file quota, applied independently in each direction. */
  readonly maxPrincipalFileTransfers: number;
  readonly handshakeGlobalBurst: number;
  readonly handshakeGlobalRatePerSecond: number;
  readonly handshakePeerBurst: number;
  readonly handshakePeerRatePerSecond: number;
  readonly maxHandshakePeerEntries: number;
  readonly connectTimeoutMs: number;
  readonly handshakeTimeoutMs: number;
  readonly streamHeaderTimeoutMs: number;
  readonly streamIdleTimeoutMs: number;
  /** Maximum close() wait for owned application/native work. Active accounting remains after timeout. */
  readonly shutdownTimeoutMs: number;
  readonly maxSessionTtlMs: number;
  readonly clockSkewMs: number;
}

export interface AdvancedP2PNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly router: TRouter;
  readonly protocol: ProtocolIdentity;
  readonly createContext: (context: PeerContext<TFileMetadata>) => Promise<inferRouterContext<TRouter>> | inferRouterContext<TRouter>;
  /** Required application authentication and authorization. There is no permissive default. */
  readonly security: SessionSecurity<TFileMetadata>;
  /** Optional cheap endpoint-key filter which runs before the credential handshake. */
  readonly preAuthorizePeer?: (peer: PeerIdentity, signal: AbortSignal) => Promise<boolean> | boolean;
  readonly getRequestHeaders?: (request: {
    readonly peer: PeerIdentity;
    readonly path: string;
    readonly type: 'query' | 'mutation' | 'subscription';
    readonly signal: AbortSignal;
  }) => Promise<RpcHeaderInput | undefined> | RpcHeaderInput | undefined;
  readonly onIncomingFile?: IncomingFileHandler<TFileMetadata>;
  /** Runtime schema required whenever a file manifest contains metadata. */
  readonly fileMetadataSchema?: FileMetadataSchema<TFileMetadata>;
  /** Best-effort notification. Use getPeer()/peersSnapshot() for reliable state lookup. */
  readonly onPeer?: (peer: Peer<AnyTRPCRouter, TFileMetadata>) => void;
  readonly onError?: (error: P2PError, peer?: PeerIdentity) => void;
  readonly onTransferProgress?: (progress: TransferProgress, peer: PeerIdentity) => void;
  /** Structured, credential-free events for an enterprise audit sink. */
  readonly onSecurityEvent?: (event: SecurityAuditEvent) => void;
  readonly iroh?: IrohEndpointOptions;
  readonly limits?: Partial<P2PNodeLimits>;
  /** Primarily for deterministic tests and alternate QUIC transports. */
  readonly endpointFactory?: (alpn: Uint8Array) => Promise<QuicEndpoint>;
}

/** Production-safe root configuration. Raw authenticators and transports live in `/advanced`. */
export type P2PNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> = Omit<
  AdvancedP2PNodeOptions<TRouter, TFileMetadata>,
  'security' | 'endpointFactory'
> & {
  readonly security: PeerBoundSessionSecurity<TFileMetadata>;
  readonly endpointFactory?: never;
};

/** Test-only configuration accepted by `@p2prpc/core/testing`. */
export type TestingP2PNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> = Omit<
  AdvancedP2PNodeOptions<TRouter, TFileMetadata>,
  'security'
> & {
  readonly security?: SessionSecurity<TFileMetadata>;
};

export interface PeerFiles<TFileMetadata = unknown> {
  sendFile(source: FileSource<TFileMetadata>, options?: SendFileOptions): Promise<FileTransfer<TFileMetadata>>;
  download(
    handle: SharedFileHandle,
    destination: FileDestination<TFileMetadata>,
    options?: DownloadFileOptions
  ): Promise<FileTransfer<TFileMetadata>>;
  /** Issue a short-lived capability bound to this endpoint and its authenticated principal. */
  share(source: FileSource<TFileMetadata>, policy?: PeerFileShareOptions): SharedFileHandle;
  /** Revoke a capability previously issued by this local node. */
  revoke(handle: SharedFileHandle): boolean;
}

/** Safe capability controls; endpoint and principal binding are automatic. */
export type PeerFileShareOptions = Omit<PeerSharePolicy, 'allowedPrincipals'>;

export interface PeerDiagnostics {
  readonly sessionId: string;
  readonly connection: ConnectionStats;
  readonly files: FileTransferDiagnostics;
  readonly resources: ResourceSnapshot;
  readonly shares: ShareRegistryDiagnostics;
  readonly tasks: {
    /** Work owned by this authenticated peer runtime, including accept loops. */
    readonly peer: number;
    /** Work owned by the node, including its endpoint accept loop. */
    readonly node: number;
  };
}

const DEFAULT_PEER_CLOSE_REASON = 'Peer closed';
const MAX_PEER_CLOSE_REASON_BYTES = 256;
const HANDSHAKE_BUFFER_BYTES = 64 * 1024;

export class Peer<TRemoteRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly rpc: CreateTRPCClient<TRemoteRouter>;
  readonly files: PeerFiles<TFileMetadata>;

  constructor(private readonly runtime: PeerRuntime<TFileMetadata>) {
    this.rpc = createTRPCProxyClient<TRemoteRouter>({
      links: [irohLink({
        connection: () => runtime.connection(),
        frameLimits: runtime.frameLimits,
        headerLimits: runtime.headerLimits,
        ...(runtime.getRequestHeaders ? {
          getRequestHeaders: (request) => runtime.getRequestHeaders?.(request)
        } : {})
      })]
    });
    this.files = {
      sendFile: (source, options) => runtime.transfers.sendFile(source, options),
      download: (handle, destination, options) => runtime.transfers.download(handle.token, destination, options),
      share: (source, policy) => runtime.share(source, policy),
      revoke: (handle) => runtime.revoke(handle)
    };
  }

  /** Current authenticated connection identity, including its live direction. */
  get identity(): PeerIdentity {
    return this.runtime.identity;
  }

  get session(): AuthenticatedSession {
    return this.runtime.session;
  }

  get principal(): SessionPrincipal {
    return this.runtime.session.principal;
  }

  stats(): Promise<ConnectionStats> {
    return this.runtime.current.stats();
  }

  /** Observe path migration for the current physical connection. */
  async *pathChanges(signal?: AbortSignal): AsyncIterable<ConnectionPath> {
    const connection = await this.runtime.connection();
    if (!connection.pathChanges) {
      throw new P2PError('REJECTED', 'Transport does not expose connection path changes');
    }
    yield* connection.pathChanges(signal);
  }

  async diagnostics(): Promise<PeerDiagnostics> {
    return Object.freeze({
      sessionId: this.runtime.session.id,
      connection: await this.runtime.current.stats(),
      files: this.runtime.transfers.diagnostics(),
      resources: this.runtime.resources(),
      shares: this.runtime.shareDiagnostics(),
      tasks: Object.freeze({
        peer: this.runtime.tasks.size,
        node: this.runtime.nodeTaskCount()
      })
    });
  }

  /** Permanently closes this peer; the display-safe reason is capped at 256 UTF-8 bytes. */
  close(reason = DEFAULT_PEER_CLOSE_REASON): Promise<void> {
    return this.runtime.close(reason);
  }
}

interface ConnectionEpoch {
  readonly connection: QuicConnection;
  readonly files: FileTransferConnectionContext;
  readonly controller: AbortController;
  readonly identity: PeerIdentity;
  readonly session: AuthenticatedSession;
}

type PeerRuntimeLifecycle =
  | {
      readonly state: 'live';
      readonly epoch: ConnectionEpoch;
      readonly outboundTarget?: NormalizedConnectOptions;
    }
  | {
      readonly state: 'disconnected';
      readonly epoch: ConnectionEpoch;
      readonly outboundTarget: NormalizedConnectOptions;
    }
  | {
      readonly state: 'reconnecting';
      readonly epoch: ConnectionEpoch;
      readonly outboundTarget: NormalizedConnectOptions;
      readonly connection: Promise<QuicConnection>;
    }
  | {
      readonly state: 'closing';
      readonly epoch: ConnectionEpoch;
      readonly settlement: Promise<void>;
      readonly publicClose: Promise<void>;
    }
  | {
      readonly state: 'closed';
      readonly epoch: ConnectionEpoch;
      readonly settlement: Promise<void>;
      readonly publicClose: Promise<void>;
    };

type LivePeerRuntimeLifecycle = Extract<PeerRuntimeLifecycle, { readonly state: 'live' }>;

interface AdmissionSelection<TFileMetadata> {
  readonly runtime: PeerRuntime<TFileMetadata>;
  readonly lifecycle: LivePeerRuntimeLifecycle;
  readonly epoch: ConnectionEpoch;
  readonly session: AuthenticatedSession;
}

class AdmissionFinalizationError extends P2PError {
  constructor() {
    super('DISCONNECTED', 'Authenticated peer lost lifecycle ownership before admission completed');
  }
}

interface PeerRuntime<TFileMetadata> {
  lifecycle: PeerRuntimeLifecycle;
  /** Derived compatibility views; lifecycle is the only mutable connection truth. */
  readonly current: QuicConnection;
  readonly currentFiles: FileTransferConnectionContext;
  readonly connectionController: AbortController;
  readonly alive: boolean;
  readonly closed: boolean;
  readonly outboundTarget: NormalizedConnectOptions | undefined;
  readonly identity: PeerIdentity;
  readonly session: AuthenticatedSession;
  readonly transfers: TransferManager<TFileMetadata>;
  readonly tasks: TaskGroup;
  readonly resources: () => ResourceSnapshot;
  readonly shareDiagnostics: () => ShareRegistryDiagnostics;
  readonly nodeTaskCount: () => number;
  share(source: FileSource<TFileMetadata>, policy?: PeerFileShareOptions): SharedFileHandle;
  revoke(handle: SharedFileHandle): boolean;
  readonly headerLimits: { readonly maxCount: number; readonly maxBytes: number };
  readonly frameLimits: FrameLimits;
  readonly getRequestHeaders?: (request: {
    readonly path: string;
    readonly type: 'query' | 'mutation' | 'subscription';
    readonly signal: AbortSignal;
  }) => Promise<RpcHeaderInput | undefined> | RpcHeaderInput | undefined;
  expiryTimer?: ReturnType<typeof setTimeout>;
  connection(): Promise<QuicConnection>;
  fileConnection(): Promise<FileTransferConnectionContext>;
  close(reason: string): Promise<void>;
}

interface AuthorizationSession {
  readonly id: string;
  readonly principal: SessionPrincipal;
}

const DEFAULT_LIMITS: P2PNodeLimits = {
  maxControlFrameBytes: 1024 * 1024,
  maxControlFrameItems: 128 * 1024,
  maxControlFrameDepth: 64,
  fileChunkSize: 1024 * 1024,
  maxFileChunkSize: 4 * 1024 * 1024,
  fileLanes: 4,
  maxFileLanes: 16,
  maxFileTransfers: 4,
  maxGlobalFileTransfers: 16,
  maxFileSize: 16 * 1024 * 1024 * 1024,
  maxFileChunks: 65_536,
  maxFileNameBytes: 255,
  maxFileShares: 10_000,
  maxFileCapabilityOperations: 10_000,
  maxFileReconciliationRecords: 1_024,
  maxPrincipalFileReconciliationRecords: 1_024,
  maxGlobalFileReconciliationRecords: 4_096,
  maxFileReplayTombstones: 1_024,
  maxPrincipalFileReplayTombstones: 2_048,
  maxGlobalFileReplayTombstones: 8_192,
  fileReconciliationTtlMs: 15 * 60_000,
  maxRpcHeaders: 64,
  maxRpcHeaderBytes: 16 * 1024,
  maxRpcPathBytes: 1024,
  maxInboundStreams: 32,
  maxGlobalInboundStreams: 256,
  maxPrincipalInboundStreams: 64,
  maxPeers: 256,
  maxPendingHandshakes: 32,
  maxBufferedBytes: 128 * 1024 * 1024,
  maxPeerBufferedBytes: 32 * 1024 * 1024,
  maxPrincipalBufferedBytes: 64 * 1024 * 1024,
  maxQueuedOperations: 128,
  maxPeerQueuedOperations: 16,
  maxPrincipalQueuedOperations: 32,
  maxCallbacks: 128,
  maxPeerCallbacks: 16,
  maxPrincipalCallbacks: 32,
  maxPrincipalFileTransfers: 8,
  handshakeGlobalBurst: 64,
  handshakeGlobalRatePerSecond: 16,
  handshakePeerBurst: 4,
  handshakePeerRatePerSecond: 1,
  maxHandshakePeerEntries: 4096,
  connectTimeoutMs: 30_000,
  handshakeTimeoutMs: 10_000,
  streamHeaderTimeoutMs: 10_000,
  streamIdleTimeoutMs: 30_000,
  shutdownTimeoutMs: 30_000,
  maxSessionTtlMs: 15 * 60_000,
  clockSkewMs: 30_000
};

export class P2PNode<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly id: string;

  private readonly peers = new Map<string, PeerRuntime<TFileMetadata>>();
  /** Includes disconnected outbound slots retained by public Peer handles. */
  private readonly runtimes: RuntimeSlotRegistry<PeerRuntime<TFileMetadata>>;
  private readonly shares: ShareRegistry<TFileMetadata>;
  private readonly receiverOperations: ReceiverOperationLedger;
  private readonly limits: P2PNodeLimits;
  private readonly protocolName: string;
  private readonly resources: ResourceScheduler;
  private readonly handshakeRate: HandshakeRateLimiter;
  private readonly tasks = new TaskGroup('p2prpc node');
  private readonly shutdownController = new AbortController();
  /** Accepted, unauthenticated connections share one bounded ownership gate. */
  private readonly rejectedConnections = new Set<Promise<void>>();
  private inboundCapacity: ReturnType<typeof deferred<void>> | undefined;
  private pendingHandshakes = 0;
  private closed = false;
  private closeTask?: Promise<void>;

  private constructor(
    private readonly endpoint: QuicEndpoint,
    private readonly alpn: Uint8Array,
    private readonly options: AdvancedP2PNodeOptions<TRouter, TFileMetadata>,
    limits: P2PNodeLimits
  ) {
    this.id = endpoint.id;
    this.limits = limits;
    this.runtimes = new RuntimeSlotRegistry(limits.maxPeers);
    this.protocolName = new TextDecoder().decode(alpn);
    this.shares = new ShareRegistry<TFileMetadata>({
      maxEntries: limits.maxFileShares,
      maxOperations: limits.maxFileCapabilityOperations
    });
    this.receiverOperations = new ReceiverOperationLedger({
      maxOperationRecords: limits.maxFileReconciliationRecords,
      maxReplayTombstones: limits.maxFileReplayTombstones,
      maxPrincipalOperationRecords: limits.maxPrincipalFileReconciliationRecords,
      maxGlobalOperationRecords: limits.maxGlobalFileReconciliationRecords,
      maxPrincipalReplayTombstones: limits.maxPrincipalFileReplayTombstones,
      maxGlobalReplayTombstones: limits.maxGlobalFileReplayTombstones,
      operationRecordTtlMs: limits.fileReconciliationTtlMs
    });
    this.resources = new ResourceScheduler(resourceLimits(limits));
    this.handshakeRate = new HandshakeRateLimiter({
      globalBurst: limits.handshakeGlobalBurst,
      globalRatePerSecond: limits.handshakeGlobalRatePerSecond,
      peerBurst: limits.handshakePeerBurst,
      peerRatePerSecond: limits.handshakePeerRatePerSecond,
      maxPeerEntries: limits.maxHandshakePeerEntries
    });
  }

  static async create<TRouter extends AnyTRPCRouter, TFileMetadata = unknown>(
    options: AdvancedP2PNodeOptions<TRouter, TFileMetadata>
  ): Promise<P2PNode<TRouter, TFileMetadata>> {
    if (
      !options.security ||
      typeof options.security.getCredential !== 'function' ||
      typeof options.security.authenticate !== 'function' ||
      typeof options.security.authorize !== 'function'
    ) {
      throw new P2PError('UNAUTHORIZED', 'A SessionSecurity implementation is required');
    }
    validateNodeConfiguration(options);
    const configuredOptions = snapshotNodeOptions(options);
    const limits = validateLimits({ ...DEFAULT_LIMITS, ...configuredOptions.limits });
    const alpn = protocolIdentifier(configuredOptions.protocol);
    const endpoint = configuredOptions.endpointFactory
      ? await configuredOptions.endpointFactory(alpn)
      : await IrohEndpoint.create(alpn, configuredOptions.iroh);
    try {
      assertTransportAdapterShape(endpoint);
      const node = new P2PNode(endpoint, alpn, configuredOptions, limits);
      node.runAcceptLoop();
      return node;
    } catch (cause) {
      await Promise.resolve(endpoint.close()).catch(() => undefined);
      throw cause;
    }
  }

  ticket(): string {
    return this.endpoint.address.ticket;
  }

  /** Create a signed ticket from the endpoint's current addresses and home relay. */
  createTicket(): Promise<string> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    return this.endpoint.createTicket
      ? this.endpoint.createTicket()
      : Promise.resolve(this.endpoint.address.ticket);
  }

  /** Native endpoint resource gauges for health checks and leak validation. */
  diagnostics(): Promise<EndpointDiagnostics> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    if (!this.endpoint.diagnostics) throw new P2PError('REJECTED', 'Endpoint does not expose diagnostics');
    return this.endpoint.diagnostics();
  }

  /** Advertise this endpoint over LAN mDNS until the optional signal aborts. */
  advertise(options?: EndpointDiscoveryOptions): Promise<void> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    if (!this.endpoint.advertise) throw new P2PError('REJECTED', 'Endpoint does not support mDNS advertisement');
    return this.endpoint.advertise(options);
  }

  /** Browse untrusted LAN mDNS route announcements. */
  browse(options?: EndpointDiscoveryOptions): AsyncIterable<EndpointDiscoveryEvent> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    if (!this.endpoint.browse) throw new P2PError('REJECTED', 'Endpoint does not support mDNS browsing');
    return this.endpoint.browse(options);
  }

  async connect<TRemoteRouter extends AnyTRPCRouter>(options: ConnectOptions): Promise<Peer<TRemoteRouter, TFileMetadata>> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    const target = normalizeConnectOptions(options);
    const existing = this.runtimes.get(target.expectedPeerId);
    if (existing && !existing.closed) {
      assertExpectedPrincipal(existing.session.principal, target.expectedPrincipal);
      this.updateOutboundTarget(existing, target);
      await this.runtimeConnection(existing);
      const admitted = this.finalizeAdmission(this.selectAdmission(existing));
      return new Peer<TRemoteRouter, TFileMetadata>(admitted);
    }
    if (existing) {
      throw new P2PError('DISCONNECTED', `Peer ${target.expectedPeerId} shutdown is still settling`);
    }
    const runtimeClaim = this.runtimes.reserve(target.expectedPeerId);
    try {
      const handshakeLease = await this.resources.acquire(
        target.expectedPeerId,
        { handshakes: 1, bufferedBytes: HANDSHAKE_BUFFER_BYTES },
        this.shutdownController.signal
      );
      const retainedHandshakeWork: Promise<unknown>[] = [];
      const retainHandshakeWork = (work: Promise<unknown>): void => {
        retainedHandshakeWork.push(work);
        void work.catch(() => undefined);
      };
      let handshakeLeaseTransferred = false;
      try {
        const connection = await this.dial(target, retainHandshakeWork);
        handshakeLeaseTransferred = true;
        const runtime = await this.registerConnection(
          connection,
          'outbound',
          runtimeClaim,
          target,
          handshakeLease,
          retainedHandshakeWork
        );
        const admitted = this.finalizeAdmission(this.selectAdmission(runtime));
        return new Peer<TRemoteRouter, TFileMetadata>(admitted);
      } catch (cause) {
        if (!handshakeLeaseTransferred) releaseAfterWork(handshakeLease, retainedHandshakeWork);
        throw cause;
      }
    } finally {
      runtimeClaim.release();
    }
  }

  peersSnapshot(): readonly PeerIdentity[] {
    return Object.freeze([...this.peers.values()].map((runtime) => runtime.identity));
  }

  /** Return a handle for a currently authenticated peer without relying on callback delivery. */
  getPeer<TRemoteRouter extends AnyTRPCRouter>(
    peerId: string
  ): Peer<TRemoteRouter, TFileMetadata> | undefined {
    if (this.closed) return undefined;
    const runtime = this.peers.get(peerId);
    return runtime && runtime.alive && !runtime.closed
      ? new Peer<TRemoteRouter, TFileMetadata>(runtime)
      : undefined;
  }

  close(): Promise<void> {
    if (this.closeTask) return this.closeTask;
    const completion = deferred<void>();
    this.closeTask = completion.promise;
    // Assign the public promise before aborting anything: AbortSignal listeners
    // are synchronous and may re-enter close().
    void this.closeOwned().then(completion.resolve, completion.reject);
    return completion.promise;
  }

  private async closeOwned(): Promise<void> {
    this.closed = true;
    const reason = new P2PError('DISCONNECTED', 'Node is closed');
    const initialCleanup = [
      startCleanup(() => this.runtimes.close(reason)),
      startCleanup(() => this.shutdownController.abort(reason)),
      startCleanup(() => this.shares.close(reason)),
      startCleanup(() => this.receiverOperations.close()),
      startCleanup(() => this.resources.close(reason)),
      startCleanup(() => this.tasks.abort(reason))
    ];
    this.peers.clear();
    // Endpoint teardown starts in the same synchronous pass, before iterating
    // peer shutdowns and before any graceful wait. Adapter throws are observed.
    const endpointClosure = startCleanup(() => this.endpoint.close());
    const runtimeClosures = [...this.runtimes.values()].map((runtime) => {
      const publicClosure = startCleanup(() => runtime.close('Node closed'));
      void publicClosure.catch(() => undefined);
      const lifecycle = runtime.lifecycle;
      return lifecycle.state === 'closing' || lifecycle.state === 'closed'
        ? lifecycle.settlement
        : publicClosure;
    });
    // Start transport teardown immediately; it must not sit behind a callback
    // which ignores cancellation. One deadline covers the whole shutdown, not
    // one serial deadline per component.
    const settlement = Promise.allSettled([
        ...initialCleanup,
        ...runtimeClosures,
        endpointClosure,
        this.tasks.join(),
        this.resources.whenIdle(),
        this.runtimes.whenEmpty()
      ]).then((outcomes) => {
        this.receiverOperations.clear();
        return outcomes;
      });
    const outcomes = await withDeadline(
      settlement,
      this.limits.shutdownTimeoutMs,
      'Node shutdown timed out'
    );
    const failures: unknown[] = outcomes
      .filter((outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected')
      .map((outcome) => outcome.reason);
    if (failures.length > 0) {
      throw new P2PError('INTERNAL', 'Node shutdown encountered cleanup failures', {
        cause: new AggregateError(failures, 'p2prpc shutdown was incomplete')
      });
    }
  }

  private runAcceptLoop(): void {
    void this.tasks.run(async (signal) => {
      while (!this.closed) {
        try {
          // Do not accept native connections that we cannot own. Authentication
          // work and rate-limited close drains consume the same fixed envelope.
          await this.waitForInboundCapacity(signal);
          const connection = await this.endpoint.accept();
          if (!connection) return;
          if (this.closed) {
            this.retireRejectedConnection(connection, 4n, 'Node closed');
            return;
          }
          try {
            this.handshakeRate.admit(connection.remoteId);
          } catch (cause) {
            this.retireRejectedConnection(connection, 5n, 'Handshake rate limited');
            this.reportError(asP2PError(cause, 'RESOURCE_LIMIT'), peerIdentity(connection.remoteId, 'inbound'));
            continue;
          }
          this.pendingHandshakes += 1;
          void this.tasks.run(() => this.registerInboundConnection(connection))
            .catch((cause) => {
              if (!this.closed) {
                this.reportError(
                  asP2PError(cause, 'UNAUTHORIZED'),
                  peerIdentity(connection.remoteId, 'inbound')
                );
              }
            })
            .finally(() => {
              this.pendingHandshakes -= 1;
              this.signalInboundCapacity();
            });
        } catch (cause) {
          if (!this.closed) this.reportError(asP2PError(cause, 'DISCONNECTED'));
        }
      }
    });
  }

  private async waitForInboundCapacity(signal: AbortSignal): Promise<void> {
    while (
      !this.closed &&
      this.pendingHandshakes + this.rejectedConnections.size >= this.limits.maxPendingHandshakes
    ) {
      this.inboundCapacity ??= deferred<void>();
      await withAbortSignal(this.inboundCapacity.promise, signal);
    }
    signal.throwIfAborted();
  }

  private signalInboundCapacity(): void {
    if (
      this.pendingHandshakes + this.rejectedConnections.size >= this.limits.maxPendingHandshakes
    ) return;
    this.inboundCapacity?.resolve();
    this.inboundCapacity = undefined;
  }

  /** Own a pre-admission rejection until fulfilled native closure proof. */
  private retireRejectedConnection(connection: QuicConnection, code: bigint, reason: string): void {
    const physicalClosure = physicalClosureProof(connection);
    this.rejectedConnections.add(physicalClosure);
    this.tasks.track(physicalClosure);
    void physicalClosure.finally(() => {
      this.rejectedConnections.delete(physicalClosure);
      this.signalInboundCapacity();
    }).catch(() => undefined);
    const closeFailure = requestConnectionClose(connection, code, reason);
    if (closeFailure !== undefined) {
      if (!this.closed) {
        this.reportError(asP2PError(closeFailure, 'INTERNAL'), peerIdentity(connection.remoteId, 'inbound'));
      }
    }
  }

  private async registerInboundConnection(
    connection: QuicConnection
  ): Promise<PeerRuntime<TFileMetadata>> {
    let runtimeClaim: RuntimeSlotClaim<PeerRuntime<TFileMetadata>>;
    try {
      runtimeClaim = this.runtimes.reserve(connection.remoteId);
    } catch (cause) {
      this.retireRejectedConnection(connection, 5n, 'Peer runtime limit reached');
      throw cause;
    }
    try {
      return await this.registerConnection(connection, 'inbound', runtimeClaim);
    } finally {
      runtimeClaim.release();
    }
  }

  private async registerConnection(
    connection: QuicConnection,
    direction: PeerIdentity['direction'],
    runtimeClaim: RuntimeSlotClaim<PeerRuntime<TFileMetadata>>,
    outboundTarget?: NormalizedConnectOptions,
    admittedHandshake?: ResourceLease,
    retainedHandshakeWork: Promise<unknown>[] = []
  ): Promise<PeerRuntime<TFileMetadata>> {
    const identity = peerIdentity(connection.remoteId, direction);
    let candidateTransferred = false;
    let candidateRetired = false;
    let selection: AdmissionSelection<TFileMetadata> | undefined;
    let handshakeLease: ResourceLease | undefined = admittedHandshake;
    let physicalClosureTracked = false;
    const retainHandshakeWork = (work: Promise<unknown>): void => {
      retainedHandshakeWork.push(work);
      void work.catch(() => undefined);
    };
    const retainPhysicalClosure = (): void => {
      if (physicalClosureTracked) return;
      physicalClosureTracked = true;
      retainHandshakeWork(physicalClosureProof(connection));
    };
    try {
      if (runtimeClaim.peerId !== identity.id) {
        throw new P2PError('UNAUTHORIZED', 'Runtime reservation does not match the connected endpoint');
      }
      if (outboundTarget && identity.id !== outboundTarget.expectedPeerId) {
        throw new P2PError('UNAUTHORIZED', 'Connected endpoint does not match the expected peer ID');
      }
      handshakeLease ??= await this.resources.acquire(
          identity.id,
          { handshakes: 1, bufferedBytes: HANDSHAKE_BUFFER_BYTES },
          this.shutdownController.signal
        );
      await this.admitPeer(identity, retainHandshakeWork);
      const session = await this.authenticate(connection, direction, retainHandshakeWork);
      if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during authentication');
      if (outboundTarget) assertExpectedPrincipal(session.principal, outboundTarget.expectedPrincipal);

      const existing = this.runtimes.get(identity.id);
      if (existing) {
        assertSamePrincipal(existing.session.principal, session.principal);
        if (outboundTarget) this.updateOutboundTarget(existing, outboundTarget);
        if (!existing.alive || (isPreferredConnection(this.id, connection) && !isPreferredConnection(this.id, existing.current))) {
          selection = this.installConnection(existing, connection, identity, session);
          candidateTransferred = true;
          this.reportAuthenticated(identity, session);
        } else {
          selection = this.selectAdmission(existing);
          // This authenticated duplicate is never transferred to a runtime.
          // Keep its pre-auth admission until native closure actually settles.
          retainPhysicalClosure();
          candidateRetired = true;
          requestConnectionClose(connection, 0n, 'Duplicate connection');
        }
        return this.finalizeAdmission(selection);
      }

      const connectionController = new AbortController();
      const managedConnection = new ManagedConnection(
        connection,
        this.resources,
        resourceOwner(identity.id, session.principal.id),
        connectionController.signal,
        this.limits.maxControlFrameBytes,
        fileDataBufferedBytes(this.limits)
      );
      const currentFiles = fileConnectionContext(
        managedConnection,
        session,
        connectionController,
        (reason) => quarantineConnection(managedConnection, connectionController, reason)
      );
      const epoch = connectionEpoch(managedConnection, currentFiles, connectionController, identity, session);
      const runtimeTasks = new TaskGroup(`peer ${identity.id}`);
      const runtime: PeerRuntime<TFileMetadata> = {
        lifecycle: liveLifecycle(epoch, outboundTarget),
        get current() { return runtime.lifecycle.epoch.connection; },
        get currentFiles() { return runtime.lifecycle.epoch.files; },
        get connectionController() { return runtime.lifecycle.epoch.controller; },
        get alive() { return runtime.lifecycle.state === 'live'; },
        get closed() { return runtime.lifecycle.state === 'closing' || runtime.lifecycle.state === 'closed'; },
        get outboundTarget() {
          const lifecycle = runtime.lifecycle;
          return lifecycle.state === 'live' || lifecycle.state === 'disconnected' || lifecycle.state === 'reconnecting'
            ? lifecycle.outboundTarget
            : undefined;
        },
        get identity() { return runtime.lifecycle.epoch.identity; },
        get session() { return runtime.lifecycle.epoch.session; },
        tasks: runtimeTasks,
        resources: () => this.resources.snapshot(),
        shareDiagnostics: () => this.shares.diagnostics(),
        nodeTaskCount: () => this.tasks.size,
        share: (source, policy = {}) => {
          this.assertAuthorizationSession(runtime, {
            id: runtime.session.id,
            principal: runtime.session.principal
          });
          return this.shares.shareForPeer(
            source,
            runtime.identity.id,
            policy,
            runtime.session.principal
          );
        },
        revoke: (handle) => this.shares.revoke(handle),
        headerLimits: { maxCount: this.limits.maxRpcHeaders, maxBytes: this.limits.maxRpcHeaderBytes },
        frameLimits: controlFrameLimits(this.limits),
        ...(this.options.getRequestHeaders ? {
          getRequestHeaders: (request) => this.withCallback(
            runtime.identity.id,
            runtime.session.principal.id,
            request.signal,
            () => this.options.getRequestHeaders?.(Object.freeze({
              peer: runtime.identity,
              ...request
            }))
          )
        } : {}),
        transfers: new TransferManager<TFileMetadata>({
          peerId: identity.id,
          connection: () => runtime.fileConnection(),
          shares: this.shares,
          authorize: (action, captured, signal) => this.authorize(runtime, {
            id: captured.sessionId,
            principal: captured.principal
          }, action, signal),
          acquireTransfer: async (direction, signal) => {
            const lease = await this.resources.acquire(
              resourceOwner(runtime.identity.id, runtime.session.principal.id),
              direction === 'outbound' ? { outboundTransfers: 1 } : { inboundTransfers: 1 },
              signal
            );
            return lease.release;
          },
          ...(this.options.onIncomingFile ? {
            incoming: (offer) => this.withCallback(
              runtime.identity.id,
              offer.principal.id,
              offer.signal,
              () => this.options.onIncomingFile!(offer)
            )
          } : {}),
          ...(this.options.fileMetadataSchema ? { metadataSchema: this.options.fileMetadataSchema } : {}),
          limits: {
            chunkSize: this.limits.fileChunkSize,
            maxChunkSize: this.limits.maxFileChunkSize,
            lanes: this.limits.fileLanes,
            maxLanes: this.limits.maxFileLanes,
            maxTransfers: this.limits.maxFileTransfers,
            maxFileSize: this.limits.maxFileSize,
            maxChunkCount: this.limits.maxFileChunks,
            maxNameBytes: this.limits.maxFileNameBytes
          },
          idleTimeoutMs: this.limits.streamIdleTimeoutMs,
          maxOperationRecords: this.limits.maxFileReconciliationRecords,
          maxReplayTombstones: this.limits.maxFileReplayTombstones,
          operationRecordTtlMs: this.limits.fileReconciliationTtlMs,
          receiverOperations: this.receiverOperations,
          frameLimits: controlFrameLimits(this.limits),
          onProgress: (progress) => this.reportBestEffortCallback(
            resourceOwner(runtime.identity.id, runtime.session.principal.id),
            () => this.options.onTransferProgress?.(progress, runtime.identity)
          )
        }),
        connection: async () => this.runtimeConnection(runtime),
        fileConnection: async () => this.runtimeFileConnection(runtime),
        close: (reason) => this.closeRuntime(runtime, reason)
      };
      runtimeClaim.commit(runtime);
      candidateTransferred = true;
      this.peers.set(identity.id, runtime);
      selection = this.selectAdmission(runtime);
      this.startConnectionLoops(runtime, epoch);
      this.scheduleExpiry(runtime, epoch);
      this.reportAuthenticated(identity, session);
      const admittedRuntime = this.finalizeAdmission(selection);
      if (this.options.onPeer) {
        const notificationSelection = selection;
        queueMicrotask(() => {
          let notificationRuntime: PeerRuntime<TFileMetadata>;
          try {
            notificationRuntime = this.finalizeAdmission(notificationSelection);
          } catch (cause) {
            if (!(cause instanceof AdmissionFinalizationError)) {
              this.reportError(asP2PError(cause), identity);
            }
            return;
          }
          this.reportBestEffortCallback(
            resourceOwner(identity.id, session.principal.id),
            () => this.options.onPeer!(new Peer<AnyTRPCRouter, TFileMetadata>(notificationRuntime)),
            (cause) => this.reportError(asP2PError(cause), identity)
          );
        });
      }
      return admittedRuntime;
    } catch (cause) {
      if (!candidateTransferred && !candidateRetired) {
        // Subscribe before requesting close so a transport cannot discard the
        // only physical-settlement proof together with its native handle.
        retainPhysicalClosure();
        requestConnectionClose(connection, 4n, 'Application authentication failed');
      }
      const error = asP2PError(cause, 'UNAUTHORIZED');
      if (!(cause instanceof AdmissionFinalizationError)) {
        this.reportSecurity({
          type: 'session.rejected',
          timestamp: Date.now(),
          peerId: identity.id,
          direction,
          code: error.code
        });
      }
      throw error;
    } finally {
      if (handshakeLease) releaseAfterWork(handshakeLease, retainedHandshakeWork);
    }
  }

  private closeRuntime(runtime: PeerRuntime<TFileMetadata>, reason: string): Promise<void> {
    const lifecycle = runtime.lifecycle;
    if (lifecycle.state === 'closing' || lifecycle.state === 'closed') return lifecycle.publicClose;
    const safeReason = safePeerCloseReason(reason);
    const completion = deferred<void>();
    const publicClose = withDeadline(
      completion.promise,
      this.limits.shutdownTimeoutMs,
      `Peer ${lifecycle.epoch.identity.id} shutdown timed out`
    );
    // Publish terminal state before invoking cancellation. Abort listeners are
    // synchronous and may re-enter Peer.close() or node.close().
    runtime.lifecycle = Object.freeze({
      state: 'closing',
      epoch: lifecycle.epoch,
      settlement: completion.promise,
      publicClose
    });
    void this.settlePeerClose(runtime, lifecycle.epoch, safeReason).then(completion.resolve, completion.reject);
    return publicClose;
  }

  private async settlePeerClose(
    runtime: PeerRuntime<TFileMetadata>,
    epoch: ConnectionEpoch,
    safeReason: string
  ): Promise<void> {
    if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
    if (this.peers.get(epoch.identity.id) === runtime) this.peers.delete(epoch.identity.id);

    const current = epoch.connection;
    const error = new P2PError('DISCONNECTED', safeReason);
    // Subscribe to the physical close proof before requesting close. Never
    // race this barrier against the session signal we abort below.
    const physicalClosure = startCleanup(() => current.closed());
    const cleanup = [
      startCleanup(() => runtime.transfers.close(error)),
      startCleanup(() => epoch.controller.abort(error)),
      startCleanup(() => runtime.tasks.abort(error)),
      startCleanup(() => requestConnectionClose(current, 0n, safeReason)),
      startCleanup(() => runtime.tasks.join()),
      // Include pre-authentication ownership, whose principal is intentionally
      // unknown, as well as every authenticated lease for this endpoint key.
      startCleanup(() => this.resources.whenOwnerIdle(epoch.identity.id)),
      physicalClosure
    ];
    const outcomes = await Promise.allSettled(cleanup);
    const failures = rejectedReasons(outcomes);
    if (failures.length > 0) {
      throw new P2PError('INTERNAL', `Peer ${epoch.identity.id} shutdown encountered cleanup failures`, {
        cause: new AggregateError(failures, 'p2prpc peer shutdown was incomplete')
      });
    }
    this.runtimes.delete(epoch.identity.id, runtime);
    const lifecycle = runtime.lifecycle;
    if (lifecycle.state === 'closing' && lifecycle.epoch === epoch) {
      runtime.lifecycle = Object.freeze({ ...lifecycle, state: 'closed' });
    }
  }

  private authenticate(
    connection: QuicConnection,
    direction: PeerIdentity['direction'],
    trackWork?: (work: Promise<unknown>) => void
  ): Promise<AuthenticatedSession> {
    const owner = this.options.security;
    const security: SessionSecurity<TFileMetadata> = Object.freeze({
      getCredential: (context: CredentialRequestContext) => this.withOwnedCallback(
        connection.remoteId,
        context.signal,
        () => owner.getCredential(context)
      ),
      authenticate: (credential: SessionCredential, context: SessionAuthenticationContext) => this.withOwnedCallback(
        connection.remoteId,
        context.signal,
        () => owner.authenticate(credential, context)
      ),
      // The handshake never authorizes operations; retain the exact snapshotted
      // implementation so the wrapper still satisfies SessionSecurity.
      authorize: (context: AuthorizationContext<TFileMetadata>) => owner.authorize(context)
    });
    return authenticateConnection(connection, direction, {
      localPeerId: this.id,
      protocol: this.protocolName,
      security,
      timeoutMs: this.limits.handshakeTimeoutMs,
      maxSessionTtlMs: this.limits.maxSessionTtlMs,
      clockSkewMs: this.limits.clockSkewMs,
      frameLimits: controlFrameLimits(this.limits, 64 * 1024),
      ...(trackWork ? { trackWork } : {})
    });
  }

  private async dial(
    target: NormalizedConnectOptions,
    trackWork?: (work: Promise<unknown>) => void,
    cancellation?: AbortSignal
  ): Promise<QuicConnection> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    const controller = new AbortController();
    const abortFromShutdown = (): void => {
      controller.abort(this.shutdownController.signal.reason ?? new P2PError('DISCONNECTED', 'Node is closed'));
    };
    if (this.shutdownController.signal.aborted) abortFromShutdown();
    else this.shutdownController.signal.addEventListener('abort', abortFromShutdown, { once: true });
    const abortFromCancellation = (): void => {
      controller.abort(cancellation?.reason ?? new P2PError('CANCELLED', 'Peer connection was cancelled'));
    };
    if (cancellation?.aborted) abortFromCancellation();
    else cancellation?.addEventListener('abort', abortFromCancellation, { once: true });

    const pending = Promise.resolve().then(() => {
      if (this.endpoint.connectLocator) {
        return this.endpoint.connectLocator(
          target.locator,
          this.alpn,
          target.expectedPeerId,
          controller.signal
        );
      }
      if (target.locator.kind !== 'ticket') {
        throw new P2PError('REJECTED', 'Endpoint supports signed-ticket locators only');
      }
      return this.endpoint.connect(target.locator.ticket, this.alpn, target.expectedPeerId);
    });
    trackWork?.(pending);
    try {
      const connection = await withDeadline(
        pending,
        this.limits.connectTimeoutMs,
        'Peer connection timed out',
        controller
      );
      controller.signal.throwIfAborted();
      if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed while connecting');
      return connection;
    } catch (cause) {
      const lateClosure = pending.then(
        async (connection) => {
          const physicallyClosed = physicalClosureProof(connection);
          requestConnectionClose(connection, 4n, 'Late or cancelled connection');
          await physicallyClosed;
        },
        () => undefined
      );
      trackWork?.(lateClosure);
      void lateClosure.catch(() => undefined);
      throw asP2PError(cause, 'DISCONNECTED');
    } finally {
      this.shutdownController.signal.removeEventListener('abort', abortFromShutdown);
      cancellation?.removeEventListener('abort', abortFromCancellation);
    }
  }

  private async runtimeConnection(runtime: PeerRuntime<TFileMetadata>): Promise<QuicConnection> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    let lifecycle = runtime.lifecycle;
    if (lifecycle.state === 'closing' || lifecycle.state === 'closed') {
      throw new P2PError('DISCONNECTED', 'Peer is closed');
    }
    if (lifecycle.state === 'reconnecting') {
      const connection = await lifecycle.connection;
      const selected = this.finalizeAdmission(this.selectAdmission(runtime));
      if (selected.current !== connection) throw new AdmissionFinalizationError();
      return connection;
    }
    if (lifecycle.state === 'live' && this.peers.get(lifecycle.epoch.identity.id) === runtime) {
      if (lifecycle.epoch.session.expiresAt > Date.now()) {
        return this.finalizeAdmission(this.selectAdmission(runtime, lifecycle)).current;
      }
      this.expireEpoch(runtime, lifecycle.epoch);
      lifecycle = runtime.lifecycle;
    }
    if (lifecycle.state !== 'disconnected') {
      throw new P2PError('DISCONNECTED', `Peer ${lifecycle.epoch.identity.id} is disconnected`);
    }
    const reconnecting = (async () => {
      if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
      if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer is closed');
      const target = lifecycle.outboundTarget;
      const handshakeLease = await this.resources.acquire(
        resourceOwner(runtime.identity.id, runtime.session.principal.id),
        { handshakes: 1, bufferedBytes: HANDSHAKE_BUFFER_BYTES },
        runtime.tasks.signal
      );
      const retainedHandshakeWork: Promise<unknown>[] = [];
      const retainHandshakeWork = (work: Promise<unknown>): void => {
        retainedHandshakeWork.push(work);
        void work.catch(() => undefined);
      };
      let connection: QuicConnection | undefined;
      let physicalClosureTracked = false;
      let connectionRetired = false;
      let connectionTransferred = false;
      let selection: AdmissionSelection<TFileMetadata> | undefined;
      const retireReconnection = (reason: string): void => {
        if (!connection || connectionRetired || connectionTransferred) return;
        connectionRetired = true;
        if (!physicalClosureTracked) {
          physicalClosureTracked = true;
          // A connection which never became runtime-owned remains charged to
          // its handshake admission until native closure is proven.
          retainHandshakeWork(physicalClosureProof(connection));
        }
        requestConnectionClose(connection, 4n, reason);
      };
      try {
        connection = await this.dial(target, retainHandshakeWork, runtime.tasks.signal);
        if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during reconnection');
        if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer closed during reconnection');
        if (connection.remoteId !== target.expectedPeerId || connection.remoteId !== runtime.identity.id) {
          throw new P2PError('UNAUTHORIZED', 'Reconnection endpoint identity does not match the expected peer');
        }
        const identity = peerIdentity(connection.remoteId, 'outbound');
        await this.admitPeer(identity, retainHandshakeWork);
        const session = await this.authenticate(connection, 'outbound', retainHandshakeWork);
        if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during reauthentication');
        if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer closed during reauthentication');
        assertExpectedPrincipal(session.principal, target.expectedPrincipal);
        assertSamePrincipal(runtime.session.principal, session.principal);
        const incumbent = this.peers.get(identity.id);
        if (incumbent && incumbent !== runtime) {
          throw new P2PError('DISCONNECTED', 'Peer already has a newer authenticated connection');
        }
        if (incumbent === runtime && runtime.alive) {
          // An inbound connection may have authenticated while this outbound
          // reconnect was in flight. Apply the same deterministic arbitration
          // as normal duplicate admission; never let completion order decide.
          const candidatePreferred = isPreferredConnection(this.id, connection);
          const incumbentPreferred = isPreferredConnection(this.id, runtime.current);
          if (!candidatePreferred || incumbentPreferred) {
            selection = this.selectAdmission(runtime);
            retireReconnection('Duplicate connection');
            return this.finalizeAdmission(selection).current;
          }
        }
        selection = this.installConnection(runtime, connection, identity, session);
        connectionTransferred = true;
        this.reportAuthenticated(identity, session);
        // installConnection wraps the native connection with mandatory
        // resource accounting. No caller may observe the unwrapped candidate.
        return this.finalizeAdmission(selection).current;
      } catch (cause) {
        retireReconnection('Reauthentication failed');
        const error = asP2PError(cause, 'UNAUTHORIZED');
        if (!(cause instanceof AdmissionFinalizationError)) {
          this.reportSecurity({
            type: 'session.rejected',
            timestamp: Date.now(),
            peerId: runtime.identity.id,
            direction: 'outbound',
            code: error.code
          });
        }
        throw error;
      } finally {
        releaseAfterWork(handshakeLease, retainedHandshakeWork);
      }
    })();
    runtime.lifecycle = Object.freeze({
      state: 'reconnecting',
      epoch: lifecycle.epoch,
      outboundTarget: lifecycle.outboundTarget,
      connection: reconnecting
    });
    let connection: QuicConnection;
    try {
      connection = await reconnecting;
    } finally {
      const current = runtime.lifecycle;
      if (current.state === 'reconnecting' && current.connection === reconnecting) {
        runtime.lifecycle = Object.freeze({
          state: 'disconnected',
          epoch: current.epoch,
          outboundTarget: current.outboundTarget
        });
      }
    }
    const admitted = this.finalizeAdmission(this.selectAdmission(runtime));
    if (admitted.current !== connection) throw new AdmissionFinalizationError();
    return connection;
  }

  private async runtimeFileConnection(runtime: PeerRuntime<TFileMetadata>): Promise<FileTransferConnectionContext> {
    const connection = await this.runtimeConnection(runtime);
    const context = runtime.currentFiles;
    if (context.connection !== connection || context.signal.aborted) {
      throw new P2PError('DISCONNECTED', 'Authenticated file connection is no longer active');
    }
    return context;
  }

  private installConnection(
    runtime: PeerRuntime<TFileMetadata>,
    connection: QuicConnection,
    identity: PeerIdentity,
    session: AuthenticatedSession
  ): AdmissionSelection<TFileMetadata> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    const incumbent = runtime.lifecycle;
    if (incumbent.state === 'closing' || incumbent.state === 'closed') {
      throw new P2PError('DISCONNECTED', 'Peer is closed');
    }
    if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
    const connectionController = new AbortController();
    const managedConnection = new ManagedConnection(
      connection,
      this.resources,
      resourceOwner(identity.id, session.principal.id),
      connectionController.signal,
      this.limits.maxControlFrameBytes,
      fileDataBufferedBytes(this.limits)
    );
    const currentFiles = fileConnectionContext(
      managedConnection,
      session,
      connectionController,
      (reason) => quarantineConnection(managedConnection, connectionController, reason)
    );
    const epoch = connectionEpoch(managedConnection, currentFiles, connectionController, identity, session);
    const outboundTarget = incumbent.outboundTarget;
    // Publish one immutable epoch before invoking any synchronous cancellation
    // listener attached to the old epoch. Reentrant close observes the new
    // epoch and makes it terminal before this method can start new loops.
    const lifecycle = liveLifecycle(epoch, outboundTarget);
    runtime.lifecycle = lifecycle;
    this.peers.set(identity.id, runtime);
    const selection = this.selectAdmission(runtime, lifecycle);
    incumbent.epoch.controller.abort(new P2PError('DISCONNECTED', 'Authenticated connection was replaced'));
    requestConnectionClose(incumbent.epoch.connection, 0n, 'Superseded connection');
    if (isLiveEpoch(runtime, epoch) && !this.closed) {
      this.startConnectionLoops(runtime, epoch);
      this.scheduleExpiry(runtime, epoch);
    } else {
      connectionController.abort(new P2PError('DISCONNECTED', 'Peer closed while installing connection'));
      requestConnectionClose(managedConnection, 0n, 'Peer closed during replacement');
    }
    return selection;
  }

  /** Capture the exact live state chosen by duplicate arbitration or installation. */
  private selectAdmission(
    runtime: PeerRuntime<TFileMetadata>,
    lifecycle: PeerRuntimeLifecycle = runtime.lifecycle
  ): AdmissionSelection<TFileMetadata> {
    if (lifecycle.state !== 'live') {
      throw new P2PError('DISCONNECTED', 'Authenticated peer is no longer live');
    }
    return Object.freeze({
      runtime,
      lifecycle,
      epoch: lifecycle.epoch,
      session: lifecycle.epoch.session
    });
  }

  /**
   * Linearize admission success after every synchronous audit, cancellation,
   * and transport-close callout made for the selected connection.
   */
  private finalizeAdmission(
    selection: AdmissionSelection<TFileMetadata>
  ): PeerRuntime<TFileMetadata> {
    const { runtime, lifecycle, epoch, session } = selection;
    const current = runtime.lifecycle;
    if (
      this.closed ||
      this.runtimes.get(epoch.identity.id) !== runtime ||
      this.peers.get(epoch.identity.id) !== runtime ||
      current !== lifecycle ||
      current.state !== 'live' ||
      current.epoch !== epoch ||
      epoch.session !== session ||
      session.expiresAt <= Date.now()
    ) {
      throw new AdmissionFinalizationError();
    }
    return runtime;
  }

  private async admitPeer(
    identity: PeerIdentity,
    trackWork?: (work: Promise<unknown>) => void
  ): Promise<void> {
    if (!this.options.preAuthorizePeer) return;
    const controller = new AbortController();
    const admission = this.withOwnedCallback(
      identity.id,
      controller.signal,
      () => this.options.preAuthorizePeer!(identity, controller.signal)
    );
    trackWork?.(admission);
    const allowed = await withDeadline(
      admission,
      this.limits.handshakeTimeoutMs,
      'Peer admission timed out',
      controller
    );
    controller.signal.throwIfAborted();
    if (allowed !== true) throw new P2PError('UNAUTHORIZED', `Peer ${identity.id} was rejected`);
  }

  private startConnectionLoops(runtime: PeerRuntime<TFileMetadata>, epoch: ConnectionEpoch): void {
    const connection = epoch.connection;
    const session = epoch.session;
    const fileContext = epoch.files;
    const connectionController = epoch.controller;
    // This is the terminal ownership barrier for every native stream attached
    // to this physical connection. A reset/stop failure cannot safely release
    // stream admission until the transport confirms that the connection (and
    // therefore all of its streams) has settled.
    const closureObservation = Promise.resolve().then(() => connection.closed());
    const physicalClosure = closureObservation.then(
      () => undefined,
      // A rejected lifecycle observation is not physical closure proof. Keep
      // every native-stream owner charged instead of reporting false idle.
      () => new Promise<void>(() => undefined)
    );
    runtime.tasks.track(physicalClosure);
    const rpc = new RpcServer({
      router: this.options.router,
      createContext: async (request) => {
        const files: P2PRequestFiles<TFileMetadata> = Object.freeze({
          share: (source: FileSource<TFileMetadata>, policy: PeerFileShareOptions = {}) => {
            this.assertAuthorizationSession(runtime, session);
            return this.shares.shareForPeer(
              source,
              runtime.identity.id,
              policy,
              session.principal
            );
          },
          revoke: (handle: SharedFileHandle) => {
            this.assertAuthorizationSession(runtime, session);
            return this.shares.revoke(handle);
          }
        });
        const p2p: P2PRequestContext<TFileMetadata> = Object.freeze({
        peer: runtime.identity,
        auth: session,
        request,
        connection: Object.freeze({ stats: () => connection.stats() }),
        files
        });
        const seed: PeerContext<TFileMetadata> = Object.freeze({ p2p });
        const application = await this.withCallback(
          runtime.identity.id,
          session.principal.id,
          request.signal,
          () => this.options.createContext(seed)
        );
        if (!isPlainRecord(application)) {
          throw new P2PError('INTERNAL', 'P2P node context factory must return a plain object');
        }
        if (Object.hasOwn(application, 'p2p') && application.p2p !== p2p) {
          throw new P2PError('UNAUTHORIZED', 'Application context cannot replace the reserved p2p namespace');
        }
        return Object.freeze({ ...application, p2p }) as inferRouterContext<TRouter>;
      },
      authorize: (request, signal) => this.authorize(runtime, session, {
        kind: 'rpc',
        path: request.path,
        type: request.type,
        headers: request.headers
      }, signal),
      frameLimits: controlFrameLimits(this.limits),
      headerLimits: { maxCount: this.limits.maxRpcHeaders, maxBytes: this.limits.maxRpcHeaderBytes },
      maxPathBytes: this.limits.maxRpcPathBytes,
      setupTimeoutMs: this.limits.streamHeaderTimeoutMs,
      sessionSignal: connectionController.signal,
      onError: (error) => this.reportError(asP2PError(error), runtime.identity)
    });

    void runtime.tasks.run(async () => {
      while (isLiveEpoch(runtime, epoch) && !this.closed) {
        let stream: Awaited<ReturnType<QuicConnection['acceptBi']>> | undefined;
        let streamLease: ResourceLease | undefined;
        try {
          const pendingAccept = connection.acceptBi();
          try {
            stream = await withAbortSignal(pendingAccept, connectionController.signal);
          } catch (cause) {
            void pendingAccept.then(
              async (late) => {
                if (!await settleStream(late, 5n, this.limits.streamHeaderTimeoutMs)) {
                  quarantineConnection(connection, connectionController, 'Late bidirectional stream cleanup failed');
                }
              },
              () => undefined
            );
            throw cause;
          }
          // QUIC does not expose application stream type at accept time. Read
          // only the bounded one-byte discriminator before admission, and do
          // so in this sequential loop: each authenticated connection can own
          // at most one pre-admission BI stream. Charging unknown streams to a
          // general or file reserve would let one class consume another
          // class's guaranteed progress path.
          const kind = await withDeadline(
            readStreamKind(stream.recv),
            this.limits.streamHeaderTimeoutMs,
            'Stream header timed out'
          );
          this.assertCurrentSession(runtime, connection, session);
          if (kind !== StreamKind.Rpc && kind !== StreamKind.TransferControl) {
            throw new P2PError('INVALID_FRAME', `Invalid bidirectional stream kind ${kind}`);
          }
          const owner = resourceOwner(runtime.identity.id, session.principal.id);
          streamLease = kind === StreamKind.Rpc
            ? this.resources.tryAcquire(owner, {
              streams: 1,
              bufferedBytes: this.limits.maxControlFrameBytes
            })
            : this.resources.tryAcquire(owner, {
              streams: 1,
              bufferedBytes: this.limits.maxControlFrameBytes,
              fileControl: 'inbound'
            });
          if (!streamLease) {
            throw new P2PError(
              'RESOURCE_LIMIT',
              kind === StreamKind.Rpc
                ? 'Inbound RPC capacity is unavailable'
                : 'Inbound file-control capacity is unavailable'
            );
          }
          const accepted = stream;
          const lease = streamLease;
          stream = undefined;
          streamLease = undefined;
          // Once admitted, the lease remains owned even if shutdown starts
          // between dispatch and handler startup.
          runtime.tasks.track((async () => {
            const ownership = retainLeaseForWork(lease);
            try {
              this.assertCurrentSession(runtime, connection, session);
              if (kind === StreamKind.Rpc) {
                return await rpc.handle(accepted, ownership.track);
              }
              if (kind === StreamKind.TransferControl) {
                return await runtime.transfers.handleControl(accepted, fileContext, ownership.track);
              }
              throw new P2PError('INVALID_FRAME', `Invalid bidirectional stream kind ${kind}`);
            } catch (cause) {
              if (!await settleStream(accepted, 1n, this.limits.streamHeaderTimeoutMs)) {
                ownership.track(physicalClosure);
                quarantineConnection(connection, connectionController, 'Bidirectional stream cleanup failed');
              }
              this.reportError(asP2PError(cause), runtime.identity);
            } finally {
              ownership.complete();
            }
          })());
        } catch (cause) {
          const mayAcceptAnother = stream !== undefined;
          if (stream) {
            const cleaned = await settleStream(stream, 5n, this.limits.streamHeaderTimeoutMs);
            if (!cleaned) {
              if (streamLease) releaseAfterWork(streamLease, [physicalClosure]);
              quarantineConnection(connection, connectionController, 'Unadmitted bidirectional stream cleanup failed');
            } else {
              streamLease?.release();
            }
          } else {
            streamLease?.release();
          }
          if (
            mayAcceptAnother &&
            !connectionController.signal.aborted &&
            isLiveEpoch(runtime, epoch) &&
            !this.closed
          ) {
            this.reportError(asP2PError(cause), runtime.identity);
            continue;
          }
          break;
        }
      }
    });

    void runtime.tasks.run(async () => {
      while (isLiveEpoch(runtime, epoch) && !this.closed) {
        let recv: Awaited<ReturnType<QuicConnection['acceptUni']>> | undefined;
        let lease: ResourceLease | undefined;
        try {
          const pendingAccept = connection.acceptUni();
          try {
            recv = await withAbortSignal(pendingAccept, connectionController.signal);
          } catch (cause) {
            void pendingAccept.then(
              async (late) => {
                if (!await settleWithin(Promise.resolve().then(() => late.stop(5n)), this.limits.streamHeaderTimeoutMs)) {
                  quarantineConnection(connection, connectionController, 'Late file stream cleanup failed');
                }
              },
              () => undefined
            );
            throw cause;
          }
          lease = await this.resources.acquire(resourceOwner(runtime.identity.id, session.principal.id), {
            streams: 1,
            bufferedBytes: fileDataBufferedBytes(this.limits),
            fileData: 'inbound'
          }, connectionController.signal);
          const accepted = recv;
          const streamLease = lease;
          recv = undefined;
          lease = undefined;
          runtime.tasks.track((async () => {
            const ownership = retainLeaseForWork(streamLease);
            try {
              const kind = await withDeadline(
                readStreamKind(accepted),
                this.limits.streamHeaderTimeoutMs,
                'Stream header timed out'
              );
              this.assertCurrentSession(runtime, connection, session);
              if (kind !== StreamKind.TransferData) throw new P2PError('INVALID_FRAME', `Invalid unidirectional stream kind ${kind}`);
              await runtime.transfers.handleData(accepted, fileContext);
            } catch (cause) {
              if (!await settleWithin(Promise.resolve().then(() => accepted.stop(1n)), this.limits.streamHeaderTimeoutMs)) {
                ownership.track(physicalClosure);
                quarantineConnection(connection, connectionController, 'File stream cleanup failed');
              }
              this.reportError(asP2PError(cause), runtime.identity);
            } finally {
              ownership.complete();
            }
          })());
        } catch {
          if (recv) {
            const cleaned = await settleWithin(
              Promise.resolve().then(() => recv!.stop(5n)),
              this.limits.streamHeaderTimeoutMs
            );
            if (!cleaned) {
              if (lease) releaseAfterWork(lease, [physicalClosure]);
              quarantineConnection(connection, connectionController, 'Unadmitted file stream cleanup failed');
            } else {
              lease?.release();
            }
          } else {
            lease?.release();
          }
          break;
        }
      }
    });

    // The signal-bounded watcher below drives session state, but the physical
    // connection remains owned even after supersession aborts that watcher.
    // Otherwise a final Peer.close() could report clean settlement while an
    // older native connection was still closing in the background.
    void runtime.tasks.track(withAbortSignal(closureObservation, connectionController.signal).then(
      () => {
        connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection closed'));
        if (isLiveEpoch(runtime, epoch)) {
          this.disconnectEpoch(runtime, epoch);
          if (this.peers.get(epoch.identity.id) === runtime) this.peers.delete(epoch.identity.id);
          if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
          if (!epochOutboundTarget(runtime, epoch)) {
            void this.tasks.track(runtime.close('Inbound peer connection closed')).catch(() => undefined);
          }
        }
      },
      (cause) => {
        if ((runtime.lifecycle.state === 'closing' || runtime.lifecycle.state === 'closed') && connectionController.signal.aborted) return;
        connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection failed', { cause }));
        if (isLiveEpoch(runtime, epoch)) {
          this.disconnectEpoch(runtime, epoch);
          if (this.peers.get(epoch.identity.id) === runtime) this.peers.delete(epoch.identity.id);
          if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
          if (!epochOutboundTarget(runtime, epoch)) {
            void this.tasks.track(runtime.close('Inbound peer connection failed')).catch(() => undefined);
          }
        }
      }
    ));
  }

  private assertCurrentSession(
    runtime: PeerRuntime<TFileMetadata>,
    connection: QuicConnection,
    session: AuthenticatedSession
  ): void {
    const lifecycle = runtime.lifecycle;
    if (
      this.closed ||
      lifecycle.state !== 'live' ||
      this.peers.get(lifecycle.epoch.identity.id) !== runtime ||
      lifecycle.epoch.connection !== connection ||
      lifecycle.epoch.session !== session ||
      session.expiresAt <= Date.now()
    ) {
      throw new P2PError('UNAUTHORIZED', 'Authenticated session is no longer active');
    }
  }

  private async authorize(
    runtime: PeerRuntime<TFileMetadata>,
    session: AuthorizationSession,
    action: AuthorizationAction<TFileMetadata>,
    requestSignal?: AbortSignal
  ): Promise<void> {
    this.assertAuthorizationSession(runtime, session);
    const checkedAction = freezeAuthorizationAction(action);
    const controller = new AbortController();
    const abortFromRequest = (): void => {
      controller.abort(requestSignal?.reason ?? new P2PError('CANCELLED', 'Authorization cancelled'));
    };
    if (requestSignal?.aborted) abortFromRequest();
    else requestSignal?.addEventListener('abort', abortFromRequest, { once: true });

    let decision: ReturnType<typeof authorizationAllowed>;
    try {
      decision = authorizationAllowed(await withDeadline(
        this.withOwnedCallback(
          resourceOwner(runtime.identity.id, session.principal.id),
          controller.signal,
          () => this.options.security.authorize(Object.freeze({
            principal: session.principal,
            localPeerId: this.id,
            remotePeerId: runtime.identity.id,
            sessionId: session.id,
            action: checkedAction,
            signal: controller.signal
          }))
        ),
        this.limits.streamHeaderTimeoutMs,
        'Authorization timed out',
        controller
      ));
      controller.signal.throwIfAborted();
      this.assertAuthorizationSession(runtime, session);
    } catch (cause) {
      this.reportSecurity({
        type: 'authorization',
        timestamp: Date.now(),
        peerId: runtime.identity.id,
        sessionId: session.id,
        principalId: session.principal.id,
        action: summarizeSecurityAction(checkedAction),
        allowed: false,
        reason: 'Authorization evaluation failed'
      });
      throw cause;
    } finally {
      requestSignal?.removeEventListener('abort', abortFromRequest);
    }
    const safeReason = decision.reason === undefined ? undefined : safeAuditReason(decision.reason);
    this.reportSecurity({
      type: 'authorization',
      timestamp: Date.now(),
      peerId: runtime.identity.id,
      sessionId: session.id,
      principalId: session.principal.id,
      action: summarizeSecurityAction(checkedAction),
      allowed: decision.allowed,
      ...(safeReason !== undefined ? { reason: safeReason } : {})
    });
    if (!decision.allowed) throw new P2PError('UNAUTHORIZED', safeReason ?? 'Operation is not authorized');
  }

  private assertAuthorizationSession(
    runtime: PeerRuntime<TFileMetadata>,
    session: AuthorizationSession
  ): void {
    const lifecycle = runtime.lifecycle;
    if (
      this.closed ||
      lifecycle.state !== 'live' ||
      this.peers.get(lifecycle.epoch.identity.id) !== runtime ||
      lifecycle.epoch.session.id !== session.id ||
      lifecycle.epoch.session.principal !== session.principal ||
      lifecycle.epoch.session.expiresAt <= Date.now()
    ) {
      throw new P2PError('UNAUTHORIZED', 'Authenticated session is no longer active');
    }
  }

  private updateOutboundTarget(
    runtime: PeerRuntime<TFileMetadata>,
    target: NormalizedConnectOptions
  ): void {
    const lifecycle = runtime.lifecycle;
    if (lifecycle.state === 'closing' || lifecycle.state === 'closed') {
      throw new P2PError('DISCONNECTED', 'Peer is closed');
    }
    runtime.lifecycle = Object.freeze({ ...lifecycle, outboundTarget: target });
  }

  private disconnectEpoch(runtime: PeerRuntime<TFileMetadata>, epoch: ConnectionEpoch): void {
    const lifecycle = runtime.lifecycle;
    if (lifecycle.state !== 'live' || lifecycle.epoch !== epoch || !lifecycle.outboundTarget) return;
    runtime.lifecycle = Object.freeze({
      state: 'disconnected',
      epoch,
      outboundTarget: lifecycle.outboundTarget
    });
  }

  private expireEpoch(runtime: PeerRuntime<TFileMetadata>, epoch: ConnectionEpoch): void {
    if (!isLiveEpoch(runtime, epoch)) return;
    const outboundTarget = epochOutboundTarget(runtime, epoch);
    if (outboundTarget) {
      runtime.lifecycle = Object.freeze({ state: 'disconnected', epoch, outboundTarget });
      if (this.peers.get(epoch.identity.id) === runtime) this.peers.delete(epoch.identity.id);
      epoch.controller.abort(new P2PError('DISCONNECTED', 'Authenticated session expired'));
      requestConnectionClose(epoch.connection, 4n, 'Session expired');
    } else {
      void this.tasks.track(runtime.close('Authenticated session expired')).catch(() => undefined);
    }
    this.reportSecurity({
      type: 'session.expired',
      timestamp: Date.now(),
      peerId: epoch.identity.id,
      sessionId: epoch.session.id,
      principalId: epoch.session.principal.id
    });
  }

  private scheduleExpiry(runtime: PeerRuntime<TFileMetadata>, epoch: ConnectionEpoch): void {
    const session = epoch.session;
    const schedule = (): void => {
      const remaining = session.expiresAt - Date.now();
      if (remaining <= 0) {
        if (isLiveEpoch(runtime, epoch)) {
          // Expiry is a logical session boundary, not a transport lifecycle
          // observation. Remove the runtime from the public live-peer view in
          // the same timer turn; native connection ownership can continue to
          // settle in the background without exposing an expired session.
          this.expireEpoch(runtime, epoch);
        }
        return;
      }
      runtime.expiryTimer = setTimeout(schedule, Math.min(remaining, 0x7fff_ffff));
      runtime.expiryTimer.unref?.();
    };
    schedule();
  }

  private reportError(error: P2PError, peer?: PeerIdentity): void {
    const runtime = peer ? this.runtimesForPeer(peer.id) : undefined;
    this.reportBestEffortCallback(
      runtime
        ? resourceOwner(peer!.id, runtime.session.principal.id)
        : peer?.id ?? this.id,
      () => this.options.onError?.(error, peer)
    );
  }

  private reportAuthenticated(identity: PeerIdentity, session: AuthenticatedSession): void {
    this.reportSecurity({
      type: 'session.authenticated',
      timestamp: Date.now(),
      peerId: identity.id,
      direction: identity.direction,
      sessionId: session.id,
      principalId: session.principal.id,
      expiresAt: session.expiresAt
    });
  }

  private reportSecurity(event: SecurityAuditEvent): void {
    const owner = 'principalId' in event
      ? resourceOwner(event.peerId, event.principalId)
      : event.peerId;
    this.reportBestEffortCallback(owner, () => this.options.onSecurityEvent?.(Object.freeze(event)));
  }

  private async withCallback<T>(
    peerId: string,
    principalId: string,
    signal: AbortSignal,
    operation: () => Promise<T> | T
  ): Promise<T> {
    return this.withOwnedCallback(resourceOwner(peerId, principalId), signal, operation);
  }

  private async withOwnedCallback<T>(
    owner: string | Readonly<{ peerId: string; principalId: string }>,
    signal: AbortSignal,
    operation: () => Promise<T> | T
  ): Promise<T> {
    const lease = await this.resources.acquire(
      owner,
      { callbacks: 1 },
      signal
    );
    try {
      signal.throwIfAborted();
      return await operation();
    } finally {
      lease.release();
    }
  }

  private reportBestEffortCallback(
    owner: string | Readonly<{ peerId: string; principalId: string }> | undefined,
    operation: () => unknown,
    onFailure?: (cause: unknown) => void
  ): void {
    if (!owner) return;
    try {
      const lease = this.resources.tryAcquire(owner, { callbacks: 1 });
      if (!lease) return;
      let delivered: unknown;
      try {
        delivered = operation();
      } catch (cause) {
        lease.release();
        onFailure?.(cause);
        return;
      }
      void Promise.resolve(delivered).then(
        () => lease.release(),
        (cause) => {
          lease.release();
          onFailure?.(cause);
        }
      );
    } catch {
      // Best-effort observability cannot affect protocol state or shutdown.
    }
  }

  private runtimesForPeer(peerId: string): PeerRuntime<TFileMetadata> | undefined {
    const runtime = this.runtimes.get(peerId);
    return runtime && !runtime.closed ? runtime : undefined;
  }
}

function fileConnectionContext(
  connection: QuicConnection,
  session: AuthenticatedSession,
  controller: AbortController,
  quarantine: (reason: string) => void
): FileTransferConnectionContext {
  return Object.freeze({
    connection,
    security: Object.freeze({ principal: session.principal, sessionId: session.id }),
    signal: controller.signal,
    quarantine
  });
}

function connectionEpoch(
  connection: QuicConnection,
  files: FileTransferConnectionContext,
  controller: AbortController,
  identity: PeerIdentity,
  session: AuthenticatedSession
): ConnectionEpoch {
  return Object.freeze({ connection, files, controller, identity, session });
}

function liveLifecycle(
  epoch: ConnectionEpoch,
  outboundTarget?: NormalizedConnectOptions
): PeerRuntimeLifecycle {
  return Object.freeze({
    state: 'live',
    epoch,
    ...(outboundTarget ? { outboundTarget } : {})
  });
}

function isLiveEpoch<TFileMetadata>(runtime: PeerRuntime<TFileMetadata>, epoch: ConnectionEpoch): boolean {
  return runtime.lifecycle.state === 'live' && runtime.lifecycle.epoch === epoch;
}

function epochOutboundTarget<TFileMetadata>(
  runtime: PeerRuntime<TFileMetadata>,
  epoch: ConnectionEpoch
): NormalizedConnectOptions | undefined {
  const lifecycle = runtime.lifecycle;
  return lifecycle.epoch === epoch && (
    lifecycle.state === 'live' || lifecycle.state === 'disconnected' || lifecycle.state === 'reconnecting'
  )
    ? lifecycle.outboundTarget
    : undefined;
}

function isPreferredConnection(localId: string, connection: QuicConnection): boolean {
  return localId < connection.remoteId ? connection.side === 'client' : connection.side === 'server';
}

function peerIdentity(id: string, direction: PeerIdentity['direction']): PeerIdentity {
  return Object.freeze({ id, direction });
}

function resourceOwner(peerId: string, principalId: string): Readonly<{ peerId: string; principalId: string }> {
  return Object.freeze({ peerId, principalId });
}

/**
 * A wire handler may finish before non-cooperative application work it
 * started. This counter transfers one admission lease to all such work and
 * releases it only after the handler and every registered promise settle.
 */
function retainLeaseForWork(lease: ResourceLease): {
  readonly track: (work: Promise<unknown>) => void;
  readonly complete: () => void;
} {
  let owners = 1;
  let released = false;
  const releaseOwner = (): void => {
    owners -= 1;
    if (owners === 0 && !released) {
      released = true;
      lease.release();
    }
  };
  return Object.freeze({
    track(work: Promise<unknown>) {
      if (released) throw new P2PError('INTERNAL', 'Cannot register work after its resource lease was released');
      owners += 1;
      void work.then(releaseOwner, releaseOwner);
    },
    complete: releaseOwner
  });
}

function releaseAfterWork(lease: ResourceLease, work: readonly Promise<unknown>[]): void {
  if (work.length === 0) {
    lease.release();
    return;
  }
  void Promise.allSettled(work).then(() => lease.release());
}

function summarizeSecurityAction<TFileMetadata>(
  action: AuthorizationAction<TFileMetadata>
): Readonly<Record<string, string | number>> {
  if (action.kind === 'rpc') return Object.freeze({ kind: action.kind, path: action.path, procedureType: action.type });
  if (action.kind === 'file.push') {
    return Object.freeze({
      kind: action.kind,
      transferId: action.manifest.transferId,
      size: action.manifest.size
    });
  }
  return Object.freeze({ kind: action.kind, capabilityId: action.capabilityId });
}

function freezeAuthorizationAction<TFileMetadata>(
  action: AuthorizationAction<TFileMetadata>
): AuthorizationAction<TFileMetadata> {
  if (action.kind === 'rpc') {
    return Object.freeze({ kind: action.kind, path: action.path, type: action.type, headers: action.headers });
  }
  if (action.kind === 'file.push') return Object.freeze({ kind: action.kind, manifest: action.manifest });
  return Object.freeze({ kind: action.kind, capabilityId: action.capabilityId });
}

function safeAuditReason(value: string): string {
  return sanitizeBoundedDisplayText(value, 256, 'Authorization decision supplied no reason');
}

function safePeerCloseReason(value: unknown): string {
  return typeof value === 'string'
    ? sanitizeBoundedDisplayText(value, MAX_PEER_CLOSE_REASON_BYTES, DEFAULT_PEER_CLOSE_REASON)
    : DEFAULT_PEER_CLOSE_REASON;
}

function normalizeConnectOptions(value: ConnectOptions): NormalizedConnectOptions {
  if (!isPlainRecord(value)) {
    throw new P2PError('INVALID_FRAME', 'Outbound connect options must be a plain object');
  }
  assertOnlyKeys(value, ['locator', 'expectedPeerId', 'expectedPrincipal'], 'Outbound connect options');
  if (!Object.hasOwn(value, 'locator')) {
    throw new P2PError('INVALID_FRAME', 'Outbound connect options must include an explicit locator');
  }
  const locator = normalizeLocator(value.locator);
  const expectedPeerId = boundedExpectedString(value.expectedPeerId, 2048, 'Expected peer ID');
  const expectedPrincipal = normalizePrincipalMatcher(value.expectedPrincipal);
  return Object.freeze({ locator, expectedPeerId, expectedPrincipal });
}

function normalizeLocator(value: unknown): PeerLocator {
  if (!isPlainRecord(value)) throw new P2PError('INVALID_FRAME', 'Outbound locator must be a plain object');
  if (value.kind === 'ticket') {
    assertOnlyKeys(value, ['kind', 'ticket'], 'Ticket locator');
    return Object.freeze({
      kind: 'ticket',
      ticket: boundedExpectedString(value.ticket, 64 * 1024, 'Outbound ticket')
    });
  }
  if (value.kind === 'dns') {
    assertOnlyKeys(value, ['kind'], 'DNS locator');
    return Object.freeze({ kind: 'dns' });
  }
  if (value.kind === 'mdns') {
    assertOnlyKeys(value, ['kind', 'serviceName'], 'mDNS locator');
    if (value.serviceName === undefined) return Object.freeze({ kind: 'mdns' });
    const serviceName = boundedExpectedString(value.serviceName, 63, 'mDNS service name');
    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(serviceName)) {
      throw new P2PError('INVALID_FRAME', 'mDNS service name is invalid');
    }
    return Object.freeze({ kind: 'mdns', serviceName });
  }
  throw new P2PError('INVALID_FRAME', 'Outbound locator kind is invalid');
}

function normalizePrincipalMatcher(value: unknown): Readonly<PrincipalMatcher> {
  if (!isPlainRecord(value)) {
    throw new P2PError('INVALID_FRAME', 'Expected principal matcher must be a plain object');
  }
  assertOnlyKeys(value, ['id', 'subject', 'issuer', 'clientId', 'tenantId'], 'Expected principal matcher');
  for (const field of ['subject', 'issuer', 'clientId', 'tenantId'] as const) {
    if (!Object.hasOwn(value, field)) {
      throw new P2PError('INVALID_FRAME', `Expected principal matcher must specify ${field}`);
    }
  }
  const subject = boundedExpectedString(value.subject, 2048, 'Expected principal subject');
  const issuer = nullableExpectedString(value.issuer, 4096, 'Expected principal issuer');
  const clientId = nullableExpectedString(value.clientId, 2048, 'Expected principal client ID');
  const tenantId = nullableExpectedString(value.tenantId, 2048, 'Expected principal tenant ID');
  const id = value.id === undefined
    ? undefined
    : boundedExpectedString(value.id, 2048, 'Expected principal ID');
  return Object.freeze({
    ...(id !== undefined ? { id } : {}),
    subject,
    issuer,
    clientId,
    tenantId
  });
}

function assertExpectedPrincipal(principal: SessionPrincipal, matcher: PrincipalMatcher): void {
  if (
    (matcher.id !== undefined && principal.id !== matcher.id) ||
    principal.subject !== matcher.subject ||
    (principal.issuer ?? null) !== matcher.issuer ||
    (principal.clientId ?? null) !== matcher.clientId ||
    (principal.tenantId ?? null) !== matcher.tenantId
  ) {
    throw new P2PError('UNAUTHORIZED', 'Authenticated principal does not match the expected target');
  }
}

function nullableExpectedString(value: unknown, maximumBytes: number, label: string): string | null {
  return value === null ? null : boundedExpectedString(value, maximumBytes, label);
}

function boundedExpectedString(value: unknown, maximumBytes: number, label: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    Buffer.byteLength(value) > maximumBytes ||
    containsUnsafeDisplayCharacters(value)
  ) {
    throw new P2PError('INVALID_FRAME', `${label} must be a bounded safe string`);
  }
  return value;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertOnlyKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new P2PError('INVALID_FRAME', `${label} contains an unknown field`);
  }
}

function assertSamePrincipal(current: SessionPrincipal, replacement: SessionPrincipal): void {
  if (
    current.id !== replacement.id ||
    current.subject !== replacement.subject ||
    current.issuer !== replacement.issuer ||
    current.clientId !== replacement.clientId ||
    current.tenantId !== replacement.tenantId
  ) {
    throw new P2PError('UNAUTHORIZED', 'A connection cannot replace a session authenticated as a different principal');
  }
}

function deferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
  readonly reject: (reason?: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

/** Invoke cleanup now while converting synchronous adapter throws to rejection. */
function startCleanup(operation: () => unknown): Promise<void> {
  try {
    return Promise.resolve(operation()).then(() => undefined);
  } catch (cause) {
    return Promise.reject(cause);
  }
}

function physicalClosureProof(connection: QuicConnection): Promise<void> {
  return startCleanup(() => connection.closed()).then(
    () => undefined,
    // A rejected closed() observation is an adapter failure, not proof that
    // the native connection and its pre-authentication streams are gone.
    () => new Promise<void>(() => undefined)
  );
}

function rejectedReasons(outcomes: readonly PromiseSettledResult<unknown>[]): unknown[] {
  return outcomes
    .filter((outcome): outcome is PromiseRejectedResult => outcome.status === 'rejected')
    .map((outcome) => outcome.reason);
}

async function withDeadline<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
  controller?: AbortController
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let removeAbortListener: (() => void) | undefined;
  try {
    const tasks: Array<Promise<T>> = [
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const error = new P2PError('TIMEOUT', message);
          controller?.abort(error);
          reject(error);
        }, timeoutMs);
        timer.unref?.();
      })
    ];
    if (controller) {
      tasks.push(new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(
          controller.signal.reason ?? new P2PError('CANCELLED', 'Operation cancelled')
        );
        if (controller.signal.aborted) onAbort();
        else {
          controller.signal.addEventListener('abort', onAbort, { once: true });
          removeAbortListener = () => controller.signal.removeEventListener('abort', onAbort);
        }
      }));
    }
    return await Promise.race(tasks);
  } finally {
    if (timer) clearTimeout(timer);
    removeAbortListener?.();
  }
}

async function withAbortSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let removeAbortListener: (() => void) | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        const onAbort = (): void => reject(
          signal.reason ?? new P2PError('CANCELLED', 'Operation cancelled')
        );
        signal.addEventListener('abort', onAbort, { once: true });
        removeAbortListener = () => signal.removeEventListener('abort', onAbort);
      })
    ]);
  } finally {
    removeAbortListener?.();
  }
}

function validateLimits(limits: P2PNodeLimits): P2PNodeLimits {
  const integer = (name: keyof P2PNodeLimits, minimum: number, maximum: number): void => {
    const value = limits[name];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new P2PError('RESOURCE_LIMIT', `${name} must be between ${minimum} and ${maximum}`);
    }
  };
  integer('maxControlFrameBytes', 1024, 16 * 1024 * 1024);
  integer('maxControlFrameItems', 1, 1_000_000);
  integer('maxControlFrameDepth', 1, 256);
  integer('fileChunkSize', 64 * 1024, 16 * 1024 * 1024);
  integer('maxFileChunkSize', 64 * 1024, 16 * 1024 * 1024);
  integer('fileLanes', 1, 64);
  integer('maxFileLanes', 1, 64);
  integer('maxFileTransfers', 1, 1_024);
  integer('maxGlobalFileTransfers', 1, 65_536);
  integer('maxFileSize', 1, Number.MAX_SAFE_INTEGER);
  integer('maxFileChunks', 1, 1_000_000);
  integer('maxFileNameBytes', 1, 4096);
  integer('maxFileShares', 1, 1_000_000);
  integer('maxFileCapabilityOperations', 1, 1_000_000);
  integer('maxFileReconciliationRecords', 1, 100_000);
  integer('maxPrincipalFileReconciliationRecords', 1, 100_000);
  integer('maxGlobalFileReconciliationRecords', 1, 100_000);
  integer('maxFileReplayTombstones', 1, 100_000);
  integer('maxPrincipalFileReplayTombstones', 1, 100_000);
  integer('maxGlobalFileReplayTombstones', 1, 100_000);
  integer('fileReconciliationTtlMs', 1_000, 24 * 60 * 60_000);
  integer('maxRpcHeaders', 0, 256);
  integer('maxRpcHeaderBytes', 0, 64 * 1024);
  integer('maxRpcPathBytes', 1, 16 * 1024);
  integer('maxInboundStreams', 1, 65_536);
  integer('maxGlobalInboundStreams', 1, 1_000_000);
  integer('maxPrincipalInboundStreams', 1, 1_000_000);
  integer('maxPeers', 1, 1_000_000);
  integer('maxPendingHandshakes', 1, 4_096);
  integer('maxBufferedBytes', 64 * 1024, 2 * 1024 * 1024 * 1024);
  integer('maxPeerBufferedBytes', 64 * 1024, 2 * 1024 * 1024 * 1024);
  integer('maxPrincipalBufferedBytes', 64 * 1024, 2 * 1024 * 1024 * 1024);
  integer('maxQueuedOperations', 1, 1_000_000);
  integer('maxPeerQueuedOperations', 1, 1_000_000);
  integer('maxPrincipalQueuedOperations', 1, 1_000_000);
  integer('maxCallbacks', 1, 1_000_000);
  integer('maxPeerCallbacks', 1, 1_000_000);
  integer('maxPrincipalCallbacks', 1, 1_000_000);
  integer('maxPrincipalFileTransfers', 1, 65_536);
  integer('handshakeGlobalBurst', 1, 1_000_000);
  integer('handshakeGlobalRatePerSecond', 1, 1_000_000);
  integer('handshakePeerBurst', 1, 1_000_000);
  integer('handshakePeerRatePerSecond', 1, 1_000_000);
  integer('maxHandshakePeerEntries', 1, 1_000_000);
  integer('connectTimeoutMs', 100, 120_000);
  integer('handshakeTimeoutMs', 100, 120_000);
  integer('streamHeaderTimeoutMs', 100, 120_000);
  integer('streamIdleTimeoutMs', 1_000, 10 * 60_000);
  integer('shutdownTimeoutMs', 100, 10 * 60_000);
  integer('maxSessionTtlMs', 1_000, 24 * 60 * 60_000);
  integer('clockSkewMs', 0, 10 * 60_000);
  if (
    limits.maxFileReconciliationRecords > limits.maxPrincipalFileReconciliationRecords ||
    limits.maxPrincipalFileReconciliationRecords > limits.maxGlobalFileReconciliationRecords
  ) {
    throw new P2PError(
      'RESOURCE_LIMIT',
      'File reconciliation limits must be ordered per-peer <= per-principal <= global'
    );
  }
  if (
    limits.maxFileReplayTombstones > limits.maxPrincipalFileReplayTombstones ||
    limits.maxPrincipalFileReplayTombstones > limits.maxGlobalFileReplayTombstones
  ) {
    throw new P2PError(
      'RESOURCE_LIMIT',
      'File replay-tombstone limits must be ordered per-peer <= per-principal <= global'
    );
  }
  if (limits.fileChunkSize > limits.maxFileChunkSize) {
    throw new P2PError('RESOURCE_LIMIT', 'fileChunkSize cannot exceed maxFileChunkSize');
  }
  if (limits.fileLanes > limits.maxFileLanes) throw new P2PError('RESOURCE_LIMIT', 'fileLanes cannot exceed maxFileLanes');
  if (limits.maxGlobalFileTransfers > limits.maxGlobalInboundStreams) {
    throw new P2PError('RESOURCE_LIMIT', 'maxGlobalFileTransfers cannot exceed maxGlobalInboundStreams');
  }
  if (
    limits.maxInboundStreams < 5 ||
    limits.maxGlobalInboundStreams < 5 ||
    limits.maxPrincipalInboundStreams < 5
  ) {
    throw new P2PError(
      'RESOURCE_LIMIT',
      'Stream quotas must admit RPC plus independent inbound/outbound file controls and data lanes'
    );
  }
  const minimumFileBuffer = 3 * limits.maxControlFrameBytes + 2 * fileDataBufferedBytes(limits);
  if (
    limits.maxBufferedBytes < minimumFileBuffer ||
    limits.maxPeerBufferedBytes < minimumFileBuffer ||
    limits.maxPrincipalBufferedBytes < minimumFileBuffer
  ) {
    throw new P2PError(
      'RESOURCE_LIMIT',
      'Buffer quotas must admit RPC plus independent inbound/outbound file controls and data lanes'
    );
  }
  return Object.freeze(limits);
}

function resourceLimits(limits: P2PNodeLimits): ResourceLimits {
  const fileDataBuffer = fileDataBufferedBytes(limits);
  return Object.freeze({
    global: Object.freeze({
      handshakes: limits.maxPendingHandshakes,
      streams: limits.maxGlobalInboundStreams,
      outboundTransfers: limits.maxGlobalFileTransfers,
      inboundTransfers: limits.maxGlobalFileTransfers,
      bufferedBytes: limits.maxBufferedBytes,
      callbacks: limits.maxCallbacks,
      queued: limits.maxQueuedOperations
    }),
    perPeer: Object.freeze({
      handshakes: 1,
      streams: Math.min(limits.maxInboundStreams, limits.maxGlobalInboundStreams),
      outboundTransfers: Math.min(limits.maxFileTransfers, limits.maxGlobalFileTransfers),
      inboundTransfers: Math.min(limits.maxFileTransfers, limits.maxGlobalFileTransfers),
      bufferedBytes: Math.min(limits.maxPeerBufferedBytes, limits.maxBufferedBytes),
      callbacks: Math.min(limits.maxPeerCallbacks, limits.maxCallbacks),
      queued: Math.min(limits.maxPeerQueuedOperations, limits.maxQueuedOperations)
    }),
    perPrincipal: Object.freeze({
      handshakes: limits.maxPendingHandshakes,
      streams: Math.min(limits.maxPrincipalInboundStreams, limits.maxGlobalInboundStreams),
      outboundTransfers: Math.min(limits.maxPrincipalFileTransfers, limits.maxGlobalFileTransfers),
      inboundTransfers: Math.min(limits.maxPrincipalFileTransfers, limits.maxGlobalFileTransfers),
      bufferedBytes: Math.min(limits.maxPrincipalBufferedBytes, limits.maxBufferedBytes),
      callbacks: Math.min(limits.maxPrincipalCallbacks, limits.maxCallbacks),
      queued: Math.min(limits.maxPrincipalQueuedOperations, limits.maxQueuedOperations)
    }),
    fileDataReserve: Object.freeze({
      global: directionalFileDataReserve(fileDataBuffer),
      perPeer: directionalFileDataReserve(fileDataBuffer),
      perPrincipal: directionalFileDataReserve(fileDataBuffer)
    }),
    fileControlReserve: Object.freeze({
      global: directionalFileDataReserve(limits.maxControlFrameBytes),
      perPeer: directionalFileDataReserve(limits.maxControlFrameBytes),
      perPrincipal: directionalFileDataReserve(limits.maxControlFrameBytes)
    }),
    generalReserve: Object.freeze({
      global: Object.freeze({ streams: 1, bufferedBytes: limits.maxControlFrameBytes }),
      perPeer: Object.freeze({ streams: 1, bufferedBytes: limits.maxControlFrameBytes }),
      perPrincipal: Object.freeze({ streams: 1, bufferedBytes: limits.maxControlFrameBytes })
    })
  });
}

function fileDataBufferedBytes(limits: Pick<P2PNodeLimits, 'maxControlFrameBytes' | 'maxFileChunkSize'>): number {
  return Math.max(limits.maxControlFrameBytes, limits.maxFileChunkSize + FILE_DATA_SEGMENT_BYTES);
}

function directionalFileDataReserve(bufferedBytes: number) {
  return Object.freeze({
    outbound: Object.freeze({ streams: 1, bufferedBytes }),
    inbound: Object.freeze({ streams: 1, bufferedBytes })
  });
}

async function settleStream(
  stream: Awaited<ReturnType<QuicConnection['acceptBi']>>,
  code: bigint,
  timeoutMs: number
): Promise<boolean> {
  const settled = await Promise.all([
    settleWithin(Promise.resolve().then(() => stream.send.reset(code)), timeoutMs),
    settleWithin(Promise.resolve().then(() => stream.recv.stop(code)), timeoutMs)
  ]);
  return settled.every(Boolean);
}

async function settleWithin(task: Promise<unknown>, timeoutMs: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const settled = await Promise.race([
    task.then(() => true, () => false),
    new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), timeoutMs);
      timer.unref?.();
    })
  ]);
  if (timer) clearTimeout(timer);
  return settled;
}

function quarantineConnection(
  connection: QuicConnection,
  controller: AbortController,
  reason: string
): void {
  const error = new P2PError('INTERNAL', reason);
  if (!controller.signal.aborted) controller.abort(error);
  requestConnectionClose(connection, 4n, 'Stream cleanup failed');
}

/**
 * Request logical connection shutdown without letting a defective custom
 * adapter replace the operation's primary outcome. Callers which need closure
 * proof subscribe to `closed()` before this request and retain that barrier.
 */
function requestConnectionClose(
  connection: QuicConnection,
  code: bigint,
  reason: string
): unknown | undefined {
  try {
    connection.close(code, new TextEncoder().encode(reason));
    return undefined;
  } catch (cause) {
    return cause;
  }
}

function validateNodeConfiguration<TRouter extends AnyTRPCRouter, TFileMetadata>(
  options: AdvancedP2PNodeOptions<TRouter, TFileMetadata>
): void {
  if (!isPlainRecord(options)) {
    throw new P2PError('INVALID_FRAME', 'P2P node options must be a plain object');
  }
  assertOnlyKeys(options, [
    'router',
    'protocol',
    'createContext',
    'security',
    'preAuthorizePeer',
    'getRequestHeaders',
    'onIncomingFile',
    'fileMetadataSchema',
    'onPeer',
    'onError',
    'onTransferProgress',
    'onSecurityEvent',
    'iroh',
    'limits',
    'endpointFactory'
  ], 'P2P node options');
  if (typeof options.createContext !== 'function') {
    throw new P2PError('INVALID_FRAME', 'P2P node context factory must be a function');
  }
  const configured = options;
  for (const name of [
    'preAuthorizePeer',
    'getRequestHeaders',
    'onIncomingFile',
    'onPeer',
    'onError',
    'onTransferProgress',
    'onSecurityEvent',
    'endpointFactory'
  ] as const) {
    if (configured[name] !== undefined && typeof configured[name] !== 'function') {
      throw new P2PError('INVALID_FRAME', `P2P node ${name} option must be a function`);
    }
  }
  if (!isPlainRecord(configured.protocol)) {
    throw new P2PError('INVALID_FRAME', 'P2P node protocol must be a plain object');
  }
  assertOnlyKeys(configured.protocol, ['applicationId', 'contractVersion'], 'P2P node protocol');
  if (configured.limits !== undefined) {
    if (!isPlainRecord(configured.limits)) {
      throw new P2PError('INVALID_FRAME', 'P2P node limits must be a plain object');
    }
    assertOnlyKeys(configured.limits, Object.keys(DEFAULT_LIMITS), 'P2P node limits');
  }
  if (configured.fileMetadataSchema !== undefined) {
    validateMetadataSchemaConfiguration(configured.fileMetadataSchema);
  }
  if (configured.iroh !== undefined && !isPlainRecord(configured.iroh)) {
    throw new P2PError('INVALID_FRAME', 'P2P node iroh options must be a plain object');
  }
}

function snapshotNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata>(
  options: AdvancedP2PNodeOptions<TRouter, TFileMetadata>
): AdvancedP2PNodeOptions<TRouter, TFileMetadata> {
  const owner = options.security;
  const getCredential = owner.getCredential;
  const authenticate = owner.authenticate;
  const authorize = owner.authorize;
  const security: SessionSecurity<TFileMetadata> = Object.freeze({
    getCredential: (context: CredentialRequestContext) => getCredential.call(owner, context),
    authenticate: (credential: SessionCredential, context: SessionAuthenticationContext) => (
      authenticate.call(owner, credential, context)
    ),
    authorize: (context: AuthorizationContext<TFileMetadata>) => authorize.call(owner, context)
  });
  const iroh = options.iroh === undefined
    ? undefined
    : Object.freeze({
        ...options.iroh,
        ...(options.iroh.secretKey !== undefined
          ? { secretKey: Uint8Array.from(options.iroh.secretKey) }
          : {}),
        ...(options.iroh.bindAddress !== undefined
          ? {
              bindAddress: typeof options.iroh.bindAddress === 'string'
                ? options.iroh.bindAddress
                : Object.freeze([...options.iroh.bindAddress])
            }
          : {}),
        ...(options.iroh.relay !== undefined
          ? {
              relay: Object.freeze(options.iroh.relay.mode === 'custom'
                ? { mode: 'custom' as const, urls: Object.freeze([...options.iroh.relay.urls]) }
                : { mode: options.iroh.relay.mode })
            }
          : {}),
        ...(options.iroh.discovery !== undefined
          ? {
              discovery: Object.freeze({
                ...options.iroh.discovery,
                ...(typeof options.iroh.discovery.dns === 'object'
                  ? { dns: Object.freeze({ ...options.iroh.discovery.dns }) }
                  : {}),
                ...(typeof options.iroh.discovery.mdns === 'object'
                  ? { mdns: Object.freeze({ ...options.iroh.discovery.mdns }) }
                  : {})
              })
            }
          : {}),
        ...(options.iroh.relayUrls !== undefined
          ? { relayUrls: Object.freeze([...options.iroh.relayUrls]) }
          : {})
      });
  const fileMetadataSchema = options.fileMetadataSchema === undefined
    ? undefined
    : snapshotMetadataSchema(options.fileMetadataSchema);
  return Object.freeze({
    ...options,
    security,
    ...(fileMetadataSchema !== undefined ? { fileMetadataSchema } : {}),
    ...(iroh !== undefined ? { iroh } : {})
  });
}

function validateMetadataSchemaConfiguration<TMetadata>(schema: FileMetadataSchema<TMetadata>): void {
  if (!isPlainRecord(schema)) throw new P2PError('INVALID_FRAME', 'File metadata schema must be a plain object');
  assertOnlyKeys(schema, ['~standard'], 'File metadata schema');
  const standard = schema['~standard'];
  if (!isPlainRecord(standard)) throw new P2PError('INVALID_FRAME', 'File metadata schema descriptor must be a plain object');
  assertOnlyKeys(standard, ['version', 'vendor', 'validate'], 'File metadata schema descriptor');
  if (
    standard.version !== 1 ||
    typeof standard.vendor !== 'string' ||
    standard.vendor.length < 1 ||
    Buffer.byteLength(standard.vendor) > 256 ||
    containsUnsafeDisplayCharacters(standard.vendor) ||
    typeof standard.validate !== 'function'
  ) {
    throw new P2PError('INVALID_FRAME', 'File metadata schema does not implement Standard Schema v1');
  }
}

function snapshotMetadataSchema<TMetadata>(schema: FileMetadataSchema<TMetadata>): FileMetadataSchema<TMetadata> {
  validateMetadataSchemaConfiguration(schema);
  const owner = schema['~standard'];
  const validate = owner.validate;
  return Object.freeze({
    '~standard': Object.freeze({
      version: 1 as const,
      vendor: owner.vendor,
      validate: (value: unknown) => validate.call(owner, value)
    })
  });
}

function controlFrameLimits(limits: P2PNodeLimits, maximumBytes = limits.maxControlFrameBytes): FrameLimits {
  return Object.freeze({
    maxControlFrameBytes: Math.min(limits.maxControlFrameBytes, maximumBytes),
    maxControlFrameItems: limits.maxControlFrameItems,
    maxControlFrameDepth: limits.maxControlFrameDepth
  });
}

export function createP2PNode<TRouter extends AnyTRPCRouter, TFileMetadata = unknown>(
  options: P2PNodeOptions<TRouter, TFileMetadata>
): Promise<P2PNode<TRouter, TFileMetadata>> {
  if (!isPeerBoundSessionSecurity(options?.security)) {
    return Promise.reject(new P2PError(
      'UNAUTHORIZED',
      'Production nodes require a peer-bound security factory from @p2prpc/core'
    ));
  }
  if (Object.hasOwn(options, 'endpointFactory')) {
    return Promise.reject(new P2PError('UNAUTHORIZED', 'Custom endpoints are available only from @p2prpc/core/advanced'));
  }
  return P2PNode.create(options);
}

/** Custom authenticators/transports are an explicit advanced trust boundary. */
export function createAdvancedP2PNode<TRouter extends AnyTRPCRouter, TFileMetadata = unknown>(
  options: AdvancedP2PNodeOptions<TRouter, TFileMetadata>
): Promise<P2PNode<TRouter, TFileMetadata>> {
  return P2PNode.create(options);
}

/** Insecure sessions and endpoint injection are deliberately isolated to the testing subpath. */
export function createTestingP2PNode<TRouter extends AnyTRPCRouter, TFileMetadata = unknown>(
  options: TestingP2PNodeOptions<TRouter, TFileMetadata>
): Promise<P2PNode<TRouter, TFileMetadata>> {
  return P2PNode.create({
    ...options,
    security: options.security ?? dangerouslyAllowInsecureSessions<TFileMetadata>()
  });
}

function protocolIdentifier(protocol: ProtocolIdentity): Uint8Array {
  const application = protocol.applicationId.trim();
  const version = protocol.contractVersion.trim();
  if (!/^[A-Za-z0-9._~-]{1,128}$/.test(application) || !/^[A-Za-z0-9._~-]{1,128}$/.test(version)) {
    throw new P2PError(
      'INCOMPATIBLE_PROTOCOL',
      'Application ID and contract version must use 1-128 ASCII letters, digits, dot, underscore, tilde, or hyphen'
    );
  }
  const encoded = new TextEncoder().encode(`p2prpc/${PROTOCOL_VERSION}/${application}/${version}`);
  if (encoded.byteLength > 255) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Protocol identifier exceeds 255 bytes');
  return encoded;
}
