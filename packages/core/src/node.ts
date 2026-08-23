import { createTRPCProxyClient, type CreateTRPCClient } from '@trpc/client';
import type { AnyTRPCRouter, inferRouterContext } from '@trpc/server';
import { P2PError, asP2PError } from './errors.js';
import {
  TransferManager,
  type FileTransferConnectionContext,
  type FileTransferDiagnostics
} from './files/manager.js';
import { ShareRegistry } from './files/share.js';
import type { Transfer } from './files/transfer.js';
import type {
  DownloadFileOptions,
  FileDestination,
  FileSource,
  IncomingFileHandler,
  SendFileOptions,
  PeerSharePolicy,
  SharePolicy,
  SharedFileHandle,
  TransferProgress
} from './files/types.js';
import { StreamKind, readStreamKind, type FrameLimits } from './protocol.js';
import { irohLink } from './rpc/link.js';
import type { RpcHeaderInput } from './rpc/headers.js';
import { RpcServer, type RpcServerRequest } from './rpc/server.js';
import { authenticateConnection } from './security/handshake.js';
import {
  authorizationAllowed,
  type AuthenticatedSession,
  type AuthorizationAction,
  type AuthorizationContext,
  type CredentialRequestContext,
  type SessionAuthenticationContext,
  type SessionCredential,
  type SessionPrincipal,
  type SessionSecurity
} from './security/types.js';
import { IrohEndpoint, type IrohEndpointOptions } from './transport/iroh.js';
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

export interface PeerContext {
  readonly peer: PeerIdentity;
  /** Trusted identity established by the mandatory application handshake. */
  readonly auth: AuthenticatedSession;
  /** Untrusted, normalized metadata for this individual RPC. */
  readonly request: RpcServerRequest;
  readonly connection: {
    stats(): Promise<ConnectionStats>;
  };
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
export type ConnectOptions = ConnectExpectations & (
  | {
      readonly locator: PeerLocator;
      readonly ticket?: never;
    }
  | {
      /** @deprecated Use `locator: { kind: 'ticket', ticket }`. */
      readonly ticket: string;
      readonly locator?: never;
    }
);

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
  readonly maxBiStreams: bigint;
  readonly maxUniStreams: bigint;
  readonly receiveWindow: bigint;
  readonly maxControlFrameBytes: number;
  readonly maxControlFrameItems: number;
  readonly maxControlFrameDepth: number;
  readonly fileChunkSize: number;
  /** Maximum peer-selected chunk size accepted for inbound files. */
  readonly maxFileChunkSize: number;
  readonly fileLanes: number;
  readonly maxFileLanes: number;
  readonly maxFileTransfers: number;
  /** Maximum concurrent inbound file control/setup operations across all peers. */
  readonly maxGlobalFileTransfers: number;
  readonly maxFileSize: number;
  readonly maxFileChunks: number;
  readonly maxFileNameBytes: number;
  readonly maxRpcHeaders: number;
  readonly maxRpcHeaderBytes: number;
  readonly maxRpcPathBytes: number;
  readonly maxInboundStreams: number;
  readonly maxGlobalInboundStreams: number;
  readonly maxPeers: number;
  readonly maxPendingHandshakes: number;
  readonly connectTimeoutMs: number;
  readonly handshakeTimeoutMs: number;
  readonly streamHeaderTimeoutMs: number;
  readonly streamIdleTimeoutMs: number;
  readonly maxSessionTtlMs: number;
  readonly clockSkewMs: number;
}

export interface P2PNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly router: TRouter;
  readonly protocol: ProtocolIdentity;
  readonly createContext: (context: PeerContext) => Promise<inferRouterContext<TRouter>> | inferRouterContext<TRouter>;
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

export interface PeerFiles<TFileMetadata = unknown> {
  sendFile(source: FileSource<TFileMetadata>, options?: SendFileOptions): Promise<Transfer<TFileMetadata>>;
  download(
    handle: SharedFileHandle,
    destination: FileDestination<TFileMetadata>,
    options?: DownloadFileOptions
  ): Promise<Transfer<TFileMetadata>>;
}

export interface PeerDiagnostics {
  readonly sessionId: string;
  readonly connection: ConnectionStats;
  readonly files: FileTransferDiagnostics;
}

const DEFAULT_PEER_CLOSE_REASON = 'Peer closed';
const MAX_PEER_CLOSE_REASON_BYTES = 256;

export class Peer<TRemoteRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly rpc: CreateTRPCClient<TRemoteRouter>;
  readonly files: PeerFiles<TFileMetadata>;

  constructor(
    readonly identity: PeerIdentity,
    private readonly runtime: PeerRuntime<TFileMetadata>
  ) {
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
      download: (handle, destination, options) => runtime.transfers.download(handle.token, destination, options)
    };
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
      files: this.runtime.transfers.diagnostics()
    });
  }

  /** Permanently closes this peer; the display-safe reason is capped at 256 UTF-8 bytes. */
  close(reason = DEFAULT_PEER_CLOSE_REASON): void {
    this.runtime.close(reason);
  }
}

interface PeerRuntime<TFileMetadata> {
  current: QuicConnection;
  currentFiles: FileTransferConnectionContext;
  connectionController: AbortController;
  alive: boolean;
  /** Permanently disables this runtime after Peer.close(); physical disconnects may still reconnect. */
  closed: boolean;
  outboundTarget?: NormalizedConnectOptions;
  identity: PeerIdentity;
  session: AuthenticatedSession;
  readonly transfers: TransferManager<TFileMetadata>;
  readonly headerLimits: { readonly maxCount: number; readonly maxBytes: number };
  readonly frameLimits: FrameLimits;
  readonly getRequestHeaders?: (request: {
    readonly path: string;
    readonly type: 'query' | 'mutation' | 'subscription';
    readonly signal: AbortSignal;
  }) => Promise<RpcHeaderInput | undefined> | RpcHeaderInput | undefined;
  reconnecting: Promise<QuicConnection> | undefined;
  expiryTimer?: ReturnType<typeof setTimeout>;
  connection(): Promise<QuicConnection>;
  fileConnection(): Promise<FileTransferConnectionContext>;
  close(reason: string): void;
}

interface AuthorizationSession {
  readonly id: string;
  readonly principal: SessionPrincipal;
}

const DEFAULT_LIMITS: P2PNodeLimits = {
  maxBiStreams: 256n,
  maxUniStreams: 64n,
  receiveWindow: 64n * 1024n * 1024n,
  maxControlFrameBytes: 1024 * 1024,
  maxControlFrameItems: 128 * 1024,
  maxControlFrameDepth: 64,
  fileChunkSize: 1024 * 1024,
  maxFileChunkSize: 4 * 1024 * 1024,
  fileLanes: 4,
  maxFileLanes: 16,
  maxFileTransfers: 4,
  maxGlobalFileTransfers: 64,
  maxFileSize: 16 * 1024 * 1024 * 1024,
  maxFileChunks: 65_536,
  maxFileNameBytes: 255,
  maxRpcHeaders: 64,
  maxRpcHeaderBytes: 16 * 1024,
  maxRpcPathBytes: 1024,
  maxInboundStreams: 128,
  maxGlobalInboundStreams: 1024,
  maxPeers: 256,
  maxPendingHandshakes: 32,
  connectTimeoutMs: 30_000,
  handshakeTimeoutMs: 10_000,
  streamHeaderTimeoutMs: 10_000,
  streamIdleTimeoutMs: 30_000,
  maxSessionTtlMs: 15 * 60_000,
  clockSkewMs: 30_000
};

export class P2PNode<TRouter extends AnyTRPCRouter, TFileMetadata = unknown> {
  readonly id: string;
  readonly files: {
    share(source: FileSource<TFileMetadata>, policy: SharePolicy): SharedFileHandle;
    shareForPeer(
      source: FileSource<TFileMetadata>,
      peerId: string,
      policy?: PeerSharePolicy
    ): SharedFileHandle;
    revoke(handle: SharedFileHandle): boolean;
  };

  private readonly peers = new Map<string, PeerRuntime<TFileMetadata>>();
  private readonly shares = new ShareRegistry<TFileMetadata>();
  private readonly limits: P2PNodeLimits;
  private readonly protocolName: string;
  private readonly globalStreamLimiter: TaskLimiter;
  private readonly globalFileTransferLimiter: TaskLimiter;
  private readonly shutdownController = new AbortController();
  private pendingHandshakes = 0;
  private closed = false;

  private constructor(
    private readonly endpoint: QuicEndpoint,
    private readonly alpn: Uint8Array,
    private readonly options: P2PNodeOptions<TRouter, TFileMetadata>,
    limits: P2PNodeLimits
  ) {
    this.id = endpoint.id;
    this.limits = limits;
    this.protocolName = new TextDecoder().decode(alpn);
    this.globalStreamLimiter = new TaskLimiter(this.limits.maxGlobalInboundStreams);
    this.globalFileTransferLimiter = new TaskLimiter(this.limits.maxGlobalFileTransfers);
    this.files = {
      share: (source, policy) => this.shares.share(source, policy),
      shareForPeer: (source, peerId, policy) => this.shares.shareForPeer(source, peerId, policy),
      revoke: (handle) => this.shares.revoke(handle)
    };
  }

  static async create<TRouter extends AnyTRPCRouter, TFileMetadata = unknown>(
    options: P2PNodeOptions<TRouter, TFileMetadata>
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
    const node = new P2PNode(endpoint, alpn, configuredOptions, limits);
    node.runAcceptLoop();
    return node;
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
    const connection = await this.dial(target);
    const runtime = await this.registerConnection(connection, 'outbound', target);
    return new Peer<TRemoteRouter, TFileMetadata>(runtime.identity, runtime);
  }

  peersSnapshot(): readonly PeerIdentity[] {
    return [...this.peers.values()].map((runtime) => runtime.identity);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    this.shutdownController.abort(new P2PError('DISCONNECTED', 'Node is closed'));
    for (const runtime of this.peers.values()) {
      if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
      runtime.close('Node closed');
    }
    this.peers.clear();
    await this.endpoint.close();
  }

  private runAcceptLoop(): void {
    void (async () => {
      while (!this.closed) {
        try {
          const connection = await this.endpoint.accept();
          if (!connection) return;
          if (this.closed) {
            connection.close(4n, new TextEncoder().encode('Node closed'));
            return;
          }
          if (this.pendingHandshakes >= this.limits.maxPendingHandshakes) {
            connection.close(5n, new TextEncoder().encode('Too many pending handshakes'));
            continue;
          }
          this.pendingHandshakes += 1;
          void this.registerConnection(connection, 'inbound')
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
            });
        } catch (cause) {
          if (!this.closed) this.reportError(asP2PError(cause, 'DISCONNECTED'));
        }
      }
    })();
  }

  private async registerConnection(
    connection: QuicConnection,
    direction: PeerIdentity['direction'],
    outboundTarget?: NormalizedConnectOptions
  ): Promise<PeerRuntime<TFileMetadata>> {
    const identity = peerIdentity(connection.remoteId, direction);
    let installed = false;
    try {
      if (outboundTarget && identity.id !== outboundTarget.expectedPeerId) {
        throw new P2PError('UNAUTHORIZED', 'Connected endpoint does not match the expected peer ID');
      }
      this.assertPeerCapacity(identity.id);
      await this.admitPeer(identity);
      this.configureConnection(connection);
      const session = await this.authenticate(connection, direction);
      if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during authentication');
      if (outboundTarget) assertExpectedPrincipal(session.principal, outboundTarget.expectedPrincipal);

      const existing = this.peers.get(identity.id);
      if (existing) {
        assertSamePrincipal(existing.session.principal, session.principal);
        if (outboundTarget) existing.outboundTarget = outboundTarget;
        if (!existing.alive || (isPreferredConnection(this.id, connection) && !isPreferredConnection(this.id, existing.current))) {
          existing.connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection was superseded'));
          existing.current.close(0n, new TextEncoder().encode('Superseded connection'));
          this.installConnection(existing, connection, identity, session);
          installed = true;
          this.reportAuthenticated(identity, session);
        } else {
          connection.close(0n, new TextEncoder().encode('Duplicate connection'));
        }
        return existing;
      }

      this.assertPeerCapacity(identity.id);
      const connectionController = new AbortController();
      const currentFiles = fileConnectionContext(connection, session, connectionController.signal);
      const runtime: PeerRuntime<TFileMetadata> = {
        current: connection,
        currentFiles,
        connectionController,
        alive: true,
        closed: false,
        ...(outboundTarget ? { outboundTarget } : {}),
        identity,
        session,
        reconnecting: undefined,
        headerLimits: { maxCount: this.limits.maxRpcHeaders, maxBytes: this.limits.maxRpcHeaderBytes },
        frameLimits: controlFrameLimits(this.limits),
        ...(this.options.getRequestHeaders ? {
          getRequestHeaders: (request) => this.options.getRequestHeaders?.(Object.freeze({
            peer: runtime.identity,
            ...request
          }))
        } : {}),
        transfers: new TransferManager<TFileMetadata>({
          peerId: identity.id,
          connection: () => runtime.fileConnection(),
          shares: this.shares,
          authorize: (action, captured, signal) => this.authorize(runtime, {
            id: captured.sessionId,
            principal: captured.principal
          }, action, signal),
          ...(this.options.onIncomingFile ? { incoming: this.options.onIncomingFile } : {}),
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
          frameLimits: controlFrameLimits(this.limits),
          onProgress: (progress) => this.options.onTransferProgress?.(progress, identity)
        }),
        connection: async () => this.runtimeConnection(runtime),
        fileConnection: async () => this.runtimeFileConnection(runtime),
        close: (reason) => {
          if (runtime.closed) return;
          const safeReason = safePeerCloseReason(reason);
          runtime.closed = true;
          runtime.alive = false;
          delete runtime.outboundTarget;
          if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
          if (this.peers.get(runtime.identity.id) === runtime) this.peers.delete(runtime.identity.id);
          const error = new P2PError('DISCONNECTED', safeReason);
          runtime.transfers.close(error);
          runtime.connectionController.abort(error);
          runtime.current.close(0n, new TextEncoder().encode(safeReason));
        }
      };
      this.peers.set(identity.id, runtime);
      this.startConnectionLoops(runtime);
      this.scheduleExpiry(runtime);
      installed = true;
      this.reportAuthenticated(identity, session);
      try {
        const delivered = this.options.onPeer?.(new Peer<AnyTRPCRouter, TFileMetadata>(identity, runtime));
        void Promise.resolve(delivered).catch((cause) => this.reportError(asP2PError(cause), identity));
      } catch (cause) {
        this.reportError(asP2PError(cause), identity);
      }
      return runtime;
    } catch (cause) {
      if (!installed) connection.close(4n, new TextEncoder().encode('Application authentication failed'));
      const error = asP2PError(cause, 'UNAUTHORIZED');
      this.reportSecurity({
        type: 'session.rejected',
        timestamp: Date.now(),
        peerId: identity.id,
        direction,
        code: error.code
      });
      throw error;
    }
  }

  private authenticate(connection: QuicConnection, direction: PeerIdentity['direction']): Promise<AuthenticatedSession> {
    return authenticateConnection(connection, direction, {
      localPeerId: this.id,
      protocol: this.protocolName,
      security: this.options.security,
      timeoutMs: this.limits.handshakeTimeoutMs,
      maxSessionTtlMs: this.limits.maxSessionTtlMs,
      clockSkewMs: this.limits.clockSkewMs,
      frameLimits: controlFrameLimits(this.limits, 64 * 1024)
    });
  }

  private async dial(target: NormalizedConnectOptions): Promise<QuicConnection> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    const controller = new AbortController();
    const abortFromShutdown = (): void => {
      controller.abort(this.shutdownController.signal.reason ?? new P2PError('DISCONNECTED', 'Node is closed'));
    };
    if (this.shutdownController.signal.aborted) abortFromShutdown();
    else this.shutdownController.signal.addEventListener('abort', abortFromShutdown, { once: true });

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
      void pending.then(
        (connection) => connection.close(4n, new TextEncoder().encode('Late or cancelled connection')),
        () => undefined
      );
      throw asP2PError(cause, 'DISCONNECTED');
    } finally {
      this.shutdownController.signal.removeEventListener('abort', abortFromShutdown);
    }
  }

  private assertPeerCapacity(peerId: string): void {
    if (!this.peers.has(peerId) && this.peers.size >= this.limits.maxPeers) {
      throw new P2PError('RESOURCE_LIMIT', 'Authenticated peer limit reached');
    }
  }

  private async runtimeConnection(runtime: PeerRuntime<TFileMetadata>): Promise<QuicConnection> {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer is closed');
    if (runtime.alive && this.peers.get(runtime.identity.id) === runtime) {
      if (runtime.session.expiresAt > Date.now()) return runtime.current;
      runtime.connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated session expired'));
      runtime.current.close(4n, new TextEncoder().encode('Session expired'));
      runtime.alive = false;
      this.peers.delete(runtime.identity.id);
    }
    if (!runtime.outboundTarget) throw new P2PError('DISCONNECTED', `Peer ${runtime.identity.id} is disconnected`);
    if (runtime.reconnecting) return runtime.reconnecting;
    this.assertPeerCapacity(runtime.identity.id);
    const reconnecting = (async () => {
      if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
      if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer is closed');
      const target = runtime.outboundTarget!;
      const connection = await this.dial(target);
      try {
        if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during reconnection');
        if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer closed during reconnection');
        if (connection.remoteId !== target.expectedPeerId || connection.remoteId !== runtime.identity.id) {
          throw new P2PError('UNAUTHORIZED', 'Reconnection endpoint identity does not match the expected peer');
        }
        this.configureConnection(connection);
        const identity = peerIdentity(connection.remoteId, 'outbound');
        await this.admitPeer(identity);
        const session = await this.authenticate(connection, 'outbound');
        if (this.closed) throw new P2PError('DISCONNECTED', 'Node closed during reauthentication');
        if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer closed during reauthentication');
        assertExpectedPrincipal(session.principal, target.expectedPrincipal);
        assertSamePrincipal(runtime.session.principal, session.principal);
        const incumbent = this.peers.get(identity.id);
        if (incumbent && incumbent !== runtime) {
          throw new P2PError('DISCONNECTED', 'Peer already has a newer authenticated connection');
        }
        this.assertPeerCapacity(identity.id);
        this.installConnection(runtime, connection, identity, session);
        this.peers.set(identity.id, runtime);
        this.reportAuthenticated(identity, session);
        return connection;
      } catch (cause) {
        connection.close(4n, new TextEncoder().encode('Reauthentication failed'));
        throw cause;
      }
    })();
    runtime.reconnecting = reconnecting;
    try {
      return await reconnecting;
    } finally {
      runtime.reconnecting = undefined;
    }
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
  ): void {
    if (this.closed) throw new P2PError('DISCONNECTED', 'Node is closed');
    if (runtime.closed) throw new P2PError('DISCONNECTED', 'Peer is closed');
    if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
    runtime.connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection was replaced'));
    const connectionController = new AbortController();
    runtime.current = connection;
    runtime.connectionController = connectionController;
    runtime.currentFiles = fileConnectionContext(connection, session, connectionController.signal);
    runtime.identity = identity;
    runtime.session = session;
    runtime.alive = true;
    this.configureConnection(connection);
    this.startConnectionLoops(runtime);
    this.scheduleExpiry(runtime);
  }

  private async admitPeer(identity: PeerIdentity): Promise<void> {
    if (!this.options.preAuthorizePeer) return;
    const controller = new AbortController();
    const allowed = await withDeadline(
      Promise.resolve(this.options.preAuthorizePeer(identity, controller.signal)),
      this.limits.handshakeTimeoutMs,
      'Peer admission timed out',
      controller
    );
    controller.signal.throwIfAborted();
    if (allowed !== true) throw new P2PError('UNAUTHORIZED', `Peer ${identity.id} was rejected`);
  }

  private startConnectionLoops(runtime: PeerRuntime<TFileMetadata>): void {
    const connection = runtime.current;
    const session = runtime.session;
    const fileContext = runtime.currentFiles;
    const connectionController = runtime.connectionController;
    const limiter = new TaskLimiter(this.limits.maxInboundStreams);
    const rpc = new RpcServer({
      router: this.options.router,
      createContext: (request) => this.options.createContext(Object.freeze({
        peer: runtime.identity,
        auth: session,
        request,
        connection: Object.freeze({ stats: () => connection.stats() })
      })),
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

    void (async () => {
      while (runtime.current === connection && !this.closed) {
        try {
          const stream = await connection.acceptBi();
          const release = acquireBoth(limiter, this.globalStreamLimiter);
          if (!release) {
            void stream.send.reset(5n).catch(() => undefined);
            void stream.recv.stop(5n).catch(() => undefined);
            continue;
          }
          void withDeadline(readStreamKind(stream.recv), this.limits.streamHeaderTimeoutMs, 'Stream header timed out')
            .then((kind) => {
              this.assertCurrentSession(runtime, connection, session);
              if (kind === StreamKind.Rpc) return rpc.handle(stream);
              if (kind === StreamKind.TransferControl) {
                const releaseFileTransfer = this.globalFileTransferLimiter.tryAcquire();
                if (!releaseFileTransfer) {
                  throw new P2PError('RESOURCE_LIMIT', 'Global inbound file transfer limit reached');
                }
                return runtime.transfers.handleControl(stream, fileContext).finally(releaseFileTransfer);
              }
              throw new P2PError('INVALID_FRAME', `Invalid bidirectional stream kind ${kind}`);
            })
            .catch((cause) => {
              void stream.send.reset(1n).catch(() => undefined);
              void stream.recv.stop(1n).catch(() => undefined);
              this.reportError(asP2PError(cause), runtime.identity);
            })
            .finally(release);
        } catch {
          break;
        }
      }
    })();

    void (async () => {
      while (runtime.current === connection && !this.closed) {
        try {
          const recv = await connection.acceptUni();
          const release = acquireBoth(limiter, this.globalStreamLimiter);
          if (!release) {
            void recv.stop(5n).catch(() => undefined);
            continue;
          }
          void withDeadline(readStreamKind(recv), this.limits.streamHeaderTimeoutMs, 'Stream header timed out')
            .then((kind) => {
              this.assertCurrentSession(runtime, connection, session);
              if (kind !== StreamKind.TransferData) throw new P2PError('INVALID_FRAME', `Invalid unidirectional stream kind ${kind}`);
              return runtime.transfers.handleData(recv, fileContext);
            })
            .catch((cause) => {
              void recv.stop(1n).catch(() => undefined);
              this.reportError(asP2PError(cause), runtime.identity);
            })
            .finally(release);
        } catch {
          break;
        }
      }
    })();

    void connection.closed().then(
      () => {
        connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection closed'));
        if (runtime.current === connection) {
          runtime.alive = false;
          if (this.peers.get(runtime.identity.id) === runtime) this.peers.delete(runtime.identity.id);
          if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
          if (!runtime.outboundTarget) {
            runtime.transfers.close(new P2PError('DISCONNECTED', 'Inbound peer connection closed'));
          }
        }
      },
      (cause) => {
        connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated connection failed', { cause }));
        if (runtime.current === connection) {
          runtime.alive = false;
          if (this.peers.get(runtime.identity.id) === runtime) this.peers.delete(runtime.identity.id);
          if (runtime.expiryTimer) clearTimeout(runtime.expiryTimer);
          if (!runtime.outboundTarget) {
            runtime.transfers.close(new P2PError('DISCONNECTED', 'Inbound peer connection failed', { cause }));
          }
        }
      }
    );
  }

  private assertCurrentSession(
    runtime: PeerRuntime<TFileMetadata>,
    connection: QuicConnection,
    session: AuthenticatedSession
  ): void {
    if (
      this.closed ||
      !runtime.alive ||
      this.peers.get(runtime.identity.id) !== runtime ||
      runtime.current !== connection ||
      runtime.session !== session ||
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
        Promise.resolve(this.options.security.authorize(Object.freeze({
          principal: session.principal,
          localPeerId: this.id,
          remotePeerId: runtime.identity.id,
          sessionId: session.id,
          action: checkedAction,
          signal: controller.signal
        }))),
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
    this.reportSecurity({
      type: 'authorization',
      timestamp: Date.now(),
      peerId: runtime.identity.id,
      sessionId: session.id,
      principalId: session.principal.id,
      action: summarizeSecurityAction(checkedAction),
      allowed: decision.allowed,
      ...(decision.reason !== undefined ? { reason: safeAuditReason(decision.reason) } : {})
    });
    if (!decision.allowed) throw new P2PError('UNAUTHORIZED', decision.reason ?? 'Operation is not authorized');
  }

  private assertAuthorizationSession(
    runtime: PeerRuntime<TFileMetadata>,
    session: AuthorizationSession
  ): void {
    if (
      this.closed ||
      !runtime.alive ||
      this.peers.get(runtime.identity.id) !== runtime ||
      runtime.session.id !== session.id ||
      runtime.session.principal !== session.principal ||
      runtime.session.expiresAt <= Date.now()
    ) {
      throw new P2PError('UNAUTHORIZED', 'Authenticated session is no longer active');
    }
  }

  private scheduleExpiry(runtime: PeerRuntime<TFileMetadata>): void {
    const session = runtime.session;
    const connection = runtime.current;
    const connectionController = runtime.connectionController;
    const schedule = (): void => {
      const remaining = session.expiresAt - Date.now();
      if (remaining <= 0) {
        if (runtime.session === session && runtime.current === connection) {
          this.reportSecurity({
            type: 'session.expired',
            timestamp: Date.now(),
            peerId: runtime.identity.id,
            sessionId: session.id,
            principalId: session.principal.id
          });
          connectionController.abort(new P2PError('DISCONNECTED', 'Authenticated session expired'));
          connection.close(4n, new TextEncoder().encode('Session expired'));
        }
        return;
      }
      runtime.expiryTimer = setTimeout(schedule, Math.min(remaining, 0x7fff_ffff));
      runtime.expiryTimer.unref?.();
    };
    schedule();
  }

  private configureConnection(connection: QuicConnection): void {
    connection.configure({
      maxBiStreams: this.limits.maxBiStreams,
      maxUniStreams: this.limits.maxUniStreams,
      receiveWindow: this.limits.receiveWindow
    });
  }

  private reportError(error: P2PError, peer?: PeerIdentity): void {
    try {
      const delivered = this.options.onError?.(error, peer);
      void Promise.resolve(delivered).catch(() => undefined);
    } catch {
      // Observability callbacks cannot affect protocol state.
    }
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
    try {
      const delivered = this.options.onSecurityEvent?.(Object.freeze(event));
      // TypeScript's void callback convention intentionally accepts async
      // callbacks. Observe the runtime return value so a rejected sink promise
      // cannot become an unhandled rejection or affect protocol state.
      void Promise.resolve(delivered).catch(() => undefined);
    } catch {
      // Audit sinks cannot affect protocol state. Deployments should monitor sink health separately.
    }
  }
}

function fileConnectionContext(
  connection: QuicConnection,
  session: AuthenticatedSession,
  signal: AbortSignal
): FileTransferConnectionContext {
  return Object.freeze({
    connection,
    security: Object.freeze({ principal: session.principal, sessionId: session.id }),
    signal
  });
}

function isPreferredConnection(localId: string, connection: QuicConnection): boolean {
  return localId < connection.remoteId ? connection.side === 'client' : connection.side === 'server';
}

function peerIdentity(id: string, direction: PeerIdentity['direction']): PeerIdentity {
  return Object.freeze({ id, direction });
}

class TaskLimiter {
  private active = 0;

  constructor(private readonly maximum: number) {}

  tryAcquire(): (() => void) | undefined {
    if (this.active >= this.maximum) return undefined;
    this.active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.active -= 1;
    };
  }
}

function acquireBoth(first: TaskLimiter, second: TaskLimiter): (() => void) | undefined {
  const releaseFirst = first.tryAcquire();
  if (!releaseFirst) return undefined;
  const releaseSecond = second.tryAcquire();
  if (!releaseSecond) {
    releaseFirst();
    return undefined;
  }
  return () => {
    releaseFirst();
    releaseSecond();
  };
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
  assertOnlyKeys(value, ['locator', 'ticket', 'expectedPeerId', 'expectedPrincipal'], 'Outbound connect options');
  if (value.ticket !== undefined && value.locator !== undefined) {
    throw new P2PError('INVALID_FRAME', 'Configure either outbound locator or legacy ticket, not both');
  }
  const locator = value.locator === undefined
    ? Object.freeze({ kind: 'ticket', ticket: boundedExpectedString(value.ticket, 64 * 1024, 'Outbound ticket') })
    : normalizeLocator(value.locator);
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

function validateLimits(limits: P2PNodeLimits): P2PNodeLimits {
  const integer = (name: keyof P2PNodeLimits, minimum: number, maximum: number): void => {
    const value = limits[name];
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new P2PError('RESOURCE_LIMIT', `${name} must be between ${minimum} and ${maximum}`);
    }
  };
  for (const name of ['maxBiStreams', 'maxUniStreams', 'receiveWindow'] as const) {
    const value = limits[name];
    if (typeof value !== 'bigint' || value <= 0n || value > 1n << 40n) {
      throw new P2PError('RESOURCE_LIMIT', `${name} is outside the supported range`);
    }
  }
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
  integer('maxRpcHeaders', 0, 256);
  integer('maxRpcHeaderBytes', 0, 64 * 1024);
  integer('maxRpcPathBytes', 1, 16 * 1024);
  integer('maxInboundStreams', 1, 65_536);
  integer('maxGlobalInboundStreams', 1, 1_000_000);
  integer('maxPeers', 1, 1_000_000);
  integer('maxPendingHandshakes', 1, 4_096);
  integer('connectTimeoutMs', 100, 120_000);
  integer('handshakeTimeoutMs', 100, 120_000);
  integer('streamHeaderTimeoutMs', 100, 120_000);
  integer('streamIdleTimeoutMs', 1_000, 10 * 60_000);
  integer('maxSessionTtlMs', 1_000, 24 * 60 * 60_000);
  integer('clockSkewMs', 0, 10 * 60_000);
  if (limits.fileChunkSize > limits.maxFileChunkSize) {
    throw new P2PError('RESOURCE_LIMIT', 'fileChunkSize cannot exceed maxFileChunkSize');
  }
  if (limits.fileLanes > limits.maxFileLanes) throw new P2PError('RESOURCE_LIMIT', 'fileLanes cannot exceed maxFileLanes');
  if (limits.maxGlobalFileTransfers > limits.maxGlobalInboundStreams) {
    throw new P2PError('RESOURCE_LIMIT', 'maxGlobalFileTransfers cannot exceed maxGlobalInboundStreams');
  }
  return Object.freeze(limits);
}

function validateNodeConfiguration<TRouter extends AnyTRPCRouter, TFileMetadata>(
  options: P2PNodeOptions<TRouter, TFileMetadata>
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
  if (configured.iroh !== undefined && !isPlainRecord(configured.iroh)) {
    throw new P2PError('INVALID_FRAME', 'P2P node iroh options must be a plain object');
  }
}

function snapshotNodeOptions<TRouter extends AnyTRPCRouter, TFileMetadata>(
  options: P2PNodeOptions<TRouter, TFileMetadata>
): P2PNodeOptions<TRouter, TFileMetadata> {
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
  return Object.freeze({
    ...options,
    security,
    ...(iroh !== undefined ? { iroh } : {})
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
  return P2PNode.create(options);
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
  const encoded = new TextEncoder().encode(`p2prpc/2/${application}/${version}`);
  if (encoded.byteLength > 255) throw new P2PError('INCOMPATIBLE_PROTOCOL', 'Protocol identifier exceeds 255 bytes');
  return encoded;
}
