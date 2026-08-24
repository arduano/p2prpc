import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  access,
  mkdir,
  mkdtemp,
  readdir,
  rename,
  rm,
  statfs,
  writeFile
} from 'node:fs/promises';
import { availableParallelism, tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { blake3 } from '@napi-rs/blake-hash';
import { initTRPC } from '@trpc/server';
import {
  createP2PNode,
  createSharedSecretSecurity,
  fileDestination,
  fileSource,
  type ConnectOptions,
  type ConnectionStats,
  type EndpointDiagnostics,
  type FileTransferDiagnostics,
  type FileMetadataSchema,
  type IrohEndpointOptions,
  type P2PNode,
  type Peer,
  type PeerContext,
  type PeerDiagnostics,
  type PeerLocator,
  type SecurityAuditEvent,
  type SharedFileHandle,
  type StreamLifecycleStats
} from '../packages/core/src/index.js';

const DEFAULT_FILE_COUNT = 10_000;
const DEFAULT_BATCH_SIZE = 100;
const DEFAULT_CONCURRENCY = 16;
const CHUNK_SIZE = 64 * 1024;
const LANES = 4;
// The single-connection cancellation case deliberately waits until its sole
// data lane has emitted progress. Cancelling while native stream opening is
// still pending is a different fail-closed test: ManagedConnection must
// quarantine that physical connection because JavaScript cannot revoke the
// hidden native open. Unit tests cover that race directly.
const CANCELLATION_LANES = 1;
const LARGE_FILE_BYTES = 256 * 1024;
const SESSION_TTL_MS = 4 * 60 * 60_000;
const MIB = 1024 * 1024;
const CONTROL_FRAME_BYTES = MIB;
const FILE_DATA_SEGMENT_BYTES = 64 * 1024;

const t = initTRPC.context<PeerContext>().create();
const router = t.router({
  ping: t.procedure.query(({ ctx }) => ({ peerId: ctx.p2p.peer.id, sessionId: ctx.p2p.auth.id }))
});
type Router = typeof router;

type FileKind = 'push' | 'pull' | 'rejected' | 'cancelled' | 'destination-failure';

interface StressFileMetadata {
  readonly kind: FileKind;
  readonly index: number;
  readonly sha256: string;
}

const stressFileMetadataSchema: FileMetadataSchema<StressFileMetadata> = {
  '~standard': {
    version: 1,
    vendor: 'p2prpc-stress',
    validate(value) {
      try {
        return { value: validateMetadata(value) };
      } catch {
        return { issues: [{ message: 'Invalid stress metadata' }] };
      }
    }
  }
};

interface FileRecord {
  readonly index: number;
  readonly kind: 'push' | 'pull';
  readonly name: string;
  readonly sourcePath: string;
  readonly destinationPath: string;
  readonly size: number;
  readonly sha256: string;
  readonly blake3: string;
}

type LocatorKind = 'ticket' | 'dns' | 'mdns';
type RelayMode = 'disabled' | 'default' | 'custom';

interface Options {
  readonly execute: boolean;
  readonly output: string;
  readonly overwrite: boolean;
  readonly fileCount: number;
  readonly batchSize: number;
  readonly concurrency: number;
  readonly errorCases: number;
  readonly locator: LocatorKind;
  readonly relay: RelayMode;
  readonly relayUrls: readonly string[];
  readonly bindAddresses: readonly string[];
  readonly dnsServerUrl?: string;
  readonly mdnsServiceName: string;
  readonly checkpointTimeoutMs: number;
  readonly maxRssGrowthBytes: number;
  readonly maxHeapGrowthBytes: number;
  readonly keepWorkdir: boolean;
}

interface AuditCounts {
  authenticated: number;
  rejected: number;
  allowedPush: number;
  allowedPull: number;
  allowedRpc: number;
  denied: number;
  sessionIds: Set<string>;
}

interface ProcessSnapshot {
  readonly timestamp: string;
  readonly rssBytes: number;
  readonly heapUsedBytes: number;
  readonly externalBytes: number;
  readonly arrayBuffersBytes: number;
  readonly fileDescriptors: number | null;
  readonly activeResources: Readonly<Record<string, number>>;
}

interface SanitizedConnectionStats {
  readonly connectionFingerprint: string | null;
  readonly rttMs: number | null;
  readonly sentBytes: number;
  readonly receivedBytes: number;
  readonly lostPackets: number;
  readonly sentPackets: number | null;
  readonly congestionWindow: number | null;
  readonly relay: boolean | null;
  readonly relayUrlFingerprint: string | null;
  readonly paths: ReadonlyArray<{
    readonly relay: boolean;
    readonly active: boolean;
    readonly addressFingerprint: string;
  }>;
  readonly streams: StreamLifecycleStats | null;
}

interface ResourceSnapshot {
  readonly process: ProcessSnapshot;
  readonly senderConnection: SanitizedConnectionStats;
  readonly receiverConnection: SanitizedConnectionStats;
  readonly senderFiles: FileTransferDiagnostics | null;
  readonly receiverFiles: FileTransferDiagnostics | null;
  readonly senderScheduler: PeerDiagnostics['resources'] | null;
  readonly receiverScheduler: PeerDiagnostics['resources'] | null;
  readonly senderShares: PeerDiagnostics['shares'] | null;
  readonly receiverShares: PeerDiagnostics['shares'] | null;
  readonly senderTasks: PeerDiagnostics['tasks'] | null;
  readonly receiverTasks: PeerDiagnostics['tasks'] | null;
  readonly senderEndpoint: EndpointDiagnostics | null;
  readonly receiverEndpoint: EndpointDiagnostics | null;
}

interface CheckpointEvidence {
  readonly sequence: number;
  readonly phase: string;
  readonly completedFiles: number;
  readonly batchFiles: number;
  readonly batchDurationMs: number;
  readonly capturedAt: string;
  readonly resources: ResourceSnapshot;
}

interface PhaseEvidence {
  readonly name: string;
  readonly direction: 'push' | 'pull';
  readonly scheduling: string;
  readonly files: number;
  readonly durationMs: number;
  readonly fileLatencyMs: {
    readonly p50: number;
    readonly p95: number;
    readonly p99: number;
    readonly maximum: number;
  };
  readonly batchMillisecondsPerFile: readonly number[];
  readonly slowdownRatio: number | null;
}

interface ControlAttemptEvidence {
  readonly logicalCases: number;
  readonly senderOpenedBi: number | null;
  readonly receiverAcceptedBi: number | null;
  readonly exact: boolean;
}

interface Evidence {
  schemaVersion: 3;
  runId: string;
  status: 'running' | 'passed' | 'failed';
  startedAt: string;
  finishedAt?: string;
  qualification: {
    requestedProductionProfile: boolean;
    diagnosticsAvailable: boolean;
    connectionDiagnosticsAvailable: boolean;
    fileDiagnosticsAvailable: boolean;
    runtimeDiagnosticsAvailable: boolean;
    fileDescriptorTelemetryAvailable: boolean;
    productionGateEligible: boolean;
    notes: string[];
  };
  configuration: {
    fileCount: number;
    pushes: number;
    pulls: number;
    sequentialPerDirection: number;
    concurrentPerDirection: number;
    concurrency: number;
    batchSize: number;
    chunkSize: number;
    lanes: number;
    smallFiles: number;
    largeFiles: number;
    largeFileBytes: number;
    errorCasesPerClass: number;
    locator: LocatorKind;
    relay: RelayMode;
    relayUrlFingerprints: string[];
    bindAddressFingerprints: string[];
    dnsServerUrlFingerprint: string | null;
    mdnsServiceNameFingerprint: string | null;
    checkpointTimeoutMs: number;
  };
  relayEvidence: {
    /** Canonical configured origins; values are full SHA-256 digests only. */
    configured: string[];
    /** Relay candidates evaluated by p2prpc while the outbound dial was active. */
    attempted: string[];
    /** Relay origins observed on an established connection. */
    connected: string[];
    /** Relay candidates denied by the application egress callback. */
    denied: string[];
    /** DNS/native fallback attempts are opaque in the pinned wrapper. */
    attemptVisibility: 'explicit-candidates' | 'opaque-native-dns';
  };
  environment: {
    platform: NodeJS.Platform;
    architecture: string;
    node: string;
    pid: number;
    cpuCount: number;
    gcExposed: boolean;
    workspaceFreeBytes: number | null;
    estimatedWorkspaceBytes: number;
  };
  identities?: {
    senderFingerprint: string;
    receiverFingerprint: string;
    sessionFingerprint: string;
  };
  baseline?: ResourceSnapshot;
  phases: PhaseEvidence[];
  checkpoints: CheckpointEvidence[];
  negativeCases?: {
    rejectedPushes: number;
    revokedPulls: number;
    senderCancellations: number;
    senderCancellationLanes: number;
    senderCancellationTrigger: 'first-data-progress';
    destinationFailures: number;
    controlAttempts: {
      rejectedPushes: ControlAttemptEvidence;
      revokedPulls: ControlAttemptEvidence;
      senderCancellations: ControlAttemptEvidence;
      destinationFailures: ControlAttemptEvidence;
    };
    /** Entry N is the number of control attempts observed for logical failure N. */
    destinationFailureAttemptsByIndex: number[];
    rpcCanaries: number;
  };
  totals?: {
    successfulFiles: number;
    uniqueTransferIds: number;
    uniquePushOffers: number;
    pushAuthorizations: number;
    pullAuthorizations: number;
    authenticationEventsPerEndpoint: number;
    elapsedMs: number;
    peakRssBytes: number;
    peakHeapUsedBytes: number;
    peakFileDescriptors: number | null;
  };
  failure?: {
    name: string;
    message: string;
    code?: string;
    stack?: string;
  };
}

interface HarnessContext {
  readonly options: Options;
  readonly evidence: Evidence;
  readonly artifact: ArtifactWriter;
  readonly directory: string;
  readonly sender: P2PNode<Router, StressFileMetadata>;
  readonly receiver: P2PNode<Router, StressFileMetadata>;
  readonly outboundPeer: Peer<Router, StressFileMetadata>;
  readonly inboundPeer: Peer<Router, StressFileMetadata>;
  readonly sessionId: string;
  readonly senderConnectionId: string | null;
  readonly receiverConnectionId: string | null;
  readonly senderAudit: AuditCounts;
  readonly receiverAudit: AuditCounts;
  readonly positiveOffers: Set<string>;
  readonly destinationFailureAttempts: Map<number, number>;
  readonly unexpectedErrors: string[];
  readonly baseline: ResourceSnapshot;
  readonly sampler: ProcessSampler;
  readonly relayEvidence: RelayEvidenceTracker;
  readonly pendingCapabilityCleanup: SharedFileHandle[];
  readonly successfulTransferIds: Set<string>;
  completedFiles: number;
}

interface RelayEvidenceTracker {
  readonly allowRelayUrl?: (origin: string) => boolean;
  beginDial(): void;
  endDial(): void;
  observe(snapshot: ResourceSnapshot): void;
}

class ArtifactWriter {
  private created = false;

  constructor(
    private readonly path: string,
    private readonly overwrite: boolean
  ) {}

  async initialize(): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true });
    if (!this.overwrite) {
      await access(this.path).then(
        () => { throw new Error(`Refusing to overwrite existing artifact: ${this.path}`); },
        () => undefined
      );
    }
  }

  async write(evidence: Evidence): Promise<void> {
    const temporary = `${this.path}.${process.pid}.tmp`;
    await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600 });
    try {
      await rename(temporary, this.path);
    } catch (cause) {
      if (!this.created && !this.overwrite) throw cause;
      await rm(this.path, { force: true });
      await rename(temporary, this.path);
    }
    this.created = true;
  }
}

class ProcessSampler {
  peakRssBytes = 0;
  peakHeapUsedBytes = 0;
  peakFileDescriptors: number | null = null;
  private timer: ReturnType<typeof setInterval> | undefined;
  private sampling = false;

  start(): void {
    this.timer = setInterval(() => {
      if (this.sampling) return;
      this.sampling = true;
      void processSnapshot().then((snapshot) => {
        this.observe(snapshot);
      }).finally(() => {
        this.sampling = false;
      });
    }, 100);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  observe(snapshot: ProcessSnapshot): void {
    this.peakRssBytes = Math.max(this.peakRssBytes, snapshot.rssBytes);
    this.peakHeapUsedBytes = Math.max(this.peakHeapUsedBytes, snapshot.heapUsedBytes);
    if (snapshot.fileDescriptors !== null) {
      this.peakFileDescriptors = Math.max(this.peakFileDescriptors ?? 0, snapshot.fileDescriptors);
    }
  }
}

const parsed = parseArguments(process.argv.slice(2));
if (parsed === 'help') {
  printHelp();
} else {
  let completed = false;
  // The pinned native wrapper owns SIGINT/SIGTERM handlers that may call
  // process.exit(0) after closing endpoints. Never let that turn an interrupted
  // stress run with a still-`running` artifact into a successful command.
  process.on('exit', () => {
    if (!completed) process.exitCode = 1;
  });
  await main(parsed);
  completed = true;
}

async function main(options: Options): Promise<void> {
  if (!options.execute && process.env.P2PRPC_RUN_NATIVE_STRESS !== '1') {
    throw new Error('Native stress execution is guarded. Pass --execute or set P2PRPC_RUN_NATIVE_STRESS=1.');
  }
  const artifact = new ArtifactWriter(options.output, options.overwrite);
  await artifact.initialize();
  const started = Date.now();
  const runId = `${new Date(started).toISOString().replaceAll(/[:.]/g, '-')}-${process.pid}`;
  const requestedProductionProfile = isProductionProfile(options);
  const evidence: Evidence = {
    schemaVersion: 3,
    runId,
    status: 'running',
    startedAt: new Date(started).toISOString(),
    qualification: {
      requestedProductionProfile,
      diagnosticsAvailable: false,
      connectionDiagnosticsAvailable: false,
      fileDiagnosticsAvailable: false,
      runtimeDiagnosticsAvailable: false,
      fileDescriptorTelemetryAvailable: false,
      productionGateEligible: false,
      notes: []
    },
    configuration: {
      fileCount: options.fileCount,
      pushes: options.fileCount / 2,
      pulls: options.fileCount / 2,
      sequentialPerDirection: options.fileCount / 4,
      concurrentPerDirection: options.fileCount / 4,
      concurrency: options.concurrency,
      batchSize: options.batchSize,
      chunkSize: CHUNK_SIZE,
      lanes: LANES,
      smallFiles: options.fileCount - Math.ceil(options.fileCount / 10),
      largeFiles: Math.ceil(options.fileCount / 10),
      largeFileBytes: LARGE_FILE_BYTES,
      errorCasesPerClass: options.errorCases,
      locator: options.locator,
      relay: options.relay,
      relayUrlFingerprints: options.relayUrls.map(relayFingerprint),
      bindAddressFingerprints: options.bindAddresses.map(fingerprint),
      dnsServerUrlFingerprint: options.dnsServerUrl ? fingerprint(options.dnsServerUrl) : null,
      mdnsServiceNameFingerprint: options.locator === 'mdns' ? fingerprint(options.mdnsServiceName) : null,
      checkpointTimeoutMs: options.checkpointTimeoutMs
    },
    relayEvidence: {
      configured: options.relayUrls.map(relayFingerprint).sort(),
      attempted: [],
      connected: [],
      denied: [],
      attemptVisibility: options.locator === 'dns' ? 'opaque-native-dns' : 'explicit-candidates'
    },
    environment: {
      platform: process.platform,
      architecture: process.arch,
      node: process.version,
      pid: process.pid,
      cpuCount: availableParallelism(),
      gcExposed: typeof globalThis.gc === 'function',
      workspaceFreeBytes: null,
      estimatedWorkspaceBytes: estimatedWorkspaceBytes(options.fileCount)
    },
    phases: [],
    checkpoints: []
  };
  await artifact.write(evidence);

  let directory: string | undefined;
  let sender: P2PNode<Router, StressFileMetadata> | undefined;
  let receiver: P2PNode<Router, StressFileMetadata> | undefined;
  let sampler: ProcessSampler | undefined;
  try {
    directory = await mkdtemp(join(tmpdir(), 'p2prpc-file-lifecycle-'));
    const filesystem = await statfs(directory).catch(() => undefined);
    evidence.environment.workspaceFreeBytes = filesystem
      ? Number(filesystem.bavail) * Number(filesystem.bsize)
      : null;
    assertDiskCapacity(evidence.environment.workspaceFreeBytes, evidence.environment.estimatedWorkspaceBytes);
    await artifact.write(evidence);

    const layout = await prepareLayout(directory);
    const records = await createSources(options.fileCount, layout);
    const pushByName = new Map(records.filter((record) => record.kind === 'push').map((record) => [record.name, record]));
    const positiveOffers = new Set<string>();
    const destinationFailureAttempts = new Map<number, number>();
    const senderAudit = auditCounts();
    const receiverAudit = auditCounts();
    const unexpectedErrors: string[] = [];
    const expectedSession = { id: undefined as string | undefined };
    let acceptingNegativeCases = false;
    let resolveInbound!: (peer: Peer<Router, StressFileMetadata>) => void;
    const inboundPeerPromise = new Promise<Peer<Router, StressFileMetadata>>((resolvePeer) => {
      resolveInbound = resolvePeer;
    });
    const security = createSharedSecretSecurity<StressFileMetadata>(randomBytes(32), {
      sessionTtlMs: SESSION_TTL_MS,
      authorize: () => true
    });
    const relayEvidence = createRelayEvidenceTracker(options, evidence.relayEvidence);
    const nodeOptions = commonNodeOptions(options, relayEvidence.allowRelayUrl);
    receiver = await createP2PNode<Router, StressFileMetadata>({
      router,
      protocol: { applicationId: 'p2prpc-file-stream-lifecycle', contractVersion: '1' },
      security,
      createContext: (context) => context,
      fileMetadataSchema: stressFileMetadataSchema,
      onSecurityEvent: (event) => observeAudit(receiverAudit, event),
      onError: (error) => {
        if (!acceptingNegativeCases) unexpectedErrors.push(`${error.code}: ${error.message}`);
      },
      onPeer: (peer) => resolveInbound(peer as Peer<Router, StressFileMetadata>),
      onIncomingFile: (offer) => {
        const metadata = validateMetadata(offer.manifest.metadata);
        if (expectedSession.id !== undefined && offer.sessionId !== expectedSession.id) {
          return { reject: 'Authenticated session changed' };
        }
        if (metadata.kind === 'rejected') {
          return { reject: 'Intentional lifecycle rejection' };
        }
        if (metadata.kind === 'destination-failure') {
          destinationFailureAttempts.set(
            metadata.index,
            (destinationFailureAttempts.get(metadata.index) ?? 0) + 1
          );
          return { accept: failingDestination() };
        }
        if (metadata.kind === 'cancelled') {
          return { accept: slowDestination() };
        }
        if (metadata.kind !== 'push') {
          return { reject: 'Unexpected incoming file class' };
        }
        const record = pushByName.get(offer.manifest.name);
        if (
          !record ||
          record.index !== metadata.index ||
          record.size !== offer.manifest.size ||
          record.sha256 !== metadata.sha256 ||
          positiveOffers.has(record.name)
        ) {
          return { reject: 'Unexpected or duplicate stress manifest' };
        }
        positiveOffers.add(record.name);
        return { accept: fileDestination(record.destinationPath, { durable: false }) };
      },
      ...nodeOptions
    });
    sender = await createP2PNode<Router, StressFileMetadata>({
      router,
      protocol: { applicationId: 'p2prpc-file-stream-lifecycle', contractVersion: '1' },
      security,
      createContext: (context) => context,
      fileMetadataSchema: stressFileMetadataSchema,
      onSecurityEvent: (event) => observeAudit(senderAudit, event),
      onError: (error) => {
        if (!acceptingNegativeCases) unexpectedErrors.push(`${error.code}: ${error.message}`);
      },
      ...nodeOptions
    });

    const ticket = await receiver.createTicket();
    const target: ConnectOptions = {
      locator: locator(options, ticket),
      expectedPeerId: receiver.id,
      expectedPrincipal: absentOptionalPrincipal(receiver.id)
    };
    relayEvidence.beginDial();
    let outboundPeer: Peer<Router, StressFileMetadata>;
    try {
      outboundPeer = await sender.connect<Router>(target);
    } finally {
      relayEvidence.endDial();
    }
    const inboundPeer = await withTimeout(inboundPeerPromise, options.checkpointTimeoutMs, 'Inbound peer callback timed out');
    expectedSession.id = outboundPeer.session.id;
    assert(inboundPeer.session.id === expectedSession.id, 'Both endpoints derived different authenticated session IDs');
    assert(outboundPeer.principal.id === receiver.id, 'Outbound principal did not match the trusted receiver');
    assert(inboundPeer.principal.id === sender.id, 'Inbound principal did not match the trusted sender');

    await settleRuntime();
    const baseline = await resourceSnapshot(sender, receiver, outboundPeer, inboundPeer);
    relayEvidence.observe(baseline);
    evidence.baseline = baseline;
    assertConnectionQuiescent(baseline.senderConnection, 'sender baseline');
    assertConnectionQuiescent(baseline.receiverConnection, 'receiver baseline');
    assertFileDiagnosticsQuiescent(baseline.senderFiles, 'sender baseline');
    assertFileDiagnosticsQuiescent(baseline.receiverFiles, 'receiver baseline');
    assertSchedulerQuiescent(baseline.senderScheduler, 'sender baseline');
    assertSchedulerQuiescent(baseline.receiverScheduler, 'receiver baseline');
    assertSharesQuiescent(baseline.senderShares, 'sender baseline');
    assertSharesQuiescent(baseline.receiverShares, 'receiver baseline');
    assertEndpointSingleConnection(baseline.senderEndpoint, 'sender baseline');
    assertEndpointSingleConnection(baseline.receiverEndpoint, 'receiver baseline');
    evidence.identities = {
      senderFingerprint: fingerprint(sender.id),
      receiverFingerprint: fingerprint(receiver.id),
      sessionFingerprint: fingerprint(expectedSession.id)
    };
    evidence.qualification.diagnosticsAvailable = baseline.senderEndpoint !== null && baseline.receiverEndpoint !== null;
    evidence.qualification.connectionDiagnosticsAvailable =
      baseline.senderConnection.connectionFingerprint !== null
      && baseline.receiverConnection.connectionFingerprint !== null
      && baseline.senderConnection.streams !== null
      && baseline.receiverConnection.streams !== null;
    evidence.qualification.fileDiagnosticsAvailable = baseline.senderFiles !== null && baseline.receiverFiles !== null;
    evidence.qualification.runtimeDiagnosticsAvailable =
      baseline.senderScheduler !== null
      && baseline.receiverScheduler !== null
      && baseline.senderShares !== null
      && baseline.receiverShares !== null
      && baseline.senderTasks !== null
      && baseline.receiverTasks !== null;
    evidence.qualification.fileDescriptorTelemetryAvailable = baseline.process.fileDescriptors !== null;
    if (!evidence.qualification.diagnosticsAvailable) {
      evidence.qualification.notes.push('Endpoint diagnostics are unavailable; native handle cleanup is reported as unqualified.');
    }
    if (!evidence.qualification.connectionDiagnosticsAvailable) {
      evidence.qualification.notes.push('Connection IDs or stream lifecycle counters are unavailable; the single-connection claim is unqualified.');
    }
    if (!evidence.qualification.fileDiagnosticsAvailable) {
      evidence.qualification.notes.push('Peer file diagnostics are unavailable; transfer queue and lane cleanup is reported as unqualified.');
    }
    if (!evidence.qualification.runtimeDiagnosticsAvailable) {
      evidence.qualification.notes.push('Scheduler, task, or capability diagnostics are unavailable; exact runtime quiescence is unqualified.');
    }
    if (baseline.senderEndpoint?.activeConnections !== 1 || baseline.receiverEndpoint?.activeConnections !== 1) {
      evidence.qualification.notes.push(
        'The native activeConnections gauge does not count raw session-mode QUIC; activeSessions and p2prpc connection IDs are authoritative.'
      );
    }
    if (!evidence.qualification.fileDescriptorTelemetryAvailable) {
      evidence.qualification.notes.push('File-descriptor telemetry is unavailable on this platform.');
    }
    if (options.relay === 'disabled') {
      evidence.qualification.notes.push(
        'Relay-less topology qualification additionally requires companion two-host evidence with non-loopback direct paths; this lifecycle run alone proves only p2prpc workload behavior.'
      );
    }
    if (!requestedProductionProfile) {
      evidence.qualification.notes.push('Non-production counts or scheduling were requested; this is a harness smoke run only.');
    }
    await artifact.write(evidence);

    sampler = new ProcessSampler();
    sampler.observe(baseline.process);
    sampler.start();
    const context: HarnessContext = {
      options,
      evidence,
      artifact,
      directory,
      sender,
      receiver,
      outboundPeer,
      inboundPeer,
      sessionId: expectedSession.id,
      senderConnectionId: baseline.senderConnection.connectionFingerprint,
      receiverConnectionId: baseline.receiverConnection.connectionFingerprint,
      senderAudit,
      receiverAudit,
      positiveOffers,
      destinationFailureAttempts,
      unexpectedErrors,
      baseline,
      sampler,
      relayEvidence,
      pendingCapabilityCleanup: [],
      successfulTransferIds: new Set(),
      completedFiles: 0
    };

    const quarter = options.fileCount / 4;
    const pushes = records.filter((record) => record.kind === 'push');
    const pulls = records.filter((record) => record.kind === 'pull');
    evidence.phases.push(await runPhase(context, 'push-sequential', 'push', 'sequential', pushes.slice(0, quarter)));
    evidence.phases.push(await runPhase(context, 'push-concurrent', 'push', 'concurrent', pushes.slice(quarter)));
    evidence.phases.push(await runPhase(context, 'pull-sequential', 'pull', 'sequential', pulls.slice(0, quarter)));
    evidence.phases.push(await runPhase(context, 'pull-concurrent', 'pull', 'concurrent', pulls.slice(quarter)));

    assert(context.completedFiles === options.fileCount, `Expected ${options.fileCount} successful files`);
    assert(context.successfulTransferIds.size === options.fileCount, 'Successful transfer IDs were not unique');
    assert(positiveOffers.size === options.fileCount / 2, 'Push offer count was not exact');
    assert(receiverAudit.allowedPush === options.fileCount / 2, 'Push authorization count was not exact');
    assert(receiverAudit.allowedPull === options.fileCount / 2, 'Pull authorization count was not exact');
    const positivePushAuthorizations = receiverAudit.allowedPush;
    const positivePullAuthorizations = receiverAudit.allowedPull;
    assertNoUnexpectedSecurityEvents(senderAudit, receiverAudit);
    assert(unexpectedErrors.length === 0, `Unexpected runtime errors: ${unexpectedErrors.slice(0, 3).join('; ')}`);
    const positiveSnapshot = evidence.checkpoints.at(-1)?.resources;
    assert(positiveSnapshot !== undefined, 'Positive workload produced no resource checkpoint');
    assertExactSuccessfulStreamDeltas(baseline, positiveSnapshot, records);
    await verifyDirectory(layout.pushDestination, options.fileCount / 2);
    await verifyDirectory(layout.pullDestination, options.fileCount / 2);

    acceptingNegativeCases = true;
    evidence.negativeCases = await runNegativeCases(context, layout, options.errorCases);
    await checkpoint(context, 'negative-cleanup', 0, 0);
    const preCanaryResources = evidence.checkpoints.at(-1)!.resources;
    acceptingNegativeCases = false;
    evidence.negativeCases.rpcCanaries = await runRpcCanaries(context, 100);
    await checkpoint(context, 'post-error-canaries', 0, 0);
    const postCanaryResources = evidence.checkpoints.at(-1)!.resources;
    if (preCanaryResources.senderConnection.streams && postCanaryResources.senderConnection.streams) {
      assertStreamDelta(preCanaryResources.senderConnection.streams, postCanaryResources.senderConnection.streams, {
        openedBi: 100,
        acceptedBi: 0,
        openedUni: 0,
        acceptedUni: 0,
        sendFinished: 100,
        recvEof: 100
      }, 'sender RPC canaries');
      assert(
        postCanaryResources.senderConnection.streams.recvStopped
          === preCanaryResources.senderConnection.streams.recvStopped,
        'sender RPC canaries stopped a cleanly finished response stream'
      );
      assert(
        postCanaryResources.senderConnection.streams.sendReset
          === preCanaryResources.senderConnection.streams.sendReset,
        'sender RPC canaries reset a send stream'
      );
    }
    if (preCanaryResources.receiverConnection.streams && postCanaryResources.receiverConnection.streams) {
      assertStreamDelta(preCanaryResources.receiverConnection.streams, postCanaryResources.receiverConnection.streams, {
        openedBi: 0,
        acceptedBi: 100,
        openedUni: 0,
        acceptedUni: 0,
        sendFinished: 100,
        recvEof: 100
      }, 'receiver RPC canaries');
      assert(
        postCanaryResources.receiverConnection.streams.sendReset
          === preCanaryResources.receiverConnection.streams.sendReset,
        'receiver RPC canaries reset a send stream'
      );
      assert(
        postCanaryResources.receiverConnection.streams.recvStopped
          === preCanaryResources.receiverConnection.streams.recvStopped,
        'receiver RPC canaries stopped a request stream'
      );
    }
    await assertNoTransferDebris(directory);

    const final = await resourceSnapshot(sender, receiver, outboundPeer, inboundPeer);
    relayEvidence.observe(final);
    assertResourceReturn(context, final, false);
    assert(final.process.rssBytes <= baseline.process.rssBytes + options.maxRssGrowthBytes,
      `RSS grew by more than ${options.maxRssGrowthBytes / MIB} MiB`);
    assert(final.process.heapUsedBytes <= baseline.process.heapUsedBytes + options.maxHeapGrowthBytes,
      `Heap grew by more than ${options.maxHeapGrowthBytes / MIB} MiB`);
    if (baseline.process.fileDescriptors !== null && sampler.peakFileDescriptors !== null) {
      assert(sampler.peakFileDescriptors <= baseline.process.fileDescriptors + 64, 'Peak file descriptors exceeded baseline +64');
    }

    evidence.totals = {
      successfulFiles: context.completedFiles,
      uniqueTransferIds: context.successfulTransferIds.size,
      uniquePushOffers: positiveOffers.size,
      pushAuthorizations: positivePushAuthorizations,
      pullAuthorizations: positivePullAuthorizations,
      authenticationEventsPerEndpoint: senderAudit.authenticated,
      elapsedMs: Date.now() - started,
      peakRssBytes: sampler.peakRssBytes,
      peakHeapUsedBytes: sampler.peakHeapUsedBytes,
      peakFileDescriptors: sampler.peakFileDescriptors
    };
    const negativeControlAttemptsExact = Object.values(evidence.negativeCases.controlAttempts)
      .every((attempts) => attempts.exact);
    if (!negativeControlAttemptsExact) {
      evidence.qualification.notes.push('Exact negative-case control-stream accounting was unavailable or did not match.');
    }
    evidence.qualification.productionGateEligible = requestedProductionProfile
      && evidence.qualification.diagnosticsAvailable
      && evidence.qualification.connectionDiagnosticsAvailable
      && evidence.qualification.fileDiagnosticsAvailable
      && evidence.qualification.runtimeDiagnosticsAvailable
      && evidence.qualification.fileDescriptorTelemetryAvailable
      && negativeControlAttemptsExact;
    evidence.status = 'passed';
    evidence.finishedAt = new Date().toISOString();
    await artifact.write(evidence);
    process.stdout.write(`${JSON.stringify({
      status: evidence.status,
      artifact: options.output,
      successfulFiles: context.completedFiles,
      productionGateEligible: evidence.qualification.productionGateEligible,
      elapsedMs: evidence.totals.elapsedMs
    })}\n`);
  } catch (cause) {
    evidence.status = 'failed';
    evidence.finishedAt = new Date().toISOString();
    evidence.failure = serializeError(cause);
    await artifact.write(evidence).catch(() => undefined);
    throw cause;
  } finally {
    sampler?.stop();
    await Promise.allSettled([sender?.close(), receiver?.close()].filter((value): value is Promise<void> => value !== undefined));
    if (directory && !options.keepWorkdir) await rm(directory, { recursive: true, force: true });
    if (directory && options.keepWorkdir) process.stderr.write(`Kept stress workspace: ${directory}\n`);
  }
}

async function runPhase(
  context: HarnessContext,
  name: string,
  direction: 'push' | 'pull',
  scheduling: 'sequential' | 'concurrent',
  records: readonly FileRecord[]
): Promise<PhaseEvidence> {
  const phaseStarted = performance.now();
  const latencies: number[] = [];
  const batchMillisecondsPerFile: number[] = [];
  for (let offset = 0; offset < records.length; offset += context.options.batchSize) {
    const batch = records.slice(offset, offset + context.options.batchSize);
    const batchStarted = performance.now();
    if (scheduling === 'sequential') {
      for (const record of batch) latencies.push(await transferOne(context, record));
    } else {
      await runBounded(batch, context.options.concurrency, async (record) => {
        latencies.push(await transferOne(context, record));
      });
    }
    const batchDurationMs = performance.now() - batchStarted;
    batchMillisecondsPerFile.push(batchDurationMs / batch.length);
    await checkpoint(context, name, batch.length, batchDurationMs);
  }
  const slowdownRatio = progressiveSlowdown(batchMillisecondsPerFile);
  if (slowdownRatio !== null) assert(slowdownRatio <= 1.5, `${name} slowed progressively by ${slowdownRatio.toFixed(2)}x`);
  latencies.sort((left, right) => left - right);
  return {
    name,
    direction,
    scheduling: scheduling === 'sequential' ? 'sequential' : `concurrency-${context.options.concurrency}`,
    files: records.length,
    durationMs: performance.now() - phaseStarted,
    fileLatencyMs: {
      p50: percentile(latencies, 0.5),
      p95: percentile(latencies, 0.95),
      p99: percentile(latencies, 0.99),
      maximum: latencies.at(-1) ?? 0
    },
    batchMillisecondsPerFile,
    slowdownRatio
  };
}

async function transferOne(context: HarnessContext, record: FileRecord): Promise<number> {
  const started = performance.now();
  const metadata: StressFileMetadata = { kind: record.kind, index: record.index, sha256: record.sha256 };
  if (record.kind === 'push') {
    const transfer = await context.outboundPeer.files.sendFile(await fileSource(record.sourcePath, metadata), {
      chunkSize: CHUNK_SIZE,
      lanes: LANES,
      transferId: `stress-push-${record.index.toString().padStart(5, '0')}`
    });
    const result = await transfer.result;
    assertManifest(record, result.manifest);
    assert(!result.resumed, `${record.name} unexpectedly resumed`);
    recordTransferId(context, result.manifest.transferId);
  } else {
    const source = await fileSource(record.sourcePath, metadata);
    const handle = context.inboundPeer.files.share(source, { maxDownloads: 1 });
    const transfer = await context.outboundPeer.files.download(
      handle,
      fileDestination(record.destinationPath, { durable: false }),
      { chunkSize: CHUNK_SIZE, lanes: LANES }
    );
    const result = await transfer.result;
    assertManifest(record, result.manifest);
    assert(!result.resumed, `${record.name} unexpectedly resumed`);
    recordTransferId(context, result.manifest.transferId);
    context.pendingCapabilityCleanup.push(handle);
  }
  assert(await sha256File(record.destinationPath) === record.sha256, `${record.name} destination digest mismatch`);
  context.completedFiles += 1;
  return performance.now() - started;
}

async function checkpoint(
  context: HarnessContext,
  phase: string,
  batchFiles: number,
  batchDurationMs: number,
  requireSuccessTerminals = !phase.startsWith('negative-') && phase !== 'post-error-canaries'
): Promise<void> {
  forceGc();
  await settleRuntime();
  for (const handle of context.pendingCapabilityCleanup.splice(0)) {
    assert(context.inboundPeer.files.revoke(handle), 'Completed pull capability cleanup failed');
  }
  await settleRuntime();
  const resources = await waitForResourceReturn(context);
  context.relayEvidence.observe(resources);
  context.sampler.observe(resources.process);
  context.evidence.checkpoints.push({
    sequence: context.evidence.checkpoints.length + 1,
    phase,
    completedFiles: context.completedFiles,
    batchFiles,
    batchDurationMs,
    capturedAt: new Date().toISOString(),
    resources
  });
  await context.artifact.write(context.evidence);
  assertSessionInvariant(context);
  assertResourceReturn(context, resources, requireSuccessTerminals);
  if (resources.process.fileDescriptors !== null && context.baseline.process.fileDescriptors !== null) {
    assert(resources.process.fileDescriptors <= context.baseline.process.fileDescriptors + 8,
      `${phase} file descriptors did not return within baseline +8`);
  }
  process.stderr.write(
    `[${phase}] ${context.completedFiles}/${context.options.fileCount} files; ` +
    `rss=${(resources.process.rssBytes / MIB).toFixed(1)}MiB; ` +
    `fds=${resources.process.fileDescriptors ?? 'n/a'}\n`
  );
}

async function waitForResourceReturn(context: HarnessContext): Promise<ResourceSnapshot> {
  const deadline = Date.now() + context.options.checkpointTimeoutMs;
  let latest = await resourceSnapshot(context.sender, context.receiver, context.outboundPeer, context.inboundPeer);
  while (Date.now() < deadline && !resourcesAtBaseline(context.baseline, latest)) {
    await delay(50);
    latest = await resourceSnapshot(context.sender, context.receiver, context.outboundPeer, context.inboundPeer);
  }
  return latest;
}

function resourcesAtBaseline(baseline: ResourceSnapshot, current: ResourceSnapshot): boolean {
  if (!connectionQuiescent(current.senderConnection) || !connectionQuiescent(current.receiverConnection)) return false;
  if (!fileDiagnosticsQuiescent(current.senderFiles) || !fileDiagnosticsQuiescent(current.receiverFiles)) return false;
  if (!sameSchedulerGauges(baseline.senderScheduler, current.senderScheduler)) return false;
  if (!sameSchedulerGauges(baseline.receiverScheduler, current.receiverScheduler)) return false;
  if (!sameShareGauges(baseline.senderShares, current.senderShares)) return false;
  if (!sameShareGauges(baseline.receiverShares, current.receiverShares)) return false;
  if (!sameTaskGauges(baseline.senderTasks, current.senderTasks)) return false;
  if (!sameTaskGauges(baseline.receiverTasks, current.receiverTasks)) return false;
  if (baseline.senderEndpoint && current.senderEndpoint && !sameEndpointGauges(baseline.senderEndpoint, current.senderEndpoint)) return false;
  if (baseline.receiverEndpoint && current.receiverEndpoint && !sameEndpointGauges(baseline.receiverEndpoint, current.receiverEndpoint)) return false;
  return true;
}

function assertResourceReturn(context: HarnessContext, current: ResourceSnapshot, requireSuccessTerminals: boolean): void {
  assertConnectionQuiescent(current.senderConnection, 'sender');
  assertConnectionQuiescent(current.receiverConnection, 'receiver');
  assertFileDiagnosticsQuiescent(current.senderFiles, 'sender');
  assertFileDiagnosticsQuiescent(current.receiverFiles, 'receiver');
  assertSameSchedulerGauges(context.baseline.senderScheduler, current.senderScheduler, 'sender');
  assertSameSchedulerGauges(context.baseline.receiverScheduler, current.receiverScheduler, 'receiver');
  assertSameShareGauges(context.baseline.senderShares, current.senderShares, 'sender');
  assertSameShareGauges(context.baseline.receiverShares, current.receiverShares, 'receiver');
  assertSameTaskGauges(context.baseline.senderTasks, current.senderTasks, 'sender');
  assertSameTaskGauges(context.baseline.receiverTasks, current.receiverTasks, 'receiver');
  assert(current.senderConnection.connectionFingerprint === context.senderConnectionId, 'Sender physical connection changed');
  assert(current.receiverConnection.connectionFingerprint === context.receiverConnectionId, 'Receiver physical connection changed');
  if (context.baseline.senderEndpoint && current.senderEndpoint) {
    assert(sameEndpointGauges(context.baseline.senderEndpoint, current.senderEndpoint), 'Sender native handles did not return to baseline');
  }
  if (context.baseline.receiverEndpoint && current.receiverEndpoint) {
    assert(sameEndpointGauges(context.baseline.receiverEndpoint, current.receiverEndpoint), 'Receiver native handles did not return to baseline');
  }
  if (requireSuccessTerminals) {
    assertNoNewErrorTerminals(context.baseline.senderConnection.streams, current.senderConnection.streams, 'sender');
    assertNoNewErrorTerminals(context.baseline.receiverConnection.streams, current.receiverConnection.streams, 'receiver');
  }
}

function assertSessionInvariant(context: HarnessContext): void {
  assert(context.outboundPeer.session.id === context.sessionId, 'Outbound authenticated session changed');
  assert(context.inboundPeer.session.id === context.sessionId, 'Inbound authenticated session changed');
  assert(context.senderAudit.authenticated === 1, 'Sender authenticated more than one physical session');
  assert(context.receiverAudit.authenticated === 1, 'Receiver authenticated more than one physical session');
  assert(context.senderAudit.sessionIds.size === 1 && context.senderAudit.sessionIds.has(context.sessionId), 'Sender audit session changed');
  assert(context.receiverAudit.sessionIds.size === 1 && context.receiverAudit.sessionIds.has(context.sessionId), 'Receiver audit session changed');
}

async function runNegativeCases(
  context: HarnessContext,
  layout: Awaited<ReturnType<typeof prepareLayout>>,
  count: number
): Promise<NonNullable<Evidence['negativeCases']>> {
  const sourcePath = join(layout.sourceRoot, 'negative-source.bin');
  const content = deterministicContent(1_000_000, 2 * MIB);
  await writeFile(sourcePath, content, { flag: 'wx', mode: 0o600 });
  const sha256 = sha256Bytes(content);
  const expectFailure = async (
    operation: () => Promise<unknown>,
    label: string,
    expectedCode?: string
  ): Promise<void> => {
    let failed = false;
    let cause: unknown;
    try {
      await operation();
    } catch (error) {
      failed = true;
      cause = error;
    }
    assert(failed, `${label} unexpectedly succeeded`);
    if (expectedCode !== undefined) {
      assert(
        typeof cause === 'object'
          && cause !== null
          && 'code' in cause
          && cause.code === expectedCode,
        `${label} failed with the wrong terminal classification`
      );
    }
  };

  let before = latestCheckpointResources(context);
  await runBounded(Array.from({ length: count }, (_, index) => index), context.options.concurrency, async (index) => {
    await expectFailure(async () => {
      const source = await fileSource<StressFileMetadata>(sourcePath, { kind: 'rejected', index, sha256 });
      const transfer = await context.outboundPeer.files.sendFile(source, {
        chunkSize: CHUNK_SIZE,
        lanes: LANES,
        transferId: `negative-reject-${index}`
      });
      await transfer.result;
    }, 'Rejected push');
  });
  if (count > 0) await checkpoint(context, 'negative-rejected-pushes', 0, 0, false);
  let after = latestCheckpointResources(context);
  const rejectedPushAttempts = controlAttemptEvidence(before, after, count, 'rejected pushes');

  before = after;
  await runBounded(Array.from({ length: count }, (_, index) => index), context.options.concurrency, async (index) => {
    const source = await fileSource<StressFileMetadata>(sourcePath, { kind: 'pull', index, sha256 });
    const handle = context.inboundPeer.files.share(source, { maxDownloads: 1 });
    assert(context.inboundPeer.files.revoke(handle), 'Capability revocation failed');
    await expectFailure(async () => {
      const transfer = await context.outboundPeer.files.download(
        handle,
        fileDestination(join(layout.negativeDestination, `revoked-${index}.bin`), { durable: false }),
        { chunkSize: CHUNK_SIZE, lanes: LANES }
      );
      await transfer.result;
    }, 'Revoked pull');
  });
  if (count > 0) await checkpoint(context, 'negative-revoked-pulls', 0, 0, false);
  after = latestCheckpointResources(context);
  const revokedPullAttempts = controlAttemptEvidence(before, after, count, 'revoked pulls');

  before = after;
  await runBounded(Array.from({ length: count }, (_, index) => index), context.options.concurrency, async (index) => {
    await expectFailure(async () => {
      const source = await fileSource<StressFileMetadata>(sourcePath, { kind: 'cancelled', index, sha256 });
      const transfer = await context.outboundPeer.files.sendFile(source, {
        chunkSize: CHUNK_SIZE,
        lanes: CANCELLATION_LANES,
        transferId: `negative-cancel-${index}`
      });
      const progress = transfer.progress()[Symbol.asyncIterator]();
      const first = await withTimeout(
        progress.next(),
        context.options.checkpointTimeoutMs,
        'Cancelled push did not reach an established data lane'
      );
      assert(
        !first.done && first.value.transferredBytes > 0,
        'Cancelled push settled before its established data lane made progress'
      );
      transfer.cancel(new Error('Intentional stress cancellation'));
      await progress.return?.();
      await transfer.result;
    }, 'Cancelled push');
  });
  if (count > 0) await checkpoint(context, 'negative-sender-cancellations', 0, 0, false);
  after = latestCheckpointResources(context);
  const senderCancellationAttempts = controlAttemptEvidence(before, after, count, 'sender cancellations');

  before = after;
  await runBounded(Array.from({ length: count }, (_, index) => index), context.options.concurrency, async (index) => {
    await expectFailure(async () => {
      const source = await fileSource<StressFileMetadata>(sourcePath, { kind: 'destination-failure', index, sha256 });
      const transfer = await context.outboundPeer.files.sendFile(source, {
        chunkSize: CHUNK_SIZE,
        lanes: LANES,
        transferId: `negative-destination-${index}`
      });
      await transfer.result;
    }, 'Destination failure', 'REJECTED');
  });
  if (count > 0) await checkpoint(context, 'negative-destination-failures', 0, 0, false);
  after = latestCheckpointResources(context);
  const destinationFailureAttempts = controlAttemptEvidence(before, after, count, 'destination failures');

  const destinationFailureAttemptsByIndex = Array.from(
    { length: count },
    (_, index) => context.destinationFailureAttempts.get(index) ?? 0
  );
  assert(
    context.destinationFailureAttempts.size === count
      && destinationFailureAttemptsByIndex.every((attempts) => attempts === 1),
    `Destination failures retried or skipped a control attempt: ${destinationFailureAttemptsByIndex.join(',')}`
  );

  return {
    rejectedPushes: count,
    revokedPulls: count,
    senderCancellations: count,
    senderCancellationLanes: CANCELLATION_LANES,
    senderCancellationTrigger: 'first-data-progress',
    destinationFailures: count,
    controlAttempts: {
      rejectedPushes: rejectedPushAttempts,
      revokedPulls: revokedPullAttempts,
      senderCancellations: senderCancellationAttempts,
      destinationFailures: destinationFailureAttempts
    },
    destinationFailureAttemptsByIndex,
    rpcCanaries: 0
  };
}

function latestCheckpointResources(context: HarnessContext): ResourceSnapshot {
  const resources = context.evidence.checkpoints.at(-1)?.resources;
  assert(resources !== undefined, 'Negative control-attempt accounting requires a preceding resource checkpoint');
  return resources;
}

function controlAttemptEvidence(
  before: ResourceSnapshot,
  after: ResourceSnapshot,
  logicalCases: number,
  label: string
): ControlAttemptEvidence {
  const senderBefore = before.senderConnection.streams;
  const senderAfter = after.senderConnection.streams;
  const receiverBefore = before.receiverConnection.streams;
  const receiverAfter = after.receiverConnection.streams;
  const senderOpenedBi = senderBefore && senderAfter
    ? senderAfter.openedBi - senderBefore.openedBi
    : null;
  const receiverAcceptedBi = receiverBefore && receiverAfter
    ? receiverAfter.acceptedBi - receiverBefore.acceptedBi
    : null;
  const exact = senderOpenedBi === logicalCases && receiverAcceptedBi === logicalCases;
  if (senderOpenedBi !== null && receiverAcceptedBi !== null) {
    assert(
      exact,
      `${label} opened/accepted ${senderOpenedBi}/${receiverAcceptedBi} control streams for ${logicalCases} logical cases`
    );
  }
  return { logicalCases, senderOpenedBi, receiverAcceptedBi, exact };
}

async function runRpcCanaries(context: HarnessContext, count: number): Promise<number> {
  await runBounded(Array.from({ length: count }, (_, index) => index), context.options.concurrency, async () => {
    const response = await context.outboundPeer.rpc.ping.query();
    assert(response.peerId === context.sender.id, 'RPC canary observed the wrong peer');
    assert(response.sessionId === context.sessionId, 'RPC canary observed a replacement session');
  });
  return count;
}

async function prepareLayout(directory: string): Promise<{
  sourceRoot: string;
  pushSource: string;
  pullSource: string;
  pushDestination: string;
  pullDestination: string;
  negativeDestination: string;
}> {
  const layout = {
    sourceRoot: join(directory, 'sources'),
    pushSource: join(directory, 'sources', 'push'),
    pullSource: join(directory, 'sources', 'pull'),
    pushDestination: join(directory, 'destinations', 'push'),
    pullDestination: join(directory, 'destinations', 'pull'),
    negativeDestination: join(directory, 'destinations', 'negative')
  };
  await Promise.all(Object.values(layout).map((path) => mkdir(path, { recursive: true })));
  return layout;
}

async function createSources(
  count: number,
  layout: Awaited<ReturnType<typeof prepareLayout>>
): Promise<FileRecord[]> {
  const records = Array.from({ length: count }, (_, index): FileRecord => {
    const kind = index < count / 2 ? 'push' : 'pull';
    const name = `${kind}-${index.toString().padStart(5, '0')}.bin`;
    const size = fileSize(index);
    const content = deterministicContent(index, size);
    return {
      index,
      kind,
      name,
      sourcePath: join(kind === 'push' ? layout.pushSource : layout.pullSource, name),
      destinationPath: join(kind === 'push' ? layout.pushDestination : layout.pullDestination, name),
      size,
      sha256: sha256Bytes(content),
      blake3: blake3(content).toString('hex')
    };
  });
  await runBounded(records, Math.min(32, Math.max(1, records.length)), async (record) => {
    await writeFile(record.sourcePath, deterministicContent(record.index, record.size), { flag: 'wx', mode: 0o600 });
  });
  return records;
}

function fileSize(index: number): number {
  if (index % 10 === 0) return LARGE_FILE_BYTES;
  return 1024 + ((index * 2654435761) >>> 0) % 3073;
}

function deterministicContent(index: number, size: number): Buffer {
  const content = Buffer.alloc(size, (index * 131 + 17) & 0xff);
  for (let offset = 0; offset + 8 <= size; offset += 4096) {
    content.writeUInt32LE(index >>> 0, offset);
    content.writeUInt32LE((index ^ offset ^ size) >>> 0, offset + 4);
  }
  return content;
}

function commonNodeOptions(options: Options, allowRelayUrl?: (origin: string) => boolean): {
  iroh: IrohEndpointOptions;
  limits: {
    maxFileTransfers: number;
    maxGlobalFileTransfers: number;
    maxPrincipalFileTransfers: number;
    fileChunkSize: number;
    maxFileChunkSize: number;
    fileLanes: number;
    maxFileLanes: number;
    maxInboundStreams: number;
    maxGlobalInboundStreams: number;
    maxPrincipalInboundStreams: number;
    maxBufferedBytes: number;
    maxPeerBufferedBytes: number;
    maxPrincipalBufferedBytes: number;
    maxSessionTtlMs: number;
    connectTimeoutMs: number;
  };
} {
  const relay: NonNullable<IrohEndpointOptions['relay']> = options.relay === 'custom'
    ? { mode: 'custom', urls: options.relayUrls }
    : { mode: options.relay };
  const discovery: NonNullable<IrohEndpointOptions['discovery']> = options.locator === 'dns'
    ? { dns: options.dnsServerUrl ? { serverUrl: options.dnsServerUrl } : true }
    : options.locator === 'mdns'
      ? { mdns: { serviceName: options.mdnsServiceName, advertise: true } }
      : { dns: false, mdns: false };
  const admittedStreams = options.concurrency * (LANES + 1);
  const fileDataBuffer = Math.max(CONTROL_FRAME_BYTES, CHUNK_SIZE + FILE_DATA_SEGMENT_BYTES);
  const admittedBuffers = options.concurrency * (CONTROL_FRAME_BYTES + LANES * fileDataBuffer);
  return {
    iroh: {
      relay,
      discovery,
      // This is a controlled topology harness. Production applications should
      // use a real address allowlist instead of admitting every ticket hint.
      ...(options.locator === 'dns' ? {} : { allowDirectAddress: () => true }),
      ...(allowRelayUrl ? { allowRelayUrl } : {}),
      ...(options.bindAddresses.length > 0 ? { bindAddress: options.bindAddresses } : {})
    },
    limits: {
      maxFileTransfers: options.concurrency,
      maxGlobalFileTransfers: options.concurrency * 2,
      maxPrincipalFileTransfers: options.concurrency,
      fileChunkSize: CHUNK_SIZE,
      maxFileChunkSize: CHUNK_SIZE,
      fileLanes: LANES,
      maxFileLanes: LANES,
      // The runtime owns logical admission; native QUIC stream limits are
      // deliberately not part of the public node API. Admit one control plus
      // every data lane for each scheduled transfer so the harness measures
      // lifecycle cleanup rather than an unrelated queue ceiling.
      maxInboundStreams: admittedStreams,
      maxGlobalInboundStreams: admittedStreams,
      maxPrincipalInboundStreams: admittedStreams,
      maxBufferedBytes: admittedBuffers,
      maxPeerBufferedBytes: admittedBuffers,
      maxPrincipalBufferedBytes: admittedBuffers,
      maxSessionTtlMs: SESSION_TTL_MS,
      connectTimeoutMs: 60_000
    }
  };
}

function locator(options: Options, ticket: string): PeerLocator {
  if (options.locator === 'ticket') return { kind: 'ticket', ticket };
  if (options.locator === 'dns') return { kind: 'dns' };
  return { kind: 'mdns', serviceName: options.mdnsServiceName };
}

async function resourceSnapshot(
  sender: P2PNode<Router, StressFileMetadata>,
  receiver: P2PNode<Router, StressFileMetadata>,
  outboundPeer: Peer<Router, StressFileMetadata>,
  inboundPeer: Peer<Router, StressFileMetadata>
): Promise<ResourceSnapshot> {
  const [processStats, senderPeer, receiverPeer, senderEndpoint, receiverEndpoint] = await Promise.all([
    processSnapshot(),
    optionalPeerDiagnostics(outboundPeer),
    optionalPeerDiagnostics(inboundPeer),
    optionalDiagnostics(sender),
    optionalDiagnostics(receiver)
  ]);
  return {
    process: processStats,
    senderConnection: sanitizeConnectionStats(senderPeer.connection),
    receiverConnection: sanitizeConnectionStats(receiverPeer.connection),
    senderFiles: senderPeer.files,
    receiverFiles: receiverPeer.files,
    senderScheduler: senderPeer.resources,
    receiverScheduler: receiverPeer.resources,
    senderShares: senderPeer.shares,
    receiverShares: receiverPeer.shares,
    senderTasks: senderPeer.tasks,
    receiverTasks: receiverPeer.tasks,
    senderEndpoint,
    receiverEndpoint
  };
}

async function optionalPeerDiagnostics(peer: Peer<Router, StressFileMetadata>): Promise<{
  connection: ConnectionStats;
  files: FileTransferDiagnostics | null;
  resources: PeerDiagnostics['resources'] | null;
  shares: PeerDiagnostics['shares'] | null;
  tasks: PeerDiagnostics['tasks'] | null;
}> {
  const candidate = peer as Peer<Router, StressFileMetadata> & {
    diagnostics?: () => Promise<PeerDiagnostics>;
  };
  if (typeof candidate.diagnostics === 'function') {
    const diagnostics = await candidate.diagnostics();
    return {
      connection: diagnostics.connection,
      files: diagnostics.files,
      resources: diagnostics.resources,
      shares: diagnostics.shares,
      tasks: diagnostics.tasks
    };
  }
  return {
    connection: await peer.stats(),
    files: null,
    resources: null,
    shares: null,
    tasks: null
  };
}

async function optionalDiagnostics(node: P2PNode<Router, StressFileMetadata>): Promise<EndpointDiagnostics | null> {
  const candidate = node as P2PNode<Router, StressFileMetadata> & {
    diagnostics?: () => Promise<EndpointDiagnostics>;
  };
  if (typeof candidate.diagnostics !== 'function') return null;
  try {
    return await candidate.diagnostics();
  } catch {
    return null;
  }
}

function sanitizeConnectionStats(stats: ConnectionStats): SanitizedConnectionStats {
  const extended = stats as ConnectionStats & Partial<{
    connectionId: string;
    sentPackets: number | null;
    congestionWindow: number | null;
    relay: boolean | null;
    relayUrl: string | null;
    paths: readonly { relay: boolean; address: string; active: boolean }[];
    streams: StreamLifecycleStats;
  }>;
  return {
    connectionFingerprint: extended.connectionId ? fingerprint(extended.connectionId) : null,
    rttMs: stats.rttMs,
    sentBytes: stats.sentBytes,
    receivedBytes: stats.receivedBytes,
    lostPackets: stats.lostPackets,
    sentPackets: extended.sentPackets ?? null,
    congestionWindow: extended.congestionWindow ?? null,
    relay: extended.relay ?? null,
    relayUrlFingerprint: extended.relayUrl
      ? relayFingerprint(canonicalRelayOrigin(extended.relayUrl))
      : null,
    paths: (extended.paths ?? []).map((path) => ({
      relay: path.relay,
      active: path.active,
      addressFingerprint: fingerprint(path.address)
    })),
    streams: extended.streams ? { ...extended.streams } : null
  };
}

async function processSnapshot(): Promise<ProcessSnapshot> {
  const memory = process.memoryUsage();
  const resources = typeof process.getActiveResourcesInfo === 'function'
    ? process.getActiveResourcesInfo()
    : [];
  const activeResources: Record<string, number> = {};
  for (const resource of resources) activeResources[resource] = (activeResources[resource] ?? 0) + 1;
  return {
    timestamp: new Date().toISOString(),
    rssBytes: memory.rss,
    heapUsedBytes: memory.heapUsed,
    externalBytes: memory.external,
    arrayBuffersBytes: memory.arrayBuffers,
    fileDescriptors: await fileDescriptorCount(),
    activeResources
  };
}

async function fileDescriptorCount(): Promise<number | null> {
  if (process.platform !== 'linux') return null;
  return readdir('/proc/self/fd').then((entries) => entries.length, () => null);
}

function assertConnectionQuiescent(stats: SanitizedConnectionStats, label: string): void {
  assert(connectionQuiescent(stats), `${label} still owns active stream handles`);
  if (!stats.streams) return;
  const totalSend = stats.streams.openedBi + stats.streams.acceptedBi + stats.streams.openedUni;
  const totalRecv = stats.streams.openedBi + stats.streams.acceptedBi + stats.streams.acceptedUni;
  assert(stats.streams.sendFinished + stats.streams.sendReset === totalSend, `${label} send terminals are unbalanced`);
  assert(stats.streams.recvEof + stats.streams.recvStopped === totalRecv, `${label} receive terminals are unbalanced`);
}

function connectionQuiescent(stats: SanitizedConnectionStats): boolean {
  return !stats.streams || (stats.streams.activeSend === 0 && stats.streams.activeRecv === 0);
}

function assertEndpointSingleConnection(stats: EndpointDiagnostics | null, label: string): void {
  if (!stats) return;
  assert(stats.activeSessions === 1, `${label} expected exactly one native session`);
  assert(stats.activeConnections === 0 || stats.activeConnections === 1, `${label} reported multiple native connections`);
}

function fileDiagnosticsQuiescent(stats: FileTransferDiagnostics | null): boolean {
  return stats === null || (
    stats.activeTransfers === 0
    && stats.queuedTransfers === 0
    && stats.incomingSessions === 0
    && stats.reservedSessions === 0
    && stats.activeLanes === 0
    && stats.activeOperations === 0
    && stats.ambiguousOperations === 0
    && stats.operationRecords === 0
    && stats.replayTombstones <= stats.maxReplayTombstones
  );
}

function assertFileDiagnosticsQuiescent(stats: FileTransferDiagnostics | null, label: string): void {
  assert(
    fileDiagnosticsQuiescent(stats),
    `${label} still owns file transfers, queues, sessions, lanes, or ambiguous operation records`
  );
}

function assertSchedulerQuiescent(stats: PeerDiagnostics['resources'] | null, label: string): void {
  if (!stats) return;
  assert(stats.queued === 0, `${label} scheduler still has queued work`);
  assert(stats.peers === 0 && stats.principals === 0, `${label} scheduler still owns peer/principal state`);
  assert(Object.values(stats.active).every((value) => value === 0), `${label} scheduler still owns active resources`);
  assert(!stats.closed, `${label} scheduler closed unexpectedly`);
}

function assertSharesQuiescent(stats: PeerDiagnostics['shares'] | null, label: string): void {
  if (!stats) return;
  assert(stats.activeShares === 0, `${label} still owns file capabilities`);
  assert(stats.operationRecords === 0, `${label} still owns capability operation records`);
  assert(stats.activeReservations === 0, `${label} still owns active capability reservations`);
  assert(stats.expiryRecords === 0, `${label} still owns capability expiry records`);
  assert(!stats.closed, `${label} share registry closed unexpectedly`);
}

function sameSchedulerGauges(
  baseline: PeerDiagnostics['resources'] | null,
  current: PeerDiagnostics['resources'] | null
): boolean {
  if (!baseline || !current) return baseline === current;
  return baseline.queued === current.queued
    && baseline.peers === current.peers
    && baseline.principals === current.principals
    && baseline.closed === current.closed
    && Object.entries(baseline.active).every(([name, value]) =>
      current.active[name as keyof typeof current.active] === value
    );
}

function assertSameSchedulerGauges(
  baseline: PeerDiagnostics['resources'] | null,
  current: PeerDiagnostics['resources'] | null,
  label: string
): void {
  assert(sameSchedulerGauges(baseline, current), `${label} scheduler resources did not return to baseline`);
}

function sameShareGauges(
  baseline: PeerDiagnostics['shares'] | null,
  current: PeerDiagnostics['shares'] | null
): boolean {
  if (!baseline || !current) return baseline === current;
  return baseline.activeShares === current.activeShares
    && baseline.operationRecords === current.operationRecords
    && baseline.activeReservations === current.activeReservations
    && baseline.expiryRecords === current.expiryRecords
    && baseline.maxShares === current.maxShares
    && baseline.maxOperationRecords === current.maxOperationRecords
    && baseline.closed === current.closed;
}

function assertSameShareGauges(
  baseline: PeerDiagnostics['shares'] | null,
  current: PeerDiagnostics['shares'] | null,
  label: string
): void {
  assert(sameShareGauges(baseline, current), `${label} capability registry did not return to baseline`);
}

function sameTaskGauges(
  baseline: PeerDiagnostics['tasks'] | null,
  current: PeerDiagnostics['tasks'] | null
): boolean {
  if (!baseline || !current) return baseline === current;
  return baseline.peer === current.peer && baseline.node === current.node;
}

function assertSameTaskGauges(
  baseline: PeerDiagnostics['tasks'] | null,
  current: PeerDiagnostics['tasks'] | null,
  label: string
): void {
  assert(sameTaskGauges(baseline, current), `${label} owned task counts did not return to baseline`);
}

function sameEndpointGauges(left: EndpointDiagnostics, right: EndpointDiagnostics): boolean {
  return left.activeReaders === right.activeReaders
    && left.activeWriters === right.activeWriters
    && left.activeSessions === right.activeSessions
    && left.totalHandles === right.totalHandles
    && left.poolSize === right.poolSize
    && left.activeConnections === right.activeConnections
    && left.activeRequests === right.activeRequests
    && left.activePathSubscriptions === right.activePathSubscriptions
    && left.activePathWatchers === right.activePathWatchers;
}

function assertNoNewErrorTerminals(
  baseline: StreamLifecycleStats | null,
  current: StreamLifecycleStats | null,
  label: string
): void {
  if (!baseline || !current) return;
  assert(current.sendReset === baseline.sendReset, `${label} reset a stream during successful transfers`);
  assert(current.recvStopped === baseline.recvStopped, `${label} stopped a stream during successful transfers`);
}

function assertExactSuccessfulStreamDeltas(
  baseline: ResourceSnapshot,
  current: ResourceSnapshot,
  records: readonly FileRecord[]
): void {
  const senderBefore = baseline.senderConnection.streams;
  const senderAfter = current.senderConnection.streams;
  const receiverBefore = baseline.receiverConnection.streams;
  const receiverAfter = current.receiverConnection.streams;
  if (!senderBefore || !senderAfter || !receiverBefore || !receiverAfter) return;
  const pushes = records.filter((record) => record.kind === 'push');
  const pulls = records.filter((record) => record.kind === 'pull');
  const pushDataStreams = dataStreamCount(pushes);
  const pullDataStreams = dataStreamCount(pulls);
  const files = records.length;
  assertStreamDelta(senderBefore, senderAfter, {
    openedBi: files,
    acceptedBi: 0,
    openedUni: pushDataStreams,
    acceptedUni: pullDataStreams,
    sendFinished: files + pushDataStreams,
    recvEof: files + pullDataStreams
  }, 'sender');
  assertStreamDelta(receiverBefore, receiverAfter, {
    openedBi: 0,
    acceptedBi: files,
    openedUni: pullDataStreams,
    acceptedUni: pushDataStreams,
    sendFinished: files + pullDataStreams,
    recvEof: files + pushDataStreams
  }, 'receiver');
}

function dataStreamCount(records: readonly FileRecord[]): number {
  return records.reduce((total, record) => total + Math.min(LANES, Math.ceil(record.size / CHUNK_SIZE)), 0);
}

function assertStreamDelta(
  before: StreamLifecycleStats,
  after: StreamLifecycleStats,
  expected: Pick<StreamLifecycleStats, 'openedBi' | 'acceptedBi' | 'openedUni' | 'acceptedUni' | 'sendFinished' | 'recvEof'>,
  label: string
): void {
  for (const key of ['openedBi', 'acceptedBi', 'openedUni', 'acceptedUni', 'sendFinished', 'recvEof'] as const) {
    assert(after[key] - before[key] === expected[key],
      `${label} ${key} delta was ${after[key] - before[key]}, expected ${expected[key]}`);
  }
}

function recordTransferId(context: HarnessContext, transferId: string): void {
  assert(!context.successfulTransferIds.has(transferId), `Duplicate successful transfer ID: ${transferId}`);
  context.successfulTransferIds.add(transferId);
}

function auditCounts(): AuditCounts {
  return {
    authenticated: 0,
    rejected: 0,
    allowedPush: 0,
    allowedPull: 0,
    allowedRpc: 0,
    denied: 0,
    sessionIds: new Set()
  };
}

function observeAudit(counts: AuditCounts, event: SecurityAuditEvent): void {
  if (event.type === 'session.authenticated') {
    counts.authenticated += 1;
    counts.sessionIds.add(event.sessionId);
    return;
  }
  if (event.type === 'session.rejected' || event.type === 'session.expired') {
    counts.rejected += 1;
    if ('sessionId' in event) counts.sessionIds.add(event.sessionId);
    return;
  }
  counts.sessionIds.add(event.sessionId);
  if (!event.allowed) {
    counts.denied += 1;
    return;
  }
  if (event.action.kind === 'file.push') counts.allowedPush += 1;
  else if (event.action.kind === 'file.pull') counts.allowedPull += 1;
  else if (event.action.kind === 'rpc') counts.allowedRpc += 1;
}

function assertNoUnexpectedSecurityEvents(sender: AuditCounts, receiver: AuditCounts): void {
  assert(sender.authenticated === 1 && receiver.authenticated === 1, 'Authentication event count was not exactly one per endpoint');
  assert(sender.rejected === 0 && receiver.rejected === 0, 'An authenticated session was rejected or expired');
  assert(sender.denied === 0 && receiver.denied === 0, 'A positive transfer authorization was denied');
}

function validateMetadata(value: unknown): StressFileMetadata {
  assert(typeof value === 'object' && value !== null && !Array.isArray(value), 'Stress file metadata is missing');
  const metadata = value as Record<string, unknown>;
  assert(
    metadata.kind === 'push' ||
    metadata.kind === 'pull' ||
    metadata.kind === 'rejected' ||
    metadata.kind === 'cancelled' ||
    metadata.kind === 'destination-failure',
    'Stress file metadata kind is invalid'
  );
  assert(Number.isSafeInteger(metadata.index), 'Stress file metadata index is invalid');
  assert(typeof metadata.sha256 === 'string' && /^[0-9a-f]{64}$/.test(metadata.sha256), 'Stress file metadata digest is invalid');
  return metadata as unknown as StressFileMetadata;
}

function failingDestination() {
  return {
    prepare: async () => new Set<number>(),
    writeChunk: async () => { throw new Error('Intentional destination failure'); },
    finalize: async () => { throw new Error('Intentional destination failure'); },
    abort: async () => undefined
  };
}

function slowDestination() {
  return {
    prepare: async () => new Set<number>(),
    writeChunk: async (_manifest: unknown, _index: number, _data: Uint8Array, signal?: AbortSignal) => {
      await delay(100, undefined, signal ? { signal } : undefined);
    },
    finalize: async (_manifest: unknown, context: { readonly markCommitted: () => void }) => {
      context.markCommitted();
    },
    abort: async () => undefined
  };
}

function assertManifest(record: FileRecord, manifest: { name: string; size: number; digest: string; metadata?: unknown }): void {
  assert(manifest.name === record.name, `${record.name} manifest name changed`);
  assert(manifest.size === record.size, `${record.name} manifest size changed`);
  assert(manifest.digest === record.blake3, `${record.name} manifest BLAKE3 digest changed`);
  const metadata = validateMetadata(manifest.metadata);
  assert(metadata.kind === record.kind && metadata.index === record.index && metadata.sha256 === record.sha256,
    `${record.name} manifest metadata changed`);
}

async function verifyDirectory(path: string, expectedFiles: number): Promise<void> {
  const entries = await readdir(path, { withFileTypes: true });
  assert(entries.length === expectedFiles, `${path} contains ${entries.length} entries, expected ${expectedFiles}`);
  assert(entries.every((entry) => entry.isFile() && !entry.name.includes('.p2prpc.')), `${path} contains transfer debris`);
}

async function assertNoTransferDebris(path: string): Promise<void> {
  const entries = await readdir(path, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = join(path, entry.name);
    if (entry.isDirectory()) {
      await assertNoTransferDebris(entryPath);
      continue;
    }
    assert(!entry.name.includes('.p2prpc.'), `Transfer debris remains at ${entryPath}`);
  }
}

async function sha256File(path: string): Promise<string> {
  const hasher = createHash('sha256');
  for await (const chunk of createReadStream(path)) hasher.update(chunk as Buffer);
  return hasher.digest('hex');
}

function sha256Bytes(value: Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}

function fingerprint(value: string): string {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

/** Full digest: release evidence must make relay-set collision substitution impractical. */
function relayFingerprint(value: string): string {
  return sha256Bytes(Buffer.from(value, 'utf8'));
}

function createRelayEvidenceTracker(
  options: Options,
  evidence: Evidence['relayEvidence']
): RelayEvidenceTracker {
  const configuredOrigins = new Set(options.relayUrls.map((value) => new URL(value).origin));
  const attempted = new Set(evidence.attempted);
  const connected = new Set(evidence.connected);
  const denied = new Set(evidence.denied);
  let dialing = false;
  const sync = (): void => {
    evidence.attempted = [...attempted].sort();
    evidence.connected = [...connected].sort();
    evidence.denied = [...denied].sort();
  };
  const allowRelayUrl = options.locator === 'dns' || options.relay === 'disabled'
    ? undefined
    : (origin: string): boolean => {
      const digest = relayFingerprint(origin);
      if (dialing) attempted.add(digest);
      const allowed = options.relay !== 'custom' || configuredOrigins.has(origin);
      if (!allowed) denied.add(digest);
      sync();
      return allowed;
    };
  return {
    ...(allowRelayUrl ? { allowRelayUrl } : {}),
    beginDial() { dialing = true; },
    endDial() { dialing = false; },
    observe(snapshot) {
      for (const stats of [snapshot.senderConnection, snapshot.receiverConnection]) {
        if (stats.relayUrlFingerprint) connected.add(stats.relayUrlFingerprint);
      }
      sync();
    }
  };
}

function absentOptionalPrincipal(id: string) {
  return { id, subject: id, issuer: null, clientId: null, tenantId: null } as const;
}

async function runBounded<T>(
  values: readonly T[],
  concurrency: number,
  operation: (value: T) => Promise<void>
): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.min(concurrency, values.length) }, async () => {
    while (next < values.length) {
      const index = next;
      next += 1;
      await operation(values[index]!);
    }
  });
  await Promise.all(workers);
}

function percentile(values: readonly number[], fraction: number): number {
  return values[Math.min(values.length - 1, Math.floor(values.length * fraction))] ?? 0;
}

function progressiveSlowdown(values: readonly number[]): number | null {
  if (values.length < 6) return null;
  const window = Math.max(2, Math.floor(values.length / 3));
  const first = median(values.slice(0, window));
  const last = median(values.slice(-window));
  return first === 0 ? null : last / first;
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle] ?? 0;
  return ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
}

function forceGc(): void {
  globalThis.gc?.();
  globalThis.gc?.();
}

async function settleRuntime(): Promise<void> {
  await delay(50);
}

function estimatedWorkspaceBytes(fileCount: number): number {
  let sourceBytes = 0;
  for (let index = 0; index < fileCount; index += 1) sourceBytes += fileSize(index);
  return sourceBytes * 2 + 256 * MIB;
}

function assertDiskCapacity(freeBytes: number | null, estimatedBytes: number): void {
  if (freeBytes === null) return;
  assert(freeBytes >= estimatedBytes, `Stress workspace needs about ${(estimatedBytes / MIB).toFixed(0)} MiB free`);
}

function isProductionProfile(options: Options): boolean {
  return options.fileCount === DEFAULT_FILE_COUNT
    && options.batchSize === DEFAULT_BATCH_SIZE
    && options.concurrency === DEFAULT_CONCURRENCY
    && options.errorCases === 50;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([promise, deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function serializeError(cause: unknown): NonNullable<Evidence['failure']> {
  if (!(cause instanceof Error)) return { name: 'Error', message: String(cause) };
  const code = 'code' in cause && typeof cause.code === 'string' ? cause.code : undefined;
  return {
    name: cause.name,
    message: cause.message,
    ...(code ? { code } : {}),
    ...(cause.stack ? { stack: cause.stack } : {})
  };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function canonicalRelayOrigin(value: string): string {
  assert(
    value.length > 0 &&
    value.length <= 2_048 &&
    value === value.trim() &&
    ![...value].some((character) => {
      const code = character.codePointAt(0)!;
      return code <= 0x1f || code === 0x7f;
    }),
    'Relay URLs must be bounded strings without surrounding whitespace or controls'
  );
  const originSyntax = /^https:\/\/([^/?#\\]+)\/?$/iu.exec(value);
  const authority = originSyntax?.[1];
  assert(
    authority !== undefined && !authority.includes('@') && !authority.endsWith(':'),
    'Relay URLs must use unambiguous credential-free HTTPS origin syntax'
  );
  const url = new URL(value);
  assert(
    url.protocol === 'https:' && !url.username && !url.password && url.port !== '0',
    'Relay URLs must be credential-free HTTPS origins with a nonzero port'
  );
  if (!url.hostname.startsWith('[') && url.hostname.endsWith('.')) {
    assert(!url.hostname.endsWith('..'), 'Relay DNS names may contain at most one trailing root dot');
    const hostname = url.hostname.slice(0, -1);
    assert(hostname.length > 0, 'Relay URL hostname is invalid');
    url.hostname = hostname;
    assert(url.hostname === hostname, 'Relay URL hostname could not be canonicalized');
  }
  return url.origin;
}

function parseArguments(argv: readonly string[]): Options | 'help' {
  const values: Record<string, string[]> = {};
  const flags = new Set<string>();
  const valueOptions = new Set([
    '--output',
    '--files',
    '--batch-size',
    '--concurrency',
    '--error-cases',
    '--locator',
    '--relay',
    '--relay-url',
    '--bind-address',
    '--dns-server-url',
    '--mdns-service-name',
    '--checkpoint-timeout-ms',
    '--max-rss-growth-mib',
    '--max-heap-growth-mib'
  ]);
  const flagOptions = new Set(['--execute', '--overwrite', '--keep-workdir', '--help', '-h']);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (flagOptions.has(argument)) {
      flags.add(argument);
      continue;
    }
    if (!valueOptions.has(argument)) throw new Error(`Unknown option: ${argument}`);
    const value = argv[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${argument} requires a value`);
    (values[argument] ??= []).push(value);
    index += 1;
  }
  if (flags.has('--help') || flags.has('-h')) return 'help';
  const output = one(values, '--output');
  if (!output) throw new Error('--output is required so partial and final JSON evidence has an explicit destination');
  const fileCount = integer(one(values, '--files') ?? String(DEFAULT_FILE_COUNT), '--files', 4, 100_000);
  assert(fileCount % 4 === 0, '--files must be divisible by four for the four exact phases');
  const batchSize = integer(one(values, '--batch-size') ?? String(DEFAULT_BATCH_SIZE), '--batch-size', 1, 10_000);
  const concurrency = integer(one(values, '--concurrency') ?? String(DEFAULT_CONCURRENCY), '--concurrency', 1, 256);
  const errorCases = integer(one(values, '--error-cases') ?? (fileCount === DEFAULT_FILE_COUNT ? '50' : '2'), '--error-cases', 0, 1000);
  const locatorValue = one(values, '--locator') ?? 'ticket';
  assert(locatorValue === 'ticket' || locatorValue === 'dns' || locatorValue === 'mdns', '--locator must be ticket, dns, or mdns');
  const relayValue = one(values, '--relay') ?? 'disabled';
  assert(relayValue === 'disabled' || relayValue === 'default' || relayValue === 'custom', '--relay must be disabled, default, or custom');
  const relayUrls = (values['--relay-url'] ?? []).map(canonicalRelayOrigin);
  assert((relayValue === 'custom') === (relayUrls.length > 0), 'Custom relay mode requires --relay-url; other modes reject it');
  assert(relayUrls.length <= 32, 'At most 32 custom relay origins may be supplied');
  assert(new Set(relayUrls).size === relayUrls.length, 'Custom relay URLs must be distinct canonical HTTPS origins');
  assert(
    locatorValue !== 'dns' || relayValue !== 'custom',
    'DNS/PKARR with custom relays is unavailable until resolved routes can be filtered before dial'
  );
  const dnsServerUrl = one(values, '--dns-server-url');
  assert(dnsServerUrl === undefined || locatorValue === 'dns', '--dns-server-url requires --locator dns');
  if (dnsServerUrl) {
    const parsedDns = new URL(dnsServerUrl);
    assert(
      parsedDns.protocol === 'https:' && !parsedDns.username && !parsedDns.password && !parsedDns.hash,
      '--dns-server-url must be a credential-free HTTPS URL without a fragment'
    );
  }
  const mdnsServiceName = one(values, '--mdns-service-name') ?? `p2prpc-stress-${process.pid}`;
  assert(/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(mdnsServiceName), 'mDNS service name is invalid');
  const bindAddresses = values['--bind-address'] ?? [];
  assert(bindAddresses.length <= 16, 'At most 16 --bind-address values may be supplied');
  for (const bindAddress of bindAddresses) {
    assert(
      /^(?:\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}|\[[0-9A-Fa-f:]+\]:\d{1,5})$/.test(bindAddress),
      '--bind-address must be an IPv4:port or [IPv6]:port socket address'
    );
  }
  const checkpointTimeoutMs = integer(one(values, '--checkpoint-timeout-ms') ?? '5000', '--checkpoint-timeout-ms', 1000, 60_000);
  const maxRssGrowthBytes = integer(one(values, '--max-rss-growth-mib') ?? '256', '--max-rss-growth-mib', 1, 16_384) * MIB;
  const maxHeapGrowthBytes = integer(one(values, '--max-heap-growth-mib') ?? '64', '--max-heap-growth-mib', 1, 4096) * MIB;
  const absoluteOutput = isAbsolute(output) ? output : resolve(output);
  return {
    execute: flags.has('--execute'),
    output: absoluteOutput,
    overwrite: flags.has('--overwrite'),
    fileCount,
    batchSize,
    concurrency,
    errorCases,
    locator: locatorValue,
    relay: relayValue,
    relayUrls,
    bindAddresses,
    ...(dnsServerUrl ? { dnsServerUrl } : {}),
    mdnsServiceName,
    checkpointTimeoutMs,
    maxRssGrowthBytes,
    maxHeapGrowthBytes,
    keepWorkdir: flags.has('--keep-workdir')
  };
}

function one(values: Readonly<Record<string, readonly string[]>>, option: string): string | undefined {
  const entries = values[option];
  if (!entries) return undefined;
  if (entries.length !== 1) throw new Error(`${option} may be supplied only once`);
  return entries[0];
}

function integer(value: string, option: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  assert(Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum,
    `${option} must be an integer between ${minimum} and ${maximum}`);
  return parsed;
}

function printHelp(): void {
  process.stdout.write(`p2prpc native single-connection file-stream lifecycle gate

Usage:
  npm run stress:files -- --execute --output benchmark-results/files-10000.json [options]

The production profile sends exactly 5,000 pushes and 5,000 peer/principal-bound
capability pulls over one mutually authenticated QUIC connection. Each direction
uses 2,500 sequential transfers and 2,500 transfers at concurrency 16. The test
checkpoints stream/native/process resources every 100 files and atomically updates
machine-readable evidence after every checkpoint.

Execution guard:
  --execute                         Confirm this heavy native run (or set P2PRPC_RUN_NATIVE_STRESS=1)
  --output <path>                   Required JSON evidence path
  --overwrite                       Explicitly replace an existing evidence file

Workload:
  --files <n>                       Successful files, divisible by 4 (default: 10000)
  --batch-size <n>                  Resource checkpoint batch (default: 100)
  --concurrency <n>                 Concurrent phase width (default: 16)
  --error-cases <n>                 Each cleanup failure class (default: 50; reduced runs: 2)
  --checkpoint-timeout-ms <n>       Quiescence deadline (default: 5000)
  --max-rss-growth-mib <n>          Final RSS allowance (default: 256)
  --max-heap-growth-mib <n>         Final heap allowance (default: 64)

Iroh lab topology:
  --locator ticket|dns|mdns         Route discovery mode (default: ticket)
  --relay disabled|default|custom   Relay policy (default: disabled)
  --relay-url <https-url>           Repeat for custom relay failover candidates
  --bind-address <address>          Repeat for explicit IPv4/IPv6 bind candidates
  --dns-server-url <https-url>      Controlled DNS/PKARR server
  --mdns-service-name <name>        Isolated LAN discovery service

Diagnostics:
  --keep-workdir                    Preserve generated real files for inspection
  --help                            Show this help without executing anything

Use --files 4 --batch-size 1 for a quick harness smoke. Such a run is explicitly
marked non-production in its evidence. A relay-disabled run must be paired with
two-host topology evidence proving non-loopback direct paths and no relay use.
`);
}
