import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { P2PError, asP2PError } from '../errors.js';
import {
  DEFAULT_FRAME_LIMITS,
  StreamKind,
  TransferFrameKind,
  readFrame,
  writeFrame,
  writeStreamKind,
  type Frame,
  type FrameLimits
} from '../protocol.js';
import type { QuicBiStream, QuicConnection, QuicRecvStream, QuicSendStream } from '../transport/types.js';
import type { SessionPrincipal } from '../security/types.js';
import { sanitizeBoundedDisplayText } from '../text.js';
import { chunkDigest, createManifest } from './fs.js';
import { capabilityId, type ShareRegistry, type ShareReservation } from './share.js';
import { Transfer } from './transfer.js';
import type {
  DownloadFileOptions,
  FileDestination,
  FileManifest,
  FileOffer,
  FileSource,
  IncomingFileHandler,
  SendFileOptions,
  TransferProgress,
  TransferResult
} from './types.js';
import {
  expectedChunkSize,
  isRecord,
  resolveFileTransferLimits,
  validateChunkSize,
  validateDigest,
  validateManifest,
  validateTransferId,
  type FileTransferLimits
} from './validation.js';

interface IncomingSession<TMetadata> {
  readonly manifest: FileManifest<TMetadata>;
  readonly destination: FileDestination<TMetadata>;
  readonly missing: Set<number>;
  readonly inFlight: Set<number>;
  readonly claimedLanes: Set<number>;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly allowedLanes: number;
  readonly totalMissing: number;
  readonly resumed: boolean;
  readonly context: FileTransferConnectionContext;
  readonly controller: AbortController;
  readonly signal: AbortSignal;
  readonly receivers: Set<QuicRecvStream>;
  readonly done: Promise<void>;
  announcedChunks: number;
  /** Register a lane handler so destination teardown cannot race its callbacks. */
  beginLane(): () => void;
  /** Resolves only after every registered lane handler has settled. */
  lanesDrained(): Promise<void>;
  resolve(): void;
  reject(error: unknown): void;
  dispose(): void;
}

interface TransferAccept {
  readonly transferId: string;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly missingRanges: Array<readonly [start: number, endExclusive: number]>;
  readonly missingCount: number;
  readonly lanes: number;
}

interface TransferPull {
  readonly token: string;
  readonly requestId: string;
  readonly options?: { readonly chunkSize?: number; readonly lanes?: number };
}

interface LaneHeader {
  readonly transferId: string;
  readonly attemptId: string;
  readonly laneToken: string;
  readonly laneId: number;
  readonly count: number;
}

interface ChunkHeader {
  readonly index: number;
  readonly size: number;
  readonly digest: string;
}

interface CompletionFrame {
  readonly transferId: string;
  readonly attemptId: string;
}

const DATA_SEGMENT_BYTES = 64 * 1024;

export interface TransferManagerOptions<TMetadata = unknown> {
  readonly peerId: string;
  readonly connection: () => Promise<FileTransferConnectionContext>;
  readonly incoming?: IncomingFileHandler<TMetadata>;
  readonly shares: ShareRegistry<TMetadata>;
  /** Required application authorization after strict parsing and before any file or capability access. */
  readonly authorize: (
    action: FileTransferAuthorization<TMetadata>,
    security: FileTransferSecurityContext,
    signal: AbortSignal
  ) => Promise<void> | void;
  readonly limits?: Partial<FileTransferLimits>;
  readonly frameLimits?: FrameLimits;
  readonly idleTimeoutMs?: number;
  readonly onProgress?: (progress: TransferProgress) => void;
}

export type FileTransferAuthorization<TMetadata = unknown> =
  | { readonly kind: 'file.push'; readonly manifest: FileManifest<TMetadata> }
  | { readonly kind: 'file.pull'; readonly capabilityId: string };

export interface FileTransferSecurityContext {
  readonly principal: SessionPrincipal;
  readonly sessionId: string;
}

/** Exact authenticated physical connection on which file streams are valid. */
export interface FileTransferConnectionContext {
  readonly connection: QuicConnection;
  readonly security: FileTransferSecurityContext;
  /** Aborts on connection close/replacement, session expiry, or node shutdown. */
  readonly signal: AbortSignal;
}

export interface FileTransferDiagnostics {
  readonly activeTransfers: number;
  readonly queuedTransfers: number;
  readonly incomingSessions: number;
  readonly reservedSessions: number;
  readonly activeLanes: number;
}

export class TransferManager<TMetadata = unknown> {
  private readonly sessions = new Map<string, IncomingSession<TMetadata>>();
  private readonly reservedSessionIds = new Set<string>();
  private readonly lifetimeController = new AbortController();
  private readonly limits: FileTransferLimits;
  private readonly idleTimeoutMs: number;
  private activeTransfers = 0;
  private readonly transferWaiters: Array<() => void> = [];

  constructor(private readonly options: TransferManagerOptions<TMetadata>) {
    this.limits = resolveFileTransferLimits(options.limits);
    this.idleTimeoutMs = options.idleTimeoutMs ?? 30_000;
    if (!Number.isSafeInteger(this.idleTimeoutMs) || this.idleTimeoutMs < 1_000 || this.idleTimeoutMs > 10 * 60_000) {
      throw new P2PError('RESOURCE_LIMIT', 'Invalid file stream idle timeout');
    }
  }

  diagnostics(): FileTransferDiagnostics {
    let activeLanes = 0;
    for (const session of this.sessions.values()) activeLanes += session.receivers.size;
    return Object.freeze({
      activeTransfers: this.activeTransfers,
      queuedTransfers: this.transferWaiters.length,
      incomingSessions: this.sessions.size,
      reservedSessions: this.reservedSessionIds.size,
      activeLanes
    });
  }

  /** Permanently abort active, queued, and retrying work for this peer runtime. */
  close(reason: unknown = new P2PError('DISCONNECTED', 'Peer file manager closed')): void {
    if (!this.lifetimeController.signal.aborted) this.lifetimeController.abort(reason);
  }

  async sendFile(source: FileSource<TMetadata>, options: SendFileOptions = {}): Promise<Transfer<TMetadata>> {
    const linked = combinedController([
      this.lifetimeController.signal,
      ...(options.signal ? [options.signal] : [])
    ]);
    const controller = linked.controller;
    let release: (() => void) | undefined;
    let chunkSize: number;
    let manifest: FileManifest<TMetadata>;
    try {
      throwIfCancelled(controller.signal);
      release = await this.acquireTransferSlot(controller.signal);
      chunkSize = validateChunkSize(options.chunkSize ?? this.limits.chunkSize, this.limits.maxChunkSize);
      manifest = await createManifest(source, {
        chunkSize,
        ...(options.transferId ? { transferId: options.transferId } : {}),
        limits: this.limits,
        signal: controller.signal,
        readTimeoutMs: this.idleTimeoutMs
      });
    } catch (cause) {
      release?.();
      linked.dispose();
      throw cause;
    }
    const transferRef: { current?: Transfer<TMetadata> } = {};
    const transfer = new Transfer(manifest, controller, async () => {
      try {
        return await this.retryFiles(
          controller.signal,
          () => this.sendAttempt(source, manifest, options, transferRef.current, controller.signal)
        );
      } finally {
        release!();
        linked.dispose();
      }
    });
    transferRef.current = transfer;
    if (options.onProgress) transfer.onProgress(options.onProgress);
    return transfer;
  }

  async download(
    token: string,
    destination: FileDestination<TMetadata>,
    options: DownloadFileOptions = {}
  ): Promise<Transfer<TMetadata>> {
    const linked = combinedController([
      this.lifetimeController.signal,
      ...(options.signal ? [options.signal] : [])
    ]);
    const controller = linked.controller;
    let release: (() => void) | undefined;
    const requestId = randomTransferId();
    let initial: {
      stream: QuicBiStream;
      manifest: FileManifest<TMetadata>;
      context: FileTransferConnectionContext;
    };
    try {
      throwIfCancelled(controller.signal);
      release = await this.acquireTransferSlot(controller.signal);
      initial = await this.retryFiles(
        controller.signal,
        () => this.openPull(token, requestId, options, controller.signal)
      );
    } catch (cause) {
      release?.();
      linked.dispose();
      throw cause;
    }
    const manifest = initial.manifest;
    let first: QuicBiStream | undefined = initial.stream;
    let firstContext: FileTransferConnectionContext | undefined = initial.context;
    const transferRef: { current?: Transfer<TMetadata> } = {};
    const transfer = new Transfer(manifest, controller, async () => {
      try {
        return await this.retryFiles(controller.signal, async () => {
          const opened = first
            ? { stream: first, manifest, context: firstContext! }
            : await this.openPull(token, requestId, options, controller.signal);
          first = undefined;
          firstContext = undefined;
          try {
            assertSameManifest(manifest, opened.manifest);
          } catch (cause) {
            const drained = await this.abortBiStream(opened.stream);
            if (!drained) throw cleanupFailed(cause);
            throw cause;
          }
          return this.receiveAttempt(
            opened.stream,
            manifest,
            destination,
            transferRef.current,
            opened.context,
            controller.signal
          );
        });
      } finally {
        release!();
        linked.dispose();
      }
    });
    transferRef.current = transfer;
    if (options.onProgress) transfer.onProgress(options.onProgress);
    return transfer;
  }

  async handleControl(stream: QuicBiStream, context: FileTransferConnectionContext): Promise<void> {
    const attempt = combinedController([this.lifetimeController.signal, context.signal]);
    let release: (() => void) | undefined;
    let reservation: ShareReservation<TMetadata> | undefined;
    let reservationAttempt: ReturnType<typeof combinedController> | undefined;
    let reservationSettled = false;
    const completeReservation = (): void => {
      if (!reservation || reservationSettled) return;
      reservationSettled = true;
      reservation.complete();
    };
    try {
      release = await this.acquireTransferSlot(attempt.controller.signal);
      await this.networkOperation(
        () => stream.send.setPriority(50),
        attempt.controller.signal,
        'File control priority timed out'
      );
      const first = await this.readControlFrame(stream.recv, attempt.controller.signal);
      if (first.kind === TransferFrameKind.Offer) {
        const manifest = validateManifest<TMetadata>(first.value, this.limits);
        await this.localOperation(
          (signal) => Promise.resolve(this.options.authorize(
            { kind: 'file.push', manifest },
            context.security,
            signal
          )),
          attempt.controller.signal,
          'File authorization timed out'
        );
        const destination = await this.offerDestination(manifest, context.security, attempt.controller.signal);
        await this.receiveAttempt(
          stream,
          manifest,
          destination,
          undefined,
          context,
          attempt.controller.signal
        );
      } else if (first.kind === TransferFrameKind.Pull) {
        const pull = validatePull(first.value, this.limits);
        await this.localOperation(
          (signal) => Promise.resolve(this.options.authorize(
            { kind: 'file.pull', capabilityId: capabilityId(pull.token) },
            context.security,
            signal
          )),
          attempt.controller.signal,
          'File authorization timed out'
        );
        const chunkSize = validateChunkSize(
          pull.options?.chunkSize ?? this.limits.chunkSize,
          this.limits.maxChunkSize
        );
        const lanes = validateLaneCount(pull.options?.lanes ?? this.limits.lanes, this.limits);
        reservation = this.options.shares.reserve(pull.token, {
          peerId: this.options.peerId,
          principalId: context.security.principal.id,
          subject: context.security.principal.subject,
          ...(context.security.principal.issuer !== undefined
            ? { issuer: context.security.principal.issuer }
            : {}),
          ...(context.security.principal.clientId !== undefined
            ? { clientId: context.security.principal.clientId }
            : {}),
          ...(context.security.principal.tenantId !== undefined
            ? { tenantId: context.security.principal.tenantId }
            : {}),
          fingerprint: `v2:${chunkSize}:${lanes}`,
          operationId: pull.requestId
        });
        reservationAttempt = combinedController([attempt.controller.signal, reservation.signal]);
        const reservationSignal = reservationAttempt.controller.signal;
        const manifest = await createManifest(reservation.source, {
          chunkSize,
          transferId: pull.requestId,
          limits: this.limits,
          signal: reservationSignal,
          readTimeoutMs: this.idleTimeoutMs
        });
        await this.writeControlFrame(
          stream.send,
          TransferFrameKind.Offer,
          manifest,
          reservationSignal
        );
        await this.senderFlow(
          stream,
          reservation.source,
          manifest,
          lanes,
          undefined,
          context,
          reservationSignal,
          completeReservation
        );
        completeReservation();
      } else {
        throw new P2PError('INVALID_FRAME', 'Unexpected transfer control frame');
      }
    } catch (cause) {
      const error = asP2PError(cause);
      const drained = cause instanceof DrainedTransferError
        ? true
        : error.code === 'DISCONNECTED'
          ? await this.abortBiStream(stream)
          : await this.rejectControlStream(stream, error);
      if (reservation && !reservationSettled) {
        reservationSettled = true;
        if (error.code === 'DISCONNECTED' && drained) reservation.release();
        else reservation.complete();
      }
      if (!drained) throw cleanupFailed(error);
      throw error;
    } finally {
      release?.();
      reservationAttempt?.dispose();
      attempt.dispose();
    }
  }

  async handleData(recv: QuicRecvStream, context: FileTransferConnectionContext): Promise<void> {
    let session: IncomingSession<TMetadata> | undefined;
    let claimed = false;
    let releaseLane: (() => void) | undefined;
    try {
      const first = await this.readControlFrame(recv, context.signal);
      if (first.kind !== TransferFrameKind.Accept) throw new P2PError('INVALID_FRAME', 'Missing lane header');
      const header = validateLaneHeader(first.value, this.limits);
      const candidate = this.sessions.get(header.transferId);
      if (
        !candidate ||
        candidate.context !== context ||
        candidate.attemptId !== header.attemptId ||
        candidate.laneToken !== header.laneToken
      ) {
        throw new P2PError('NOT_FOUND', 'Transfer lane is stale or inactive');
      }
      if (header.laneId >= candidate.allowedLanes || candidate.claimedLanes.has(header.laneId)) {
        throw new P2PError('INVALID_FRAME', 'Transfer lane is duplicate or outside the negotiated range');
      }
      if (candidate.announcedChunks + header.count > candidate.totalMissing) {
        throw new P2PError('RESOURCE_LIMIT', 'Transfer lanes announced too many chunks');
      }
      throwIfCancelled(candidate.signal);
      candidate.claimedLanes.add(header.laneId);
      candidate.announcedChunks += header.count;
      candidate.receivers.add(recv);
      releaseLane = candidate.beginLane();
      session = candidate;
      claimed = true;

      for (let position = 0; position < header.count; position += 1) {
        const frame = await this.readControlFrame(recv, session.signal);
        if (frame.kind !== TransferFrameKind.ChunkHeader) throw new P2PError('INVALID_FRAME', 'Missing chunk header');
        const chunk = validateChunkHeader(frame.value, session.manifest);
        if (!session.missing.has(chunk.index) || session.inFlight.has(chunk.index)) {
          throw new P2PError('INVALID_FRAME', `Unexpected or duplicate chunk ${chunk.index}`);
        }
        session.inFlight.add(chunk.index);
        try {
          const data = await this.readChunkBody(recv, chunk.size, session.signal);
          if (chunkDigest(data) !== chunk.digest) throw new P2PError('INTEGRITY_FAILED', `Chunk ${chunk.index} failed verification`);
          await this.localOperation(
            (operationSignal) => session!.destination.writeChunk(
              session!.manifest,
              chunk.index,
              data,
              operationSignal
            ),
            session.signal,
            'File destination write timed out'
          );
          session.missing.delete(chunk.index);
        } finally {
          session.inFlight.delete(chunk.index);
        }
        this.emitProgress(session.manifest, session.manifest.chunkCount - session.missing.size, 'receive', undefined);
      }
      await this.expectRecvEnd(recv, session.signal);
    } catch (cause) {
      const error = asP2PError(cause);
      if (claimed && session) {
        // This handler owns cleanup for its receive half. Remove it before
        // aborting the attempt so the control-flow cleanup cannot stop the
        // same lane concurrently.
        session.receivers.delete(recv);
        session.reject(error);
      }
      const drained = await this.abortRecvStream(recv);
      if (!drained) throw cleanupFailed(error);
      throw error;
    } finally {
      session?.receivers.delete(recv);
      releaseLane?.();
    }
  }

  private async sendAttempt(
    source: FileSource<TMetadata>,
    manifest: FileManifest<TMetadata>,
    options: SendFileOptions,
    transfer: Transfer<TMetadata> | undefined,
    signal: AbortSignal
  ): Promise<TransferResult<TMetadata>> {
    const context = await this.getConnection(signal);
    const attempt = combinedController([signal, context.signal]);
    let stream: QuicBiStream | undefined;
    try {
      const opened = await this.openBiStream(context.connection, attempt.controller.signal);
      stream = opened;
      await this.networkOperation(() => opened.send.setPriority(50), attempt.controller.signal, 'File control priority timed out');
      await this.writeKind(opened.send, StreamKind.TransferControl, attempt.controller.signal);
      await this.writeControlFrame(opened.send, TransferFrameKind.Offer, manifest, attempt.controller.signal);
      return await this.senderFlow(
        opened,
        source,
        manifest,
        options.lanes,
        transfer,
        context,
        attempt.controller.signal
      );
    } catch (cause) {
      if (cause instanceof DrainedTransferError) throw cause;
      if (!stream) throw cause;
      const drained = await this.abortBiStream(stream);
      if (!drained) throw cleanupFailed(cause);
      throw cause;
    } finally {
      attempt.dispose();
    }
  }

  private async senderFlow(
    stream: QuicBiStream,
    source: FileSource<TMetadata>,
    manifest: FileManifest<TMetadata>,
    requestedLanes: number | undefined,
    transfer: Transfer<TMetadata> | undefined,
    context: FileTransferConnectionContext,
    signal: AbortSignal,
    onAcknowledged?: () => void
  ): Promise<TransferResult<TMetadata>> {
    const startedAt = Date.now();
    const attempt = childController(signal);
    const activeSends = new Set<QuicSendStream>();
    const laneTasks: Array<Promise<void>> = [];
    try {
      const response = await this.readControlFrame(stream.recv, attempt.controller.signal);
      if (response.kind === TransferFrameKind.Reject) throw new P2PError('REJECTED', readReason(response.value));
      if (response.kind !== TransferFrameKind.Accept) throw new P2PError('INVALID_FRAME', 'Transfer was not accepted');
      const accept = validateAccept(response.value, manifest, this.limits);
      const missing = expandRanges(accept.missingRanges, manifest.chunkCount, accept.missingCount);
      const preferredLanes = requestedLanes === undefined
        ? accept.lanes
        : Math.min(validateLaneCount(requestedLanes, this.limits), accept.lanes);
      const lanes = clampLanes(preferredLanes, this.limits.maxLanes, Math.max(1, missing.length));
      const assignments = Array.from({ length: lanes }, () => [] as number[]);
      missing.forEach((index, position) => assignments[position % lanes]?.push(index));
      let sentChunks = manifest.chunkCount - missing.length;
      // The receiver may reject an accepted transfer later (for example, a
      // destination write can fail). Listen while lanes are active so its
      // explicit terminal frame wins over secondary STOP_SENDING write errors.
      // A transfer may legitimately run much longer than one idle interval.
      // Keep the control read cancellable, but start an idle deadline only if
      // a failed lane makes us wait for the receiver's terminal decision.
      const terminalOutcome = this.readControlFrameUntilCancelled(stream.recv, attempt.controller.signal).then(
        (frame) => ({ kind: 'frame' as const, frame }),
        (error: unknown) => ({ kind: 'error' as const, error })
      );

      for (const [laneId, indexes] of assignments.entries()) {
        if (indexes.length === 0) continue;
        laneTasks.push((async () => {
          const send = await this.openUniStream(context.connection, attempt.controller.signal);
          activeSends.add(send);
          let finished = false;
          try {
            await this.networkOperation(() => send.setPriority(-10), attempt.controller.signal, 'File lane priority timed out');
            await this.writeKind(send, StreamKind.TransferData, attempt.controller.signal);
            await this.writeControlFrame(send, TransferFrameKind.Accept, {
              transferId: manifest.transferId,
              attemptId: accept.attemptId,
              laneToken: accept.laneToken,
              laneId,
              count: indexes.length
            } satisfies LaneHeader, attempt.controller.signal);
            for (const index of indexes) {
              const data = await this.localOperation(
                (operationSignal) => source.readChunk(index, manifest.chunkSize, operationSignal),
                attempt.controller.signal,
                'File source read timed out'
              );
              const expected = expectedChunkSize(manifest, index);
              if (data.byteLength !== expected) {
                throw new P2PError('INTEGRITY_FAILED', `Source returned an invalid chunk ${index}`);
              }
              await this.writeControlFrame(send, TransferFrameKind.ChunkHeader, {
                index,
                size: expected,
                digest: chunkDigest(data)
              } satisfies ChunkHeader, attempt.controller.signal);
              await this.writeChunkBody(send, data, attempt.controller.signal);
              sentChunks += 1;
              this.emitProgress(manifest, sentChunks, 'send', transfer);
            }
            await this.finishSendStream(send, attempt.controller.signal);
            finished = true;
          } finally {
            if (finished) activeSends.delete(send);
          }
        })());
      }
      const lanesOutcome = Promise.all(laneTasks).then(
        () => ({ kind: 'lanes' as const }),
        (error: unknown) => ({ kind: 'lane-error' as const, error })
      );
      const firstFinished = await Promise.race([lanesOutcome, terminalOutcome]);
      if (firstFinished.kind === 'frame') {
        if (firstFinished.frame.kind === TransferFrameKind.Reject) {
          throw new P2PError('REJECTED', readReason(firstFinished.frame.value));
        }
        throw new P2PError('INVALID_FRAME', 'Receiver completed before all file lanes settled');
      }
      if (firstFinished.kind === 'error') throw firstFinished.error;
      if (firstFinished.kind === 'lane-error') {
        // The receiver writes and finishes Reject before stopping its lane
        // readers, but QUIC streams are independently scheduled. Apply the
        // configured idle deadline now and wait for the authoritative control
        // outcome instead of guessing after a shorter grace period and
        // accidentally retrying side-effecting destination work.
        const peerTerminal = await withDeadline(
          terminalOutcome,
          this.idleTimeoutMs,
          'Peer transfer terminal frame timed out'
        ).catch(() => undefined);
        if (peerTerminal?.kind === 'frame' && peerTerminal.frame.kind === TransferFrameKind.Reject) {
          throw new P2PError('REJECTED', readReason(peerTerminal.frame.value));
        }
        if (peerTerminal?.kind === 'frame') {
          throw new P2PError('INVALID_FRAME', 'Receiver completed after a failed file lane');
        }
        throw firstFinished.error;
      }

      const completion: CompletionFrame = { transferId: manifest.transferId, attemptId: accept.attemptId };
      await this.writeControlFrame(stream.send, TransferFrameKind.Complete, completion, attempt.controller.signal);
      // This is the sender's final control message. Half-close before waiting
      // for the receiver's acknowledgement so the receiver can prove that the
      // request contains no trailing frames.
      await this.finishSendStream(stream.send, attempt.controller.signal);
      const terminal = await withDeadline(
        terminalOutcome,
        this.idleTimeoutMs,
        'Peer transfer acknowledgement timed out'
      );
      if (terminal.kind === 'error') throw terminal.error;
      const complete = terminal.frame;
      if (complete.kind === TransferFrameKind.Reject) {
        throw new P2PError('REJECTED', readReason(complete.value));
      }
      if (complete.kind !== TransferFrameKind.Complete || !matchesCompletion(complete.value, completion)) {
        throw new P2PError('INTEGRITY_FAILED', 'Receiver did not verify this transfer attempt');
      }
      await this.expectRecvEnd(stream.recv, attempt.controller.signal);
      onAcknowledged?.();
      return { manifest, resumed: missing.length < manifest.chunkCount, durationMs: Date.now() - startedAt };
    } catch (cause) {
      attempt.controller.abort(cause);
      const [lanesSettled, sendsDrained, controlDrained] = await Promise.all([
        this.settleTasks(laneTasks),
        this.abortSendStreams(activeSends),
        this.abortBiStream(stream)
      ]);
      if (!lanesSettled || !sendsDrained || !controlDrained) throw cleanupFailed(cause);
      throw drainedTransferError(cause);
    } finally {
      attempt.dispose();
    }
  }

  private async receiveAttempt(
    stream: QuicBiStream,
    manifest: FileManifest<TMetadata>,
    destination: FileDestination<TMetadata>,
    transfer: Transfer<TMetadata> | undefined,
    context: FileTransferConnectionContext,
    signal: AbortSignal
  ): Promise<TransferResult<TMetadata>> {
    const startedAt = Date.now();
    const attempt = combinedController([signal, context.signal]);
    let ownsReservation = false;
    let destinationPrepared = false;
    let session: IncomingSession<TMetadata> | undefined;
    try {
      throwIfCancelled(attempt.controller.signal);
      if (this.sessions.has(manifest.transferId) || this.reservedSessionIds.has(manifest.transferId)) {
        throw new P2PError('REJECTED', 'A transfer with this ID is already active');
      }
      this.reservedSessionIds.add(manifest.transferId);
      ownsReservation = true;
      const completed = await this.localOperation(
        (operationSignal) => destination.prepare(manifest, operationSignal),
        attempt.controller.signal,
        'File destination preparation timed out'
      );
      destinationPrepared = true;
      if (completed.size > manifest.chunkCount) throw new P2PError('INVALID_FRAME', 'Destination returned too many completed chunks');
      for (const index of completed) {
        if (!Number.isSafeInteger(index) || index < 0 || index >= manifest.chunkCount) {
          throw new P2PError('INVALID_FRAME', 'Destination returned an invalid completed chunk');
        }
      }
      const missing = new Set<number>();
      for (let index = 0; index < manifest.chunkCount; index += 1) {
        if (!completed.has(index)) missing.add(index);
      }
      const allowedLanes = clampLanes(this.limits.lanes, this.limits.maxLanes, Math.max(1, missing.size));
      session = createSession(
        manifest,
        destination,
        missing,
        completed.size > 0,
        allowedLanes,
        context,
        attempt.controller.signal
      );
      if (this.sessions.has(manifest.transferId)) throw new P2PError('REJECTED', 'A transfer with this ID is already active');
      this.sessions.set(manifest.transferId, session);
      this.reservedSessionIds.delete(manifest.transferId);
      ownsReservation = false;
      const missingRanges = compressRanges(missing, this.limits.maxMissingRanges);
      const acceptance: TransferAccept = {
        transferId: manifest.transferId,
        attemptId: session.attemptId,
        laneToken: session.laneToken,
        missingRanges,
        missingCount: missing.size,
        lanes: allowedLanes
      };
      await this.writeControlFrame(stream.send, TransferFrameKind.Accept, acceptance, session.signal);
      if (missing.size === 0) session.resolve();
      const completionPromise = this.readControlFrame(stream.recv, session.signal);
      const firstFinished = await Promise.race([
        completionPromise.then((completion) => ({ kind: 'completion' as const, completion })),
        session.done.then(() => ({ kind: 'data' as const }))
      ]);
      const completion = firstFinished.kind === 'completion'
        ? firstFinished.completion
        : await completionPromise;
      if (completion.kind !== TransferFrameKind.Complete || !matchesCompletion(completion.value, acceptance)) {
        throw new P2PError('INVALID_FRAME', 'Sender completed a different transfer attempt');
      }
      await this.expectRecvEnd(stream.recv, session.signal);
      // QUIC does not order independent data lanes against this control stream,
      // so a valid completion frame may arrive while previously written lane
      // bytes are still in flight. Bound that wait instead of rejecting it.
      await this.localOperation(() => session!.done, session.signal, 'File data lanes timed out');
      if (session.missing.size !== 0) throw new P2PError('INVALID_FRAME', 'Sender completed before all chunks arrived');
      // A lane is complete only after its final chunk and clean FIN have both
      // been consumed. Do not finalize durable state or acknowledge the
      // transfer while a lane handler still owns a receive stream.
      await this.localOperation(() => session!.lanesDrained(), session.signal, 'File data lanes timed out');
      await this.localOperation(
        (operationSignal) => destination.finalize(manifest, operationSignal),
        session.signal,
        'File destination finalization timed out'
      );
      await this.writeControlFrame(stream.send, TransferFrameKind.Complete, {
        transferId: manifest.transferId,
        attemptId: session.attemptId
      } satisfies CompletionFrame, session.signal);
      await this.finishSendStream(stream.send, session.signal);
      this.emitProgress(manifest, manifest.chunkCount, 'receive', transfer);
      return { manifest, resumed: session.resumed, durationMs: Date.now() - startedAt };
    } catch (cause) {
      const error = asP2PError(cause);
      if (ownsReservation) this.reservedSessionIds.delete(manifest.transferId);
      if (session && this.sessions.get(manifest.transferId) === session) this.sessions.delete(manifest.transferId);
      // Tell the sender why this attempt is terminal while the control send
      // half is still usable. Stopping data lanes first can make their writers
      // fail with DISCONNECTED, which looks retryable and can eventually poison
      // an otherwise healthy long-lived session.
      const controlDrained = await this.rejectControlStream(stream, error);
      session?.controller.abort(error);
      session?.reject(error);
      const receiversDrained = session ? await this.abortRecvStreams(session.receivers) : true;
      // writeChunk() is a side-effecting custom-adapter callback. It may still
      // be cooperatively settling after its lane stream is stopped, so wait for
      // every claimed lane handler before invoking destination.abort() or
      // allowing a retry to prepare the same destination.
      if (session) await session.lanesDrained();
      if (destinationPrepared) {
        await this.localOperation(
          (operationSignal) => destination.abort(
            manifest,
            { discard: error.code === 'INTEGRITY_FAILED' || error.code === 'INVALID_FRAME' },
            operationSignal
          ),
          undefined,
          'File destination cleanup timed out'
        ).catch(() => undefined);
      }
      if (!receiversDrained || !controlDrained) throw cleanupFailed(error);
      throw drainedTransferError(error);
    } finally {
      if (ownsReservation) this.reservedSessionIds.delete(manifest.transferId);
      if (session && this.sessions.get(manifest.transferId) === session) this.sessions.delete(manifest.transferId);
      session?.dispose();
      attempt.dispose();
    }
  }

  private async offerDestination(
    manifest: FileManifest<TMetadata>,
    security: FileTransferSecurityContext,
    signal: AbortSignal
  ): Promise<FileDestination<TMetadata>> {
    if (!this.options.incoming) throw new P2PError('REJECTED', 'Peer does not accept incoming files');
    let destination: FileDestination<TMetadata> | undefined;
    let rejection: string | undefined;
    await this.localOperation((operationSignal) => {
      const offer: FileOffer<TMetadata> = Object.freeze({
        peerId: this.options.peerId,
        principal: security.principal,
        sessionId: security.sessionId,
        signal: operationSignal,
        manifest,
        accept(value: FileDestination<TMetadata>) {
          throwIfCancelled(operationSignal);
          if (destination || rejection) throw new P2PError('INTERNAL', 'File offer already decided');
          destination = value;
        },
        reject(reason = 'File offer rejected') {
          throwIfCancelled(operationSignal);
          if (destination || rejection) throw new P2PError('INTERNAL', 'File offer already decided');
          rejection = safeRejectionReason(reason, 'File offer rejected');
        }
      });
      return Promise.resolve(this.options.incoming!(offer));
    }, signal, 'Incoming file decision timed out');
    if (rejection || !destination) throw new P2PError('REJECTED', rejection ?? 'Incoming handler did not accept the file');
    return destination;
  }

  private async openPull(
    token: string,
    requestId: string,
    options: DownloadFileOptions,
    signal: AbortSignal
  ): Promise<{
    stream: QuicBiStream;
    manifest: FileManifest<TMetadata>;
    context: FileTransferConnectionContext;
  }> {
    throwIfCancelled(signal);
    validateTransferId(requestId, this.limits);
    validateChunkSize(options.chunkSize ?? this.limits.chunkSize, this.limits.maxChunkSize);
    validateLaneCount(options.lanes ?? this.limits.lanes, this.limits);
    const context = await this.getConnection(signal);
    const attempt = combinedController([signal, context.signal]);
    let stream: QuicBiStream | undefined;
    try {
      const opened = await this.openBiStream(context.connection, attempt.controller.signal);
      stream = opened;
      await this.networkOperation(
        () => opened.send.setPriority(50),
        attempt.controller.signal,
        'File control priority timed out'
      );
      await this.writeKind(opened.send, StreamKind.TransferControl, attempt.controller.signal);
      await this.writeControlFrame(opened.send, TransferFrameKind.Pull, {
        token,
        requestId,
        options: { chunkSize: options.chunkSize ?? this.limits.chunkSize, lanes: options.lanes ?? this.limits.lanes }
      } satisfies TransferPull, attempt.controller.signal);
      const offer = await this.readControlFrame(opened.recv, attempt.controller.signal);
      if (offer.kind === TransferFrameKind.Reject) throw new P2PError('REJECTED', readReason(offer.value));
      if (offer.kind !== TransferFrameKind.Offer) throw new P2PError('INVALID_FRAME', 'Pull did not receive a file offer');
      return { stream: opened, manifest: validateManifest<TMetadata>(offer.value, this.limits), context };
    } catch (cause) {
      if (!stream) throw cause;
      const drained = await this.abortBiStream(stream);
      if (!drained) throw cleanupFailed(cause);
      throw cause;
    } finally {
      attempt.dispose();
    }
  }

  private async retryFiles<TResult>(signal: AbortSignal, operation: () => Promise<TResult>): Promise<TResult> {
    let attempt = 0;
    while (true) {
      throwIfCancelled(signal);
      try {
        return await operation();
      } catch (cause) {
        const error = asP2PError(cause, 'DISCONNECTED');
        if (error.code !== 'DISCONNECTED' || attempt >= 5) throw error;
        try {
          await delay(Math.min(500 * 2 ** attempt, 8_000), undefined, { signal });
        } catch (delayCause) {
          if (signal.aborted) throw signalError(signal);
          throw delayCause;
        }
        attempt += 1;
      }
    }
  }

  private emitProgress(
    manifest: FileManifest<TMetadata>,
    completedChunks: number,
    direction: 'send' | 'receive',
    transfer: Transfer<TMetadata> | undefined
  ): void {
    const progress: TransferProgress = Object.freeze({
      transferId: manifest.transferId,
      direction,
      transferredBytes: Math.min(manifest.size, completedChunks * manifest.chunkSize),
      totalBytes: manifest.size,
      completedChunks,
      totalChunks: manifest.chunkCount
    });
    transfer?.emit(progress);
    try {
      const delivered = this.options.onProgress?.(progress);
      void Promise.resolve(delivered).catch(() => undefined);
    } catch {
      // Observability callbacks cannot influence transfer correctness.
    }
  }

  private frameLimits(): FrameLimits {
    return this.options.frameLimits ?? DEFAULT_FRAME_LIMITS;
  }

  private readControlFrame<T = unknown>(recv: QuicRecvStream, signal?: AbortSignal): Promise<Frame<T>> {
    return this.networkOperation(
      () => readFrame<T>(recv, this.frameLimits()),
      signal,
      'File control frame timed out'
    );
  }

  private readControlFrameUntilCancelled<T = unknown>(
    recv: QuicRecvStream,
    signal?: AbortSignal
  ): Promise<Frame<T>> {
    return cancellableOperation(
      () => readFrame<T>(recv, this.frameLimits()),
      signal,
      'DISCONNECTED'
    );
  }

  private async getConnection(signal: AbortSignal): Promise<FileTransferConnectionContext> {
    const context = await this.networkOperation(this.options.connection, signal, 'File connection timed out');
    if (
      !context ||
      typeof context !== 'object' ||
      !context.connection ||
      !context.security ||
      !(context.signal instanceof AbortSignal)
    ) {
      throw new P2PError('INTERNAL', 'File connection provider returned an invalid authenticated context');
    }
    throwIfCancelled(context.signal);
    return context;
  }

  private async openBiStream(connection: QuicConnection, signal: AbortSignal): Promise<QuicBiStream> {
    const pending = Promise.resolve().then(() => connection.openBi());
    try {
      return await this.networkOperation(() => pending, signal, 'Opening file control stream timed out');
    } catch (cause) {
      void pending.then((stream) => this.abortBiStream(stream), () => undefined);
      throw cause;
    }
  }

  private async openUniStream(connection: QuicConnection, signal: AbortSignal): Promise<QuicSendStream> {
    const pending = Promise.resolve().then(() => connection.openUni());
    try {
      return await this.networkOperation(() => pending, signal, 'Opening file data stream timed out');
    } catch (cause) {
      void pending.then((send) => this.abortSendStream(send), () => undefined);
      throw cause;
    }
  }

  private writeKind(send: QuicSendStream, kind: StreamKind, signal?: AbortSignal): Promise<void> {
    return this.networkOperation(() => writeStreamKind(send, kind), signal, 'Writing file stream header timed out');
  }

  private writeControlFrame(
    send: QuicSendStream,
    kind: TransferFrameKind,
    value: unknown,
    signal?: AbortSignal
  ): Promise<void> {
    return this.networkOperation(
      () => writeFrame(send, kind, value, this.frameLimits()),
      signal,
      'Writing file control frame timed out'
    );
  }

  private finishSendStream(send: QuicSendStream, signal?: AbortSignal): Promise<void> {
    return this.networkOperation(() => send.finish(), signal, 'Finishing file stream timed out');
  }

  private expectRecvEnd(recv: QuicRecvStream, signal?: AbortSignal): Promise<void> {
    return this.networkOperation(() => recv.expectEnd(), signal, 'Finishing file stream timed out');
  }

  private async writeChunkBody(send: QuicSendStream, data: Uint8Array, signal: AbortSignal): Promise<void> {
    for (let offset = 0; offset < data.byteLength; offset += DATA_SEGMENT_BYTES) {
      const segment = data.subarray(offset, Math.min(data.byteLength, offset + DATA_SEGMENT_BYTES));
      await this.networkOperation(() => send.writeAll(segment), signal, 'File chunk write timed out');
    }
  }

  private async readChunkBody(recv: QuicRecvStream, size: number, signal: AbortSignal): Promise<Uint8Array> {
    const data = new Uint8Array(size);
    for (let offset = 0; offset < size; offset += DATA_SEGMENT_BYTES) {
      const length = Math.min(DATA_SEGMENT_BYTES, size - offset);
      data.set(
        await this.networkOperation(() => recv.readExact(length), signal, 'File chunk body timed out'),
        offset
      );
    }
    return data;
  }

  private networkOperation<TResult>(
    operation: () => Promise<TResult>,
    signal: AbortSignal | undefined,
    message: string
  ): Promise<TResult> {
    return boundedOperation(operation, this.idleTimeoutMs, message, signal, 'DISCONNECTED');
  }

  private localOperation<TResult>(
    operation: (signal: AbortSignal) => Promise<TResult>,
    signal: AbortSignal | undefined,
    message: string
  ): Promise<TResult> {
    return cooperativeOperation(operation, this.idleTimeoutMs, message, signal);
  }

  private async settleTasks(tasks: readonly Promise<unknown>[]): Promise<boolean> {
    if (tasks.length === 0) return true;
    return this.cleanupOperation(() => Promise.allSettled(tasks).then(() => undefined));
  }

  private abortSendStream(send: QuicSendStream): Promise<boolean> {
    return this.cleanupOperation(() => send.reset(3n));
  }

  private abortRecvStream(recv: QuicRecvStream): Promise<boolean> {
    return this.cleanupOperation(() => recv.stop(3n));
  }

  private async abortBiStream(stream: QuicBiStream): Promise<boolean> {
    const results = await Promise.all([
      this.abortSendStream(stream.send),
      this.abortRecvStream(stream.recv)
    ]);
    return results.every(Boolean);
  }

  private async abortSendStreams(streams: ReadonlySet<QuicSendStream>): Promise<boolean> {
    const results = await Promise.all([...streams].map((stream) => this.abortSendStream(stream)));
    return results.every(Boolean);
  }

  private async abortRecvStreams(streams: ReadonlySet<QuicRecvStream>): Promise<boolean> {
    const results = await Promise.all([...streams].map((stream) => this.abortRecvStream(stream)));
    return results.every(Boolean);
  }

  private async rejectControlStream(stream: QuicBiStream, cause: unknown): Promise<boolean> {
    let wrote = false;
    const writeSettled = await this.cleanupOperation(async () => {
      await writeFrame(stream.send, TransferFrameKind.Reject, publicRejection(cause), this.frameLimits());
      await stream.send.finish();
      wrote = true;
    });
    const recvStopped = await this.abortRecvStream(stream.recv);
    if (writeSettled && wrote) return recvStopped;
    const sendReset = await this.abortSendStream(stream.send);
    return sendReset && recvStopped;
  }

  private async cleanupOperation(operation: () => Promise<unknown>): Promise<boolean> {
    try {
      const settled = Promise.resolve()
        .then(operation)
        .then(() => undefined, () => undefined);
      await withDeadline(
        settled,
        Math.min(this.idleTimeoutMs, 1_000),
        'File stream cleanup timed out'
      );
      return true;
    } catch {
      return false;
    }
  }

  private async acquireTransferSlot(signal?: AbortSignal): Promise<() => void> {
    throwIfCancelled(signal);
    if (this.activeTransfers < this.limits.maxTransfers) {
      this.activeTransfers += 1;
    } else {
      if (this.transferWaiters.length >= this.limits.maxQueuedTransfers) {
        throw new P2PError('RESOURCE_LIMIT', 'File transfer queue is full');
      }
      await new Promise<void>((resolve, reject) => {
        const waiter = (): void => {
          detachAbort();
          resolve();
        };
        const detachAbort = onAbort(signal, () => {
          const index = this.transferWaiters.indexOf(waiter);
          if (index >= 0) this.transferWaiters.splice(index, 1);
          reject(signal ? signalError(signal) : cancelledError());
        });
        this.transferWaiters.push(waiter);
      });
    }
    let released = false;
    return () => {
      if (released) return;
      released = true;
      const waiter = this.transferWaiters.shift();
      if (waiter) waiter();
      else this.activeTransfers -= 1;
    };
  }
}

function createSession<TMetadata>(
  manifest: FileManifest<TMetadata>,
  destination: FileDestination<TMetadata>,
  missing: Set<number>,
  resumed: boolean,
  allowedLanes: number,
  context: FileTransferConnectionContext,
  signal: AbortSignal
): IncomingSession<TMetadata> {
  const linked = childController(signal);
  let resolvePromise!: () => void;
  let rejectPromise!: (error: unknown) => void;
  let settled = false;
  let activeLanes = 0;
  const laneDrainWaiters = new Set<() => void>();
  const done = new Promise<void>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  // Lane failures can arrive before the control flow awaits `done`; attach a
  // handler immediately while preserving the original rejection for awaiters.
  void done.catch(() => undefined);
  const detachAbort = onAbort(linked.controller.signal, () => {
    if (!settled) {
      settled = true;
      rejectPromise(signalError(linked.controller.signal));
    }
  });
  return {
    manifest,
    destination,
    missing,
    inFlight: new Set(),
    claimedLanes: new Set(),
    attemptId: randomOpaqueId(),
    laneToken: randomBytes(32).toString('base64url'),
    allowedLanes,
    totalMissing: missing.size,
    resumed,
    context,
    controller: linked.controller,
    signal: linked.controller.signal,
    receivers: new Set(),
    done,
    announcedChunks: 0,
    beginLane() {
      activeLanes += 1;
      let released = false;
      return () => {
        if (released) return;
        released = true;
        activeLanes -= 1;
        if (activeLanes === 0) {
          if (missing.size === 0) this.resolve();
          for (const resolve of laneDrainWaiters) resolve();
          laneDrainWaiters.clear();
        }
      };
    },
    lanesDrained() {
      if (activeLanes === 0) return Promise.resolve();
      return new Promise<void>((resolve) => laneDrainWaiters.add(resolve));
    },
    resolve() {
      if (!settled) {
        settled = true;
        resolvePromise();
      }
    },
    reject(error) {
      if (!settled) {
        settled = true;
        rejectPromise(error);
      }
    },
    dispose() {
      detachAbort();
      linked.dispose();
    }
  };
}

function linkedController(signal?: AbortSignal): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const dispose = onAbort(signal, () => controller.abort(signal?.reason));
  return { controller, dispose };
}

function childController(signal: AbortSignal): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const dispose = onAbort(signal, () => controller.abort(signal.reason));
  return { controller, dispose };
}

function combinedController(signals: readonly AbortSignal[]): { controller: AbortController; dispose(): void } {
  const controller = new AbortController();
  const disposers = signals.map((signal) => onAbort(signal, () => controller.abort(signal.reason)));
  return {
    controller,
    dispose() {
      for (const dispose of disposers) dispose();
    }
  };
}

function onAbort(signal: AbortSignal | undefined, callback: () => void): () => void {
  if (!signal) return () => undefined;
  if (signal.aborted) {
    callback();
    return () => undefined;
  }
  signal.addEventListener('abort', callback, { once: true });
  return () => signal.removeEventListener('abort', callback);
}

function throwIfCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw signalError(signal);
}

function cancelledError(): P2PError {
  return new P2PError('CANCELLED', 'Transfer cancelled');
}

function signalError(signal: AbortSignal): P2PError {
  return signal.reason instanceof P2PError ? signal.reason : cancelledError();
}

function cleanupFailed(cause: unknown): P2PError {
  return new P2PError('INTERNAL', 'File transfer stream cleanup could not be confirmed', { cause });
}

class DrainedTransferError extends P2PError {
  constructor(error: P2PError) {
    super(error.code, error.message, { cause: error });
    this.name = 'DrainedTransferError';
  }
}

function drainedTransferError(cause: unknown): DrainedTransferError {
  return new DrainedTransferError(asP2PError(cause));
}

function validatePull(value: unknown, limits: FileTransferLimits): TransferPull {
  if (!isRecord(value) || typeof value.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.token)) {
    throw new P2PError('INVALID_FRAME', 'Invalid file pull request');
  }
  const requestId = validateTransferId(value.requestId, limits);
  if (value.options !== undefined && !isRecord(value.options)) throw new P2PError('INVALID_FRAME', 'Invalid file pull options');
  const options = value.options as Record<string, unknown> | undefined;
  const chunkSize = options?.chunkSize === undefined
    ? undefined
    : validateChunkSize(options.chunkSize as number, limits.maxChunkSize);
  const lanes = options?.lanes === undefined ? undefined : validateLaneCount(options.lanes as number, limits);
  return {
    token: value.token,
    requestId,
    ...((chunkSize !== undefined || lanes !== undefined) ? { options: { ...(chunkSize !== undefined ? { chunkSize } : {}), ...(lanes !== undefined ? { lanes } : {}) } } : {})
  };
}

function validateAccept(value: unknown, manifest: FileManifest, limits: FileTransferLimits): TransferAccept {
  if (!isRecord(value) || value.transferId !== manifest.transferId) throw new P2PError('INVALID_FRAME', 'Invalid transfer acceptance');
  const attemptId = validateOpaqueId(value.attemptId, 'attempt ID');
  const laneToken = validateLaneToken(value.laneToken);
  const lanes = validateLaneCount(value.lanes as number, limits);
  if (!Number.isSafeInteger(value.missingCount) || (value.missingCount as number) < 0 || (value.missingCount as number) > manifest.chunkCount) {
    throw new P2PError('INVALID_FRAME', 'Invalid missing chunk count');
  }
  if (!Array.isArray(value.missingRanges) || value.missingRanges.length > limits.maxMissingRanges) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid or excessive missing chunk ranges');
  }
  return {
    transferId: manifest.transferId,
    attemptId,
    laneToken,
    missingRanges: value.missingRanges as Array<readonly [number, number]>,
    missingCount: value.missingCount as number,
    lanes
  };
}

function validateLaneHeader(value: unknown, limits: FileTransferLimits): LaneHeader {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer lane header');
  const transferId = validateTransferId(value.transferId, limits);
  const attemptId = validateOpaqueId(value.attemptId, 'attempt ID');
  const laneToken = validateLaneToken(value.laneToken);
  if (!Number.isSafeInteger(value.laneId) || (value.laneId as number) < 0 || (value.laneId as number) >= limits.maxLanes) {
    throw new P2PError('INVALID_FRAME', 'Invalid transfer lane ID');
  }
  if (!Number.isSafeInteger(value.count) || (value.count as number) < 1 || (value.count as number) > limits.maxChunkCount) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid transfer lane chunk count');
  }
  return { transferId, attemptId, laneToken, laneId: value.laneId as number, count: value.count as number };
}

function validateChunkHeader(value: unknown, manifest: FileManifest): ChunkHeader {
  if (!isRecord(value) || !Number.isSafeInteger(value.index)) throw new P2PError('INVALID_FRAME', 'Invalid chunk header');
  const index = value.index as number;
  const expected = expectedChunkSize(manifest, index);
  if (value.size !== expected) throw new P2PError('INVALID_FRAME', `Invalid size for chunk ${index}`);
  const digest = validateDigest(value.digest, 'chunk digest');
  return { index, size: expected, digest };
}

function validateLaneCount(value: number, limits: FileTransferLimits): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > limits.maxLanes) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid lane count');
  }
  return value;
}

function clampLanes(value: number, max: number, work: number): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new P2PError('RESOURCE_LIMIT', 'Invalid lane count');
  return Math.max(1, Math.min(value, max, work));
}

function compressRanges(indexes: ReadonlySet<number>, maximumRanges: number): Array<readonly [number, number]> {
  const ranges: Array<readonly [number, number]> = [];
  let start: number | undefined;
  let previous: number | undefined;
  for (const index of indexes) {
    if (start === undefined) {
      start = previous = index;
    } else if (previous !== undefined && index === previous + 1) {
      previous = index;
    } else {
      ranges.push([start, (previous ?? start) + 1]);
      if (ranges.length > maximumRanges) throw new P2PError('RESOURCE_LIMIT', 'Resume state is too fragmented');
      start = previous = index;
    }
  }
  if (start !== undefined) ranges.push([start, (previous ?? start) + 1]);
  if (ranges.length > maximumRanges) throw new P2PError('RESOURCE_LIMIT', 'Resume state is too fragmented');
  return ranges;
}

function expandRanges(ranges: Array<readonly [number, number]>, chunkCount: number, expectedCount: number): number[] {
  const indexes: number[] = [];
  let previousEnd = 0;
  for (const range of ranges) {
    if (!Array.isArray(range) || range.length !== 2) throw new P2PError('INVALID_FRAME', 'Invalid chunk range');
    const [start, end] = range;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < previousEnd || end <= start || end > chunkCount) {
      throw new P2PError('INVALID_FRAME', 'Invalid or overlapping chunk range');
    }
    if (indexes.length + end - start > expectedCount) throw new P2PError('INVALID_FRAME', 'Missing ranges exceed their declared count');
    for (let index = start; index < end; index += 1) indexes.push(index);
    previousEnd = end;
  }
  if (indexes.length !== expectedCount) throw new P2PError('INVALID_FRAME', 'Missing ranges do not match their declared count');
  return indexes;
}

function matchesCompletion(value: unknown, expected: { transferId: string; attemptId: string }): boolean {
  return isRecord(value) && value.transferId === expected.transferId && value.attemptId === expected.attemptId;
}

function assertSameManifest(expected: FileManifest, actual: FileManifest): void {
  if (
    expected.transferId !== actual.transferId ||
    expected.digest !== actual.digest ||
    expected.size !== actual.size ||
    expected.chunkSize !== actual.chunkSize ||
    expected.chunkCount !== actual.chunkCount ||
    expected.name !== actual.name ||
    !metadataEqual(expected.metadata, actual.metadata)
  ) {
    throw new P2PError('INTEGRITY_FAILED', 'Shared file changed while resuming a download');
  }
}

function metadataEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left instanceof Uint8Array || right instanceof Uint8Array) {
    if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array) || left.byteLength !== right.byteLength) return false;
    for (let index = 0; index < left.byteLength; index += 1) {
      if (left[index] !== right[index]) return false;
    }
    return true;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => metadataEqual(item, right[index]));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every((key, index) => key === rightKeys[index] && metadataEqual(left[key], right[key]));
}

function publicRejection(cause: unknown): { readonly code: string; readonly reason: string } {
  const error = asP2PError(cause);
  const reason = error.code === 'RESOURCE_LIMIT'
    ? 'Transfer exceeds receiver resource policy'
    : error.code === 'INCOMPATIBLE_PROTOCOL'
      ? 'Transfer protocol is incompatible'
      : 'Transfer rejected';
  return { code: error.code, reason };
}

function readReason(value: unknown): string {
  return isRecord(value)
    ? safeRejectionReason(value.reason, 'Transfer rejected')
    : 'Transfer rejected';
}

function safeRejectionReason(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const output = sanitizeBoundedDisplayText(value, 256, fallback);
  return output.trim().length > 0 ? output : fallback;
}

function validateOpaqueId(value: unknown, label: string): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(value)) throw new P2PError('INVALID_FRAME', `Invalid ${label}`);
  return value;
}

function validateLaneToken(value: unknown): string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new P2PError('INVALID_FRAME', 'Invalid transfer lane token');
  return value;
}

function randomOpaqueId(): string {
  return randomBytes(16).toString('base64url');
}

function randomTransferId(): string {
  return `r${randomOpaqueId()}`;
}

async function boundedOperation<T>(
  operation: () => Promise<T>,
  timeoutMs: number,
  message: string,
  signal: AbortSignal | undefined,
  fallback: 'DISCONNECTED' | 'INTERNAL'
): Promise<T> {
  throwIfCancelled(signal);
  let timer: ReturnType<typeof setTimeout> | undefined;
  let detachAbort = (): void => undefined;
  const task = Promise.resolve().then(operation).catch((cause: unknown) => {
    throw asP2PError(cause, fallback);
  });
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new P2PError('TIMEOUT', message)), timeoutMs);
    timer.unref?.();
  });
  const aborted = new Promise<never>((_, reject) => {
    detachAbort = onAbort(signal, () => reject(signal ? signalError(signal) : cancelledError()));
  });
  try {
    return await Promise.race([task, timeout, aborted]);
  } finally {
    if (timer) clearTimeout(timer);
    detachAbort();
  }
}

async function cancellableOperation<T>(
  operation: () => Promise<T>,
  signal: AbortSignal | undefined,
  fallback: 'DISCONNECTED' | 'INTERNAL'
): Promise<T> {
  throwIfCancelled(signal);
  let detachAbort = (): void => undefined;
  const task = Promise.resolve().then(operation).catch((cause: unknown) => {
    throw asP2PError(cause, fallback);
  });
  const aborted = new Promise<never>((_, reject) => {
    detachAbort = onAbort(signal, () => reject(signal ? signalError(signal) : cancelledError()));
  });
  try {
    return await Promise.race([task, aborted]);
  } finally {
    detachAbort();
  }
}

async function cooperativeOperation<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  message: string,
  signal: AbortSignal | undefined
): Promise<T> {
  throwIfCancelled(signal);
  const linked = linkedController(signal);
  const timeoutError = new P2PError('TIMEOUT', message);
  let detachAbort = (): void => undefined;
  const task = Promise.resolve()
    .then(() => operation(linked.controller.signal))
    .then(
      (value) => ({ kind: 'result' as const, value }),
      (cause: unknown) => ({ kind: 'error' as const, error: asP2PError(cause, 'INTERNAL') })
    );
  const aborted = new Promise<{ kind: 'aborted' }>((resolve) => {
    detachAbort = onAbort(linked.controller.signal, () => resolve({ kind: 'aborted' }));
  });
  const timer = setTimeout(() => linked.controller.abort(timeoutError), timeoutMs);
  timer.unref?.();
  try {
    const outcome = await Promise.race([task, aborted]);
    if (outcome.kind === 'result') return outcome.value;
    if (outcome.kind === 'error') throw outcome.error;

    // File callbacks are side-effecting. Once cancelled, wait for them to
    // observe the cooperative signal and settle before returning an error so
    // they cannot publish a destination after the caller sees TIMEOUT.
    const settled = await task;
    // A callback may have crossed an uninterruptible atomic commit just before
    // cancellation. Report that successful commit as success; never report a
    // timeout and then allow its externally visible publication to appear.
    if (settled.kind === 'result') return settled.value;
    throw signalError(linked.controller.signal);
  } finally {
    clearTimeout(timer);
    detachAbort();
    linked.dispose();
  }
}

async function withDeadline<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new P2PError('TIMEOUT', message)), timeoutMs);
        timer.unref?.();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
