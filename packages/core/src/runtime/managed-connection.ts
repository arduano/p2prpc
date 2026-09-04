import { P2PError } from '../errors.js';
import type {
  ConnectionPath,
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicRecvStream,
  QuicSendStream,
  StreamOpenOptions
} from '../transport/types.js';
import type { ResourceLease, ResourceOwner, ResourceScheduler } from './resources.js';

/** Accounts every locally opened QUIC stream until its halves terminate. */
export class ManagedConnection implements QuicConnection {
  readonly remoteId: string;
  readonly side: 'client' | 'server';
  private readonly openScopes = new Set<StreamLease>();
  private readonly opening = new Set<ResourceLease>();
  private readonly closeController = new AbortController();
  private closedForOpens = false;
  private closeRequested = false;
  private resourcesReleased = false;

  constructor(
    private readonly inner: QuicConnection,
    private readonly scheduler: ResourceScheduler,
    private readonly owner: Readonly<ResourceOwner>,
    private readonly signal: AbortSignal,
    private readonly biBufferedBytes: number,
    private readonly uniBufferedBytes: number
  ) {
    this.remoteId = inner.remoteId;
    this.side = inner.side;
    // Only fulfilled closed() is proof that native streams no longer exist.
    // An adapter rejection is a diagnostics failure, not permission to erase
    // admission ownership and report a false quiescent state.
    void Promise.resolve().then(() => inner.closed()).then(
      () => this.releaseAll(),
      () => undefined
    );
  }

  async openBi(options: StreamOpenOptions = {}): Promise<QuicBiStream> {
    validateBiOptions(options);
    const signal = this.openSignal(options.signal);
    const lease = await this.acquire(this.biBufferedBytes, options, signal);
    if (this.closedForOpens) {
      lease.release();
      throw new P2PError('DISCONNECTED', 'Connection closed while admitting a stream open');
    }
    throwIfAborted(signal, lease);
    this.opening.add(lease);
    let stream: QuicBiStream | undefined;
    let cancelled = false;
    // Do not forward cancellation into the raw adapter. A raw promise may
    // reject cooperatively while its native open can still produce a stream,
    // which would erase the only ownership proof. ManagedConnection owns the
    // prompt public race and observes the raw promise to real settlement.
    const pending = startOperation(() => this.inner.openBi());
    try {
      stream = await abortable(pending, signal, () => {
        cancelled = true;
        this.quarantine('Bidirectional stream opening was cancelled');
      });
      if (signal.aborted || this.closedForOpens) {
        cancelled = true;
        this.quarantine('Bidirectional stream opening was cancelled');
        this.settleLateBi(Promise.resolve(stream), lease);
        throw abortReason(signal);
      }
      // Read adapter-owned properties before transferring the lease to a
      // public wrapper. A hostile or broken getter cannot strand an adopted
      // stream outside either terminal cleanup or physical-close ownership.
      const send = stream.send;
      const recv = stream.recv;
      if (signal.aborted || this.closedForOpens) {
        cancelled = true;
        this.quarantine('Bidirectional stream adoption was cancelled');
        this.settleLateBi(Promise.resolve({ send, recv }), lease);
        throw abortReason(signal);
      }
      const wrapped = this.wrapBi(send, recv, lease);
      this.opening.delete(lease);
      return wrapped;
    } catch (cause) {
      // Before a native stream exists, rejection settles the owned operation.
      // After one exists, a failed terminal cleanup remains owned until the
      // physical connection's closed() promise confirms teardown.
      if (cancelled && !stream) {
        this.settleLateBi(pending, lease);
      } else if (!stream) {
        this.opening.delete(lease);
        lease.release();
        // A raw transport that cannot open a stream is no longer a usable
        // connection, even if its separate closed() notification has not
        // arrived yet. Quarantine it so retained Peer proxies can move to the
        // disconnected state and redial instead of retrying one stale native
        // session handle forever.
        this.quarantine('Bidirectional stream opening failed');
      } else if (!this.closedForOpens) {
        // This is only reachable if wrapping the native stream itself throws.
        // Quarantine it: no caller owns its terminal halves. Admission remains
        // charged until terminal cleanup or physical closure is confirmed.
        this.quarantine('Stream adoption failed');
        this.settleLateBi(Promise.resolve(stream), lease);
      }
      throw cause;
    }
  }

  acceptBi(): Promise<QuicBiStream> {
    return this.inner.acceptBi();
  }

  async openUni(options: StreamOpenOptions = {}): Promise<QuicSendStream> {
    const classified = options.fileData === undefined
      ? { ...options, fileData: 'outbound' as const }
      : options;
    validateUniOptions(classified);
    const signal = this.openSignal(classified.signal);
    const lease = await this.acquire(this.uniBufferedBytes, classified, signal);
    if (this.closedForOpens) {
      lease.release();
      throw new P2PError('DISCONNECTED', 'Connection closed while admitting a stream open');
    }
    throwIfAborted(signal, lease);
    this.opening.add(lease);
    let stream: QuicSendStream | undefined;
    let cancelled = false;
    const pending = startOperation(() => this.inner.openUni());
    try {
      stream = await abortable(pending, signal, () => {
        cancelled = true;
        this.quarantine('Unidirectional stream opening was cancelled');
      });
      if (signal.aborted || this.closedForOpens) {
        cancelled = true;
        this.quarantine('Unidirectional stream adoption was cancelled');
        this.settleLateUni(Promise.resolve(stream), lease);
        throw abortReason(signal);
      }
      const scope = new StreamLease(lease, 1, this.openScopes);
      const wrapped = this.wrapSend(stream, scope.half());
      this.opening.delete(lease);
      return wrapped;
    } catch (cause) {
      if (cancelled && !stream) {
        this.settleLateUni(pending, lease);
      } else if (!stream) {
        this.opening.delete(lease);
        lease.release();
        this.quarantine('Unidirectional stream opening failed');
      } else if (!this.closedForOpens) {
        this.quarantine('Stream adoption failed');
        this.settleLateUni(Promise.resolve(stream), lease);
      }
      throw cause;
    }
  }

  acceptUni(): Promise<QuicRecvStream> {
    return this.inner.acceptUni();
  }

  closed(): Promise<string> { return this.inner.closed(); }
  stats(): Promise<ConnectionStats> { return this.inner.stats(); }
  pathChanges(signal?: AbortSignal): AsyncIterable<ConnectionPath> {
    if (!this.inner.pathChanges) throw new P2PError('REJECTED', 'Transport does not expose connection path changes');
    return this.inner.pathChanges(signal);
  }

  close(code: bigint, reason: Uint8Array): void {
    this.closedForOpens = true;
    if (!this.closeController.signal.aborted) {
      this.closeController.abort(new P2PError('DISCONNECTED', 'Connection was closed'));
    }
    if (this.closeRequested) return;
    this.closeRequested = true;
    this.inner.close(code, reason);
  }

  private acquire(
    bufferedBytes: number,
    options: StreamOpenOptions,
    signal: AbortSignal
  ): Promise<ResourceLease> {
    if (this.closedForOpens) return Promise.reject(new P2PError('DISCONNECTED', 'Connection resource scope is closed'));
    return this.scheduler.acquire(this.owner, {
      streams: 1,
      bufferedBytes,
      ...(options.fileControl !== undefined ? { fileControl: options.fileControl } : {}),
      ...(options.fileData !== undefined ? { fileData: options.fileData } : {})
    }, signal);
  }

  private openSignal(operationSignal?: AbortSignal): AbortSignal {
    const signals = [
      ...(operationSignal ? [operationSignal] : []),
      this.closeController.signal,
      this.signal
    ];
    return signals.length === 1 ? signals[0]! : AbortSignal.any(signals);
  }

  private wrapBi(send: QuicSendStream, recv: QuicRecvStream, lease: ResourceLease): QuicBiStream {
    const scope = new StreamLease(lease, 2, this.openScopes);
    return Object.freeze({
      send: this.wrapSend(send, scope.half()),
      recv: this.wrapRecv(recv, scope.half())
    });
  }

  private settleLateBi(pending: Promise<QuicBiStream>, lease: ResourceLease): void {
    void pending.then(async (stream) => {
      const outcomes = await Promise.allSettled([
        startOperation(() => stream.send.reset(2n)),
        startOperation(() => stream.recv.stop(2n))
      ]);
      if (outcomes.every((outcome) => outcome.status === 'fulfilled')) {
        this.releaseOpening(lease);
      } else {
        this.requestPhysicalClose('Late bidirectional stream cleanup failed');
      }
    }, () => this.releaseOpening(lease)).catch(() => {
      this.requestPhysicalClose('Late bidirectional stream cleanup failed');
    });
  }

  private settleLateUni(pending: Promise<QuicSendStream>, lease: ResourceLease): void {
    void pending.then(async (stream) => {
      try {
        await stream.reset(2n);
        this.releaseOpening(lease);
      } catch {
        this.requestPhysicalClose('Late unidirectional stream cleanup failed');
      }
    }, () => this.releaseOpening(lease)).catch(() => {
      this.requestPhysicalClose('Late unidirectional stream cleanup failed');
    });
  }

  private releaseOpening(lease: ResourceLease): void {
    this.opening.delete(lease);
    lease.release();
  }

  private quarantine(reason: string): void {
    if (this.closedForOpens) return;
    this.closedForOpens = true;
    if (!this.closeController.signal.aborted) {
      this.closeController.abort(new P2PError('DISCONNECTED', reason));
    }
    this.requestPhysicalClose(reason);
  }

  private requestPhysicalClose(reason: string): void {
    if (this.closeRequested) return;
    this.closeRequested = true;
    requestClose(this.inner, 4n, reason);
  }

  private wrapSend(stream: QuicSendStream, settleHalf: () => void): QuicSendStream {
    return Object.freeze({
      writeAll: (data: Uint8Array) => stream.writeAll(data),
      setPriority: (priority: number) => stream.setPriority(priority),
      finish: () => terminal(() => stream.finish(), settleHalf),
      reset: (code: bigint) => terminal(() => stream.reset(code), settleHalf)
    });
  }

  private wrapRecv(stream: QuicRecvStream, settleHalf: () => void): QuicRecvStream {
    return Object.freeze({
      readExact: (size: number) => stream.readExact(size),
      expectEnd: () => terminal(() => stream.expectEnd(), settleHalf),
      stop: (code: bigint) => terminal(() => stream.stop(code), settleHalf)
    });
  }

  private releaseAll(): void {
    if (this.resourcesReleased) return;
    this.resourcesReleased = true;
    this.closedForOpens = true;
    this.closeRequested = true;
    if (!this.closeController.signal.aborted) {
      this.closeController.abort(new P2PError('DISCONNECTED', 'Physical connection closed'));
    }
    for (const lease of this.opening) lease.release();
    this.opening.clear();
    for (const scope of [...this.openScopes]) scope.force();
  }
}

function validateBiOptions(options: StreamOpenOptions): void {
  validateOpenSignal(options.signal);
  if (options.fileData !== undefined || (options.fileControl !== undefined && options.fileControl !== 'outbound')) {
    throw new P2PError('INTERNAL', 'Invalid bidirectional stream resource class');
  }
}

function validateUniOptions(options: StreamOpenOptions): void {
  validateOpenSignal(options.signal);
  if (options.fileControl !== undefined || options.fileData !== 'outbound') {
    throw new P2PError('INTERNAL', 'Invalid unidirectional stream resource class');
  }
}

function validateOpenSignal(signal: AbortSignal | undefined): void {
  if (signal !== undefined && !(signal instanceof AbortSignal)) {
    throw new P2PError('INTERNAL', 'Invalid stream-open cancellation signal');
  }
}

function throwIfAborted(signal: AbortSignal, lease: ResourceLease): void {
  if (!signal.aborted) return;
  lease.release();
  throw abortReason(signal);
}

function abortReason(signal: AbortSignal): unknown {
  return signal.aborted
    ? signal.reason ?? new P2PError('CANCELLED', 'Stream opening was cancelled')
    : new P2PError('DISCONNECTED', 'Connection closed while opening a stream');
}

function startOperation<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return Promise.resolve(operation());
  } catch (cause) {
    return Promise.reject(cause);
  }
}

function abortable<T>(
  operation: Promise<T>,
  signal: AbortSignal,
  onAbort: () => void
): Promise<T> {
  if (signal.aborted) {
    onAbort();
    return Promise.reject(abortReason(signal));
  }
  return new Promise<T>((resolve, reject) => {
    const aborted = (): void => {
      onAbort();
      reject(abortReason(signal));
    };
    signal.addEventListener('abort', aborted, { once: true });
    void operation.then(
      (value) => {
        signal.removeEventListener('abort', aborted);
        resolve(value);
      },
      (cause) => {
        signal.removeEventListener('abort', aborted);
        reject(cause);
      }
    );
  });
}

class StreamLease {
  private remaining: number;
  private released = false;

  constructor(
    private readonly lease: ResourceLease,
    halves: number,
    private readonly owner: Set<StreamLease>
  ) {
    this.remaining = halves;
    owner.add(this);
  }

  half(): () => void {
    let settled = false;
    return () => {
      if (settled || this.released) return;
      settled = true;
      this.remaining -= 1;
      if (this.remaining === 0) this.force();
    };
  }

  force(): void {
    if (this.released) return;
    this.released = true;
    this.owner.delete(this);
    this.lease.release();
  }
}

async function terminal(operation: () => Promise<void>, settle: () => void): Promise<void> {
  await operation();
  settle();
}

/** A broken adapter close must not replace the operation which exposed it. */
function requestClose(connection: QuicConnection, code: bigint, reason: string): void {
  try {
    connection.close(code, new TextEncoder().encode(reason));
  } catch {
    // Admission deliberately remains owned until fulfilled closed() proof.
  }
}
