import type { FileManifest, FileTransfer, TransferProgress, TransferResult } from './types.js';

/** Internal implementation; public APIs expose the read-only FileTransfer interface. */
export class Transfer<TMetadata = unknown> implements FileTransfer<TMetadata>, AsyncIterable<TransferProgress> {
  readonly result: Promise<TransferResult<TMetadata>>;
  private readonly listeners = new Map<(value: TransferProgress) => void, ProgressListener>();
  private readonly subscribers = new Set<ProgressSubscriber>();
  private settled = false;

  constructor(
    readonly manifest: FileManifest<TMetadata>,
    private readonly controller: AbortController,
    executor: () => Promise<TransferResult<TMetadata>>
  ) {
    this.result = executor().finally(() => {
      this.settled = true;
      for (const subscriber of this.subscribers) subscriber.finish();
      this.subscribers.clear();
      for (const listener of this.listeners.values()) listener.close();
      this.listeners.clear();
    });
    // The executor starts before sendFile()/download() can return the handle.
    // A fast rejection can therefore reach the host's unhandled-rejection
    // checkpoint while a caller is still awaiting the handle or deliberately
    // waiting before cancel(). Observe that transient window without changing
    // `result`: a later consumer still receives its original settlement.
    void this.result.catch(() => undefined);
  }

  cancel(reason: unknown = new Error('Transfer cancelled')): void {
    this.controller.abort(reason);
  }

  onProgress(listener: (progress: TransferProgress) => void): () => void {
    if (this.settled) return () => undefined;
    const state = new ProgressListener(listener);
    this.listeners.set(listener, state);
    return () => {
      state.close();
      this.listeners.delete(listener);
    };
  }

  emit(progress: TransferProgress): void {
    const snapshot: TransferProgress = Object.freeze({
      transferId: progress.transferId,
      direction: progress.direction,
      transferredBytes: progress.transferredBytes,
      totalBytes: progress.totalBytes,
      completedChunks: progress.completedChunks,
      totalChunks: progress.totalChunks
    });
    for (const listener of this.listeners.values()) listener.push(snapshot);
    for (const subscriber of this.subscribers) subscriber.push(snapshot);
  }

  /**
   * Returns an independently conflated progress feed. A slow observer retains
   * only the newest snapshot and cannot consume another observer's events.
   */
  progress(): AsyncIterable<TransferProgress> {
    return Object.freeze({
      [Symbol.asyncIterator]: () => this.createProgressIterator()
    });
  }

  /** @deprecated Prefer progress(), which makes independent subscriptions explicit. */
  [Symbol.asyncIterator](): AsyncIterator<TransferProgress> {
    return this.createProgressIterator();
  }

  private createProgressIterator(): AsyncIterator<TransferProgress> {
    if (this.settled) return completedIterator();
    const subscriber = new ProgressSubscriber(() => this.subscribers.delete(subscriber));
    this.subscribers.add(subscriber);
    // Settlement and subscription creation are synchronous, but keep this
    // defensive check so future executor changes cannot strand a subscriber.
    if (this.settled) subscriber.finish();
    return subscriber;
  }
}

/** One bounded, conflated delivery lane per observer. */
class ProgressListener {
  private inFlight = false;
  private queued: TransferProgress | undefined;
  private closed = false;

  constructor(private readonly listener: (value: TransferProgress) => void) {}

  push(value: TransferProgress): void {
    if (this.closed) return;
    if (this.inFlight) {
      this.queued = value;
      return;
    }
    this.deliver(value);
  }

  close(): void {
    this.closed = true;
    this.queued = undefined;
  }

  private deliver(value: TransferProgress): void {
    let result: unknown;
    try {
      result = this.listener(value);
    } catch {
      return;
    }
    if (!isPromiseLike(result)) return;
    this.inFlight = true;
    void Promise.resolve(result).then(
      () => this.resume(),
      () => this.resume()
    );
  }

  private resume(): void {
    this.inFlight = false;
    if (this.closed) return;
    const queued = this.queued;
    this.queued = undefined;
    if (queued) this.deliver(queued);
  }
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  try {
    return (
      (typeof value === 'object' && value !== null) ||
      typeof value === 'function'
    ) && typeof (value as { then?: unknown }).then === 'function';
  } catch {
    return false;
  }
}

class ProgressSubscriber implements AsyncIterator<TransferProgress> {
  private queued: TransferProgress | undefined;
  private waiter: ((value: IteratorResult<TransferProgress>) => void) | undefined;
  private settled = false;

  constructor(private readonly unregister: () => void) {}

  push(value: TransferProgress): void {
    if (this.settled) return;
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = undefined;
      waiter({ done: false, value });
    } else {
      this.queued = value;
    }
  }

  next(): Promise<IteratorResult<TransferProgress>> {
    const queued = this.queued;
    this.queued = undefined;
    if (queued) return Promise.resolve({ done: false, value: queued });
    if (this.settled) return Promise.resolve({ done: true, value: undefined });
    if (this.waiter) {
      return Promise.reject(new TypeError('Concurrent next() calls are not supported on a progress iterator'));
    }
    return new Promise<IteratorResult<TransferProgress>>((resolve) => {
      this.waiter = resolve;
    });
  }

  return(): Promise<IteratorResult<TransferProgress>> {
    this.finish();
    return Promise.resolve({ done: true, value: undefined });
  }

  finish(): void {
    if (this.settled) return;
    this.settled = true;
    this.queued = undefined;
    const waiter = this.waiter;
    this.waiter = undefined;
    this.unregister();
    waiter?.({ done: true, value: undefined });
  }
}

function completedIterator(): AsyncIterator<TransferProgress> {
  return Object.freeze({
    next: (): Promise<IteratorResult<TransferProgress>> => Promise.resolve({ done: true, value: undefined }),
    return: (): Promise<IteratorResult<TransferProgress>> => Promise.resolve({ done: true, value: undefined })
  });
}
