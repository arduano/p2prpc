import type { FileManifest, TransferProgress, TransferResult } from './types.js';

export class Transfer<TMetadata = unknown> implements AsyncIterable<TransferProgress> {
  readonly result: Promise<TransferResult<TMetadata>>;
  private readonly listeners = new Set<(value: TransferProgress) => void>();
  private queued: TransferProgress | undefined;
  private readonly waiters: Array<(value: IteratorResult<TransferProgress>) => void> = [];
  private settled = false;

  constructor(
    readonly manifest: FileManifest<TMetadata>,
    private readonly controller: AbortController,
    executor: () => Promise<TransferResult<TMetadata>>
  ) {
    this.result = executor().finally(() => {
      this.settled = true;
      for (const waiter of this.waiters.splice(0)) waiter({ done: true, value: undefined });
    });
  }

  cancel(reason: unknown = new Error('Transfer cancelled')): void {
    this.controller.abort(reason);
  }

  onProgress(listener: (progress: TransferProgress) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
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
    for (const listener of this.listeners) {
      try {
        const delivered = listener(snapshot);
        void Promise.resolve(delivered).catch(() => undefined);
      } catch {
        // Progress observers cannot abort or corrupt a transfer.
      }
    }
    const waiter = this.waiters.shift();
    if (waiter) waiter({ done: false, value: snapshot });
    else this.queued = snapshot;
  }

  [Symbol.asyncIterator](): AsyncIterator<TransferProgress> {
    return {
      next: async () => {
        const queued = this.queued;
        this.queued = undefined;
        if (queued) return { done: false, value: queued };
        if (this.settled) return { done: true, value: undefined };
        return new Promise<IteratorResult<TransferProgress>>((resolve) => this.waiters.push(resolve));
      }
    };
  }
}
