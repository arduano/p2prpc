import { unrefTimer } from '../platform.js';
import { P2PError } from '../errors.js';

/** Structured ownership for every asynchronous task started by the library. */
export class TaskGroup {
  readonly controller = new AbortController();
  readonly signal: globalThis.AbortSignal = this.controller.signal;
  private readonly tasks = new Set<Promise<unknown>>();
  private generation = 0;
  private closing = false;
  private draining = false;
  private readonly joins = new Set<(error?: unknown) => void>();

  constructor(readonly name: string) {}

  get size(): number {
    return this.tasks.size;
  }

  run<T>(operation: (signal: AbortSignal) => Promise<T> | T): Promise<T> {
    if (this.closing) {
      const rejected = Promise.reject<T>(
        this.signal.reason ?? new P2PError('DISCONNECTED', `${this.name} is closing`)
      );
      // Several internal races intentionally attempt run() after an abort and
      // discard the result. Observe that expected rejection without changing
      // the promise returned to callers which do await it.
      void rejected.catch(() => undefined);
      return rejected;
    }
    const task = Promise.resolve().then(() => {
      this.signal.throwIfAborted();
      return operation(this.signal);
    });
    this.own(task);
    return task;
  }

  /** Track an already-started operation until it settles. */
  track<T>(task: Promise<T>): Promise<T> {
    // Closing prevents new library work through run(), but an operation which
    // has already started remains ours to account for. In particular, timeout
    // and cancellation paths commonly discover native/application work only
    // while unwinding shutdown.
    this.own(task);
    return task;
  }

  abort(reason: unknown = new P2PError('CANCELLED', `${this.name} was cancelled`)): void {
    if (this.signal.aborted) return;
    this.closing = true;
    this.controller.abort(reason);
  }

  async close(reason?: unknown, options: TaskGroupJoinOptions = {}): Promise<void> {
    this.abort(reason);
    await this.join(options);
  }

  join(options: TaskGroupJoinOptions = {}): Promise<void> {
    this.closing = true;
    validateJoinOptions(options);
    return new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const finish = (error?: unknown): void => {
        this.joins.delete(finish);
        if (timer) clearTimeout(timer);
        options.signal?.removeEventListener('abort', cancel);
        if (error === undefined) resolve();
        else reject(error);
      };
      const cancel = (): void => finish(
        options.signal?.reason ?? new P2PError('CANCELLED', `${this.name} join was cancelled`)
      );
      if (options.signal?.aborted) { cancel(); return; }
      this.joins.add(finish);
      options.signal?.addEventListener('abort', cancel, { once: true });
      if (options.timeoutMs !== undefined) {
        timer = setTimeout(() => finish(
          new P2PError('TIMEOUT', `${this.name} did not settle during shutdown`)
        ), options.timeoutMs);
        unrefTimer(timer);
      }
      if (!this.draining) {
        this.draining = true;
        void this.drain().catch(error => this.finishJoins(error));
      }
    });
  }

  private finishJoins(error?: unknown): void {
    this.draining = false;
    for (const join of [...this.joins]) join(error);
  }

  private async drain(): Promise<void> {
    // An abort can reveal already-started native work in the same or following
    // microtask. Require two consecutive empty epochs before linearizing a
    // successful join, while still allowing track() after a timed-out join.
    let emptyGeneration: number | undefined;
    while (true) {
      await Promise.resolve();
      if (this.tasks.size === 0) {
        if (emptyGeneration === this.generation) {
          // Linearize all current joins in this same empty observation. A later
          // join starts a new drain, even if promise observers have not run yet.
          this.finishJoins();
          return;
        }
        emptyGeneration = this.generation;
        continue;
      }
      emptyGeneration = undefined;
      await Promise.allSettled([...this.tasks]);
    }
  }

  private own(task: Promise<unknown>): void {
    if (this.tasks.has(task)) return;
    this.tasks.add(task);
    this.generation += 1;
    void task.finally(() => this.tasks.delete(task)).catch(() => undefined);
  }
}

export interface TaskGroupJoinOptions {
  /** Reject this wait without erasing still-active tasks. Omit to wait indefinitely. */
  readonly timeoutMs?: number;
  /** Cancel only this wait; the owned tasks and a later join remain intact. */
  readonly signal?: AbortSignal;
}

function validateJoinOptions(options: TaskGroupJoinOptions): void {
  if (
    options.timeoutMs !== undefined &&
    (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1 || options.timeoutMs > 10 * 60_000)
  ) {
    throw new P2PError('RESOURCE_LIMIT', 'Task-group join timeout must be between 1 ms and 10 minutes');
  }
  if (options.signal !== undefined && !(options.signal instanceof AbortSignal)) {
    throw new P2PError('INVALID_FRAME', 'Task-group join signal is invalid');
  }
}
