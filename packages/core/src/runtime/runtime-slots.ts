import { P2PError } from '../errors.js';

interface RuntimeSlotState<TRuntime> {
  runtime?: TRuntime;
  claims: number;
}

/**
 * Bounds runtime ownership by distinct endpoint ID. A pending admission and a
 * committed runtime for the same endpoint consume one shared slot.
 */
export class RuntimeSlotRegistry<TRuntime> {
  private readonly entries = new Map<string, RuntimeSlotState<TRuntime>>();
  private readonly emptyWaiters = new Set<() => void>();
  private live = 0;
  private closed?: P2PError;

  constructor(readonly capacity: number) {
    if (!Number.isSafeInteger(capacity) || capacity < 1) {
      throw new P2PError('RESOURCE_LIMIT', 'Runtime-slot capacity must be a positive safe integer');
    }
  }

  /** Number of committed runtimes. Pending claims are intentionally excluded. */
  get size(): number {
    return this.live;
  }

  /** Number of distinct endpoint IDs which currently own or reserve a slot. */
  get occupied(): number {
    return this.entries.size;
  }

  get(peerId: string): TRuntime | undefined {
    return this.entries.get(peerId)?.runtime;
  }

  has(peerId: string): boolean {
    return this.entries.get(peerId)?.runtime !== undefined;
  }

  *values(): IterableIterator<TRuntime> {
    for (const entry of this.entries.values()) {
      if (entry.runtime !== undefined) yield entry.runtime;
    }
  }

  reserve(peerId: string): RuntimeSlotClaim<TRuntime> {
    this.assertOpen();
    validatePeerId(peerId);
    let entry = this.entries.get(peerId);
    if (!entry) {
      if (this.entries.size >= this.capacity) {
        throw new P2PError('RESOURCE_LIMIT', 'Peer runtime limit reached');
      }
      entry = { claims: 0 };
      this.entries.set(peerId, entry);
    }
    entry.claims += 1;
    return new RuntimeSlotClaim(this, peerId, entry);
  }

  delete(peerId: string, expected: TRuntime): boolean {
    const entry = this.entries.get(peerId);
    if (!entry || entry.runtime !== expected) return false;
    delete entry.runtime;
    this.live -= 1;
    this.compact(peerId, entry);
    return true;
  }

  close(reason = new P2PError('DISCONNECTED', 'Runtime registry is closed')): void {
    this.closed ??= reason;
    this.notifyEmpty();
  }

  whenEmpty(): Promise<void> {
    if (this.entries.size === 0) return Promise.resolve();
    return new Promise<void>((resolve) => this.emptyWaiters.add(resolve));
  }

  commit(peerId: string, entry: RuntimeSlotState<TRuntime>, runtime: TRuntime): void {
    this.assertOpen();
    if (this.entries.get(peerId) !== entry || entry.claims < 1) {
      throw new P2PError('INTERNAL', 'Runtime-slot claim is no longer active');
    }
    if (entry.runtime !== undefined) {
      throw new P2PError('INTERNAL', 'Runtime slot already has a committed owner');
    }
    entry.runtime = runtime;
    this.live += 1;
  }

  release(peerId: string, entry: RuntimeSlotState<TRuntime>): void {
    if (this.entries.get(peerId) !== entry || entry.claims < 1) return;
    entry.claims -= 1;
    this.compact(peerId, entry);
  }

  private compact(peerId: string, entry: RuntimeSlotState<TRuntime>): void {
    if (entry.claims === 0 && entry.runtime === undefined) this.entries.delete(peerId);
    this.notifyEmpty();
  }

  private notifyEmpty(): void {
    if (this.entries.size !== 0) return;
    for (const resolve of this.emptyWaiters) resolve();
    this.emptyWaiters.clear();
  }

  private assertOpen(): void {
    if (this.closed) throw this.closed;
  }
}

export class RuntimeSlotClaim<TRuntime> {
  private active = true;
  private committed = false;

  constructor(
    private readonly registry: RuntimeSlotRegistry<TRuntime>,
    readonly peerId: string,
    private readonly entry: RuntimeSlotState<TRuntime>
  ) {}

  commit(runtime: TRuntime): void {
    if (!this.active || this.committed) {
      throw new P2PError('INTERNAL', 'Runtime-slot claim cannot be committed twice');
    }
    this.registry.commit(this.peerId, this.entry, runtime);
    this.committed = true;
  }

  release(): void {
    if (!this.active) return;
    this.active = false;
    this.registry.release(this.peerId, this.entry);
  }
}

function validatePeerId(value: unknown): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value) > 2_048) {
    throw new P2PError('INVALID_FRAME', 'Invalid runtime-slot peer ID');
  }
}
