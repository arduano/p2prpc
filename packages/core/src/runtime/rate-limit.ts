import { P2PError } from '../errors.js';

interface Bucket { tokens: number; updatedAt: number; }

export interface HandshakeRateLimitOptions {
  readonly globalBurst: number;
  readonly globalRatePerSecond: number;
  readonly peerBurst: number;
  readonly peerRatePerSecond: number;
  readonly maxPeerEntries: number;
  readonly now?: () => number;
}

/** Bounded global + endpoint-key token buckets for pre-authentication admission. */
export class HandshakeRateLimiter {
  private readonly global: Bucket;
  private readonly peers = new Map<string, Bucket>();
  private lastNow: number;

  constructor(private readonly options: HandshakeRateLimitOptions) {
    validateOptions(options);
    this.lastNow = readNow(options.now);
    this.global = { tokens: options.globalBurst, updatedAt: this.lastNow };
  }

  admit(peerId: string): void {
    if (typeof peerId !== 'string' || peerId.length === 0 || Buffer.byteLength(peerId) > 2_048) {
      throw new P2PError('INVALID_FRAME', 'Invalid handshake peer ID');
    }
    const now = this.now();
    refill(this.global, now, this.options.globalBurst, this.options.globalRatePerSecond);
    if (this.global.tokens < 1) {
      throw new P2PError('RESOURCE_LIMIT', 'Handshake rate limit reached');
    }
    let bucket = this.peers.get(peerId);
    if (!bucket) {
      if (this.peers.size >= this.options.maxPeerEntries) this.peers.delete(this.peers.keys().next().value as string);
      bucket = { tokens: this.options.peerBurst, updatedAt: now };
      this.peers.set(peerId, bucket);
    } else {
      this.peers.delete(peerId);
      this.peers.set(peerId, bucket);
    }
    refill(bucket, now, this.options.peerBurst, this.options.peerRatePerSecond);
    if (bucket.tokens < 1) {
      throw new P2PError('RESOURCE_LIMIT', 'Peer handshake rate limit reached');
    }
    // Admission is transactional: a peer-local denial must not consume the
    // node-wide budget and starve unrelated endpoint keys.
    bucket.tokens -= 1;
    this.global.tokens -= 1;
  }

  private now(): number {
    // A wall-clock rollback must not mint a second interval of tokens when the
    // clock catches up. Clamp the logical bucket clock monotonically.
    this.lastNow = Math.max(this.lastNow, readNow(this.options.now));
    return this.lastNow;
  }
}

function refill(bucket: Bucket, now: number, burst: number, rate: number): void {
  const elapsed = Math.max(0, now - bucket.updatedAt) / 1_000;
  bucket.tokens = Math.min(burst, bucket.tokens + elapsed * rate);
  bucket.updatedAt = now;
}

function validateOptions(options: HandshakeRateLimitOptions): void {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid handshake rate-limit options');
  }
  for (const [name, value] of [
    ['globalBurst', options.globalBurst],
    ['peerBurst', options.peerBurst],
    ['maxPeerEntries', options.maxPeerEntries]
  ] as const) {
    if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid handshake rate-limit ${name}`);
    }
  }
  for (const [name, value] of [
    ['globalRatePerSecond', options.globalRatePerSecond],
    ['peerRatePerSecond', options.peerRatePerSecond]
  ] as const) {
    if (!Number.isFinite(value) || value <= 0 || value > 1_000_000) {
      throw new P2PError('RESOURCE_LIMIT', `Invalid handshake rate-limit ${name}`);
    }
  }
  if (options.now !== undefined && typeof options.now !== 'function') {
    throw new P2PError('RESOURCE_LIMIT', 'Invalid handshake rate-limit clock');
  }
}

function readNow(clock: (() => number) | undefined): number {
  const value = (clock ?? Date.now)();
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new P2PError('RESOURCE_LIMIT', 'Handshake rate-limit clock returned an invalid time');
  }
  return value;
}
