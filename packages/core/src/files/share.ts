import { createHash, randomBytes } from 'node:crypto';
import { P2PError } from '../errors.js';
import type {
  FilePrincipalIdentity,
  FileSource,
  PrincipalBoundSharePolicy,
  SharePolicy,
  SharedFileHandle
} from './types.js';
import { hasControlCharacters } from './validation.js';

interface NormalizedSharePolicy {
  readonly expiresAt: number;
  readonly allowedPeerIds?: ReadonlySet<string>;
  readonly allowedPrincipalBindings?: ReadonlySet<string>;
  readonly maxDownloads: number;
}

interface ShareEntry<TMetadata> {
  readonly source: FileSource<TMetadata>;
  readonly policy: NormalizedSharePolicy;
  readonly operations: Map<string, ShareOperation>;
  readonly activeReservations: Set<AbortController>;
  operationRecordsCounted: boolean;
}

interface ShareOperation {
  readonly peerId: string;
  readonly principalBinding: string;
  readonly fingerprint: string;
  state: 'active' | 'reconnectable' | 'completed';
  generation: number;
  attempts: number;
  reconnectUntil?: number;
  readonly controller: AbortController;
}

export interface ShareRegistryOptions {
  readonly defaultTtlMs?: number;
  readonly maxTtlMs?: number;
  /** Maximum window after the first disconnect in which the same operation may reconnect. */
  readonly reconnectLeaseMs?: number;
  /** Maximum reconnect reservations after the initial reservation. Defaults to five. */
  readonly maxReconnects?: number;
  readonly maxEntries?: number;
  /** Global maximum capability-operation records across every share. */
  readonly maxOperations?: number;
  readonly now?: () => number;
}

/** Credential-free gauges for capability lifecycle and leak validation. */
export interface ShareRegistryDiagnostics {
  readonly activeShares: number;
  readonly operationRecords: number;
  readonly activeReservations: number;
  readonly expiryRecords: number;
  readonly maxShares: number;
  readonly maxOperationRecords: number;
  readonly closed: boolean;
}

interface ExpiryItem<TMetadata> {
  readonly expiresAt: number;
  readonly key: string;
  readonly entry: ShareEntry<TMetadata>;
  index: number;
}

export interface ShareReservation<TMetadata = unknown> {
  readonly source: FileSource<TMetadata>;
  /** Aborts immediately if the capability is actively revoked. */
  readonly signal: AbortSignal;
  /** Permanently closes this operation after success or any non-retryable failure. */
  complete(): void;
  /** Allows this operation to reconnect only within its fixed, bounded disconnect lease. */
  release(): void;
}

export interface ShareOperationStatus {
  readonly state: 'active' | 'reconnectable' | 'completed';
}

export interface ShareReservationRequest {
  readonly peerId: string;
  readonly principalId: string;
  readonly subject?: string;
  readonly issuer?: string;
  readonly clientId?: string;
  readonly tenantId?: string;
  /** Stable negotiated parameters which must not change across reconnects. */
  readonly fingerprint: string;
  readonly operationId: string;
}

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const OPERATION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;

export class ShareRegistry<TMetadata = unknown> {
  private readonly entries = new Map<string, ShareEntry<TMetadata>>();
  private readonly defaultTtlMs: number;
  private readonly maxTtlMs: number;
  private readonly reconnectLeaseMs: number;
  private readonly maxReconnects: number;
  private readonly maxEntries: number;
  private readonly maxOperations: number;
  private readonly now: () => number;
  private readonly expiryHeap: Array<ExpiryItem<TMetadata>> = [];
  private readonly expiryItems = new Map<ShareEntry<TMetadata>, ExpiryItem<TMetadata>>();
  private operationCount = 0;
  private activeReservationCount = 0;
  private closed: P2PError | undefined;

  constructor(options: ShareRegistryOptions = {}) {
    if (!isPlainObject(options)) {
      throw new P2PError('INVALID_FRAME', 'Shared file registry options must be an object');
    }
    assertOnlyKeys(
      options,
      ['defaultTtlMs', 'maxTtlMs', 'reconnectLeaseMs', 'maxReconnects', 'maxEntries', 'maxOperations', 'now'],
      'Shared file registry options'
    );
    this.defaultTtlMs = validateDuration(
      options.defaultTtlMs === undefined ? 5 * 60_000 : options.defaultTtlMs,
      'default share lifetime'
    );
    this.maxTtlMs = validateDuration(
      options.maxTtlMs === undefined ? 60 * 60_000 : options.maxTtlMs,
      'maximum share lifetime'
    );
    if (this.defaultTtlMs > this.maxTtlMs) {
      throw new P2PError('RESOURCE_LIMIT', 'Default share lifetime exceeds the maximum share lifetime');
    }
    this.reconnectLeaseMs = validateDuration(
      options.reconnectLeaseMs === undefined ? 30_000 : options.reconnectLeaseMs,
      'file reconnect lease'
    );
    this.maxReconnects = validateNonNegativeInteger(
      options.maxReconnects === undefined ? 5 : options.maxReconnects,
      'maximum file reconnect count',
      100
    );
    this.maxEntries = validatePositiveInteger(
      options.maxEntries === undefined ? 10_000 : options.maxEntries,
      'maximum share count',
      1_000_000
    );
    this.maxOperations = validatePositiveInteger(
      options.maxOperations === undefined ? 10_000 : options.maxOperations,
      'maximum capability operation count',
      1_000_000
    );
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new P2PError('INVALID_FRAME', 'Shared file registry clock must be a function');
    }
    this.now = options.now === undefined ? Date.now : options.now;
  }

  diagnostics(): ShareRegistryDiagnostics {
    if (!this.closed) this.removeExpired(this.now());
    return Object.freeze({
      activeShares: this.entries.size,
      operationRecords: this.operationCount,
      activeReservations: this.activeReservationCount,
      expiryRecords: this.expiryHeap.length,
      maxShares: this.maxEntries,
      maxOperationRecords: this.maxOperations,
      closed: this.closed !== undefined
    });
  }

  share(source: FileSource<TMetadata>, policy: SharePolicy): SharedFileHandle {
    this.assertOpen();
    const now = this.now();
    this.removeExpired(now);
    if (this.entries.size >= this.maxEntries) throw new P2PError('RESOURCE_LIMIT', 'Shared file registry is full');
    const normalized = normalizePolicy(policy, now, this.defaultTtlMs, this.maxTtlMs);
    let token: string;
    let key: string;
    do {
      token = randomBytes(32).toString('base64url');
      key = capabilityId(token);
    } while (this.entries.has(key));
    const entry: ShareEntry<TMetadata> = {
      source,
      policy: normalized,
      operations: new Map(),
      activeReservations: new Set(),
      operationRecordsCounted: true
    };
    this.entries.set(key, entry);
    this.pushExpiry({ expiresAt: normalized.expiresAt, key, entry, index: -1 });
    return Object.freeze({ token, expiresAt: normalized.expiresAt });
  }

  shareForPeer(
    source: FileSource<TMetadata>,
    peerId: string,
    policy: PrincipalBoundSharePolicy = {},
    expectedPrincipal?: FilePrincipalIdentity
  ): SharedFileHandle {
    if (!isPlainObject(policy)) throw new P2PError('INVALID_FRAME', 'Peer share policy must be an object');
    assertOnlyKeys(policy, ['expiresAt', 'allowedPrincipals', 'maxDownloads'], 'Peer share policy');
    if (expectedPrincipal !== undefined && policy.allowedPrincipals !== undefined) {
      throw new P2PError('INVALID_FRAME', 'Peer-bound sharing cannot override its authenticated principal binding');
    }
    if (expectedPrincipal !== undefined && !validFilePrincipal(expectedPrincipal)) {
      throw new P2PError('INVALID_FRAME', 'Invalid authenticated principal binding');
    }
    return this.share(source, {
      ...policy,
      ...(expectedPrincipal !== undefined ? { allowedPrincipals: [expectedPrincipal] } : {}),
      allowedPeerIds: [peerId]
    });
  }

  revoke(handle: SharedFileHandle): boolean {
    if (this.closed) return false;
    if (!isPlainObject(handle) || !hasOnlyKeys(handle, ['token', 'expiresAt'])) return false;
    if (!TOKEN_PATTERN.test(handle.token)) return false;
    const key = capabilityId(handle.token);
    const entry = this.entries.get(key);
    if (!entry) return false;
    this.removeEntry(key, entry, new P2PError('UNAUTHORIZED', 'Shared file capability was revoked'));
    return true;
  }

  /**
   * Atomically reserves a capability operation. An operation can have only one
   * active reservation and becomes terminal after completion. A disconnected
   * reservation may reconnect during one fixed, bounded lease.
   */
  reserve(token: string, request: ShareReservationRequest): ShareReservation<TMetadata> {
    this.assertOpen();
    if (!isPlainObject(request)) throw invalidCapability();
    assertOnlyKeys(
      request,
      ['peerId', 'principalId', 'subject', 'issuer', 'clientId', 'tenantId', 'fingerprint', 'operationId'],
      'File capability reservation'
    );
    const { peerId, principalId, subject, issuer, clientId, tenantId, fingerprint, operationId } = request;
    if (
      !TOKEN_PATTERN.test(token) ||
      !validPeerId(peerId) ||
      !validPrincipalId(principalId) ||
      (subject !== undefined && !validSubject(subject)) ||
      (issuer !== undefined && !validPrincipalField(issuer, 4096)) ||
      (clientId !== undefined && !validPrincipalField(clientId, 2048)) ||
      (tenantId !== undefined && !validPrincipalField(tenantId, 2048)) ||
      !validFingerprint(fingerprint)
    ) {
      throw invalidCapability();
    }
    if (!OPERATION_PATTERN.test(operationId)) {
      throw new P2PError('INVALID_FRAME', 'Invalid file capability operation ID');
    }
    const now = this.now();
    this.removeExpired(now);
    const key = capabilityId(token);
    const entry = this.entries.get(key);
    if (!entry || entry.policy.expiresAt <= now) {
      // Expiry prevents new or reconnect reservations, but an already
      // authorized operation may finish. Keep active entries addressable so an
      // explicit revoke can still abort them.
      if (entry && entry.activeReservations.size === 0) this.deleteEntry(key, entry);
      throw invalidCapability();
    }
    if (entry.policy.allowedPeerIds && !entry.policy.allowedPeerIds.has(peerId)) throw invalidCapability();
    const binding = principalBinding({ principalId, subject, issuer, clientId, tenantId });
    if (entry.policy.allowedPrincipalBindings && !entry.policy.allowedPrincipalBindings.has(binding)) throw invalidCapability();

    const operationKey = operationIdHash(operationId);
    let operation = entry.operations.get(operationKey);
    if (operation !== undefined) {
      if (
        operation.peerId !== peerId ||
        operation.principalBinding !== binding ||
        operation.fingerprint !== fingerprint
      ) {
        throw invalidCapability();
      }
      if (
        operation.state !== 'reconnectable' ||
        operation.reconnectUntil === undefined ||
        operation.reconnectUntil <= now ||
        operation.attempts > this.maxReconnects
      ) {
        if (operation.state === 'reconnectable') operation.state = 'completed';
        throw invalidCapability();
      }
      operation.state = 'active';
      operation.generation += 1;
      operation.attempts += 1;
    } else {
      if (entry.operations.size >= entry.policy.maxDownloads) throw invalidCapability();
      if (this.operationCount >= this.maxOperations) {
        throw new P2PError('RESOURCE_LIMIT', 'Shared file capability operation limit reached');
      }
      operation = {
        peerId,
        principalBinding: binding,
        fingerprint,
        state: 'active',
        generation: 1,
        attempts: 1,
        controller: new AbortController()
      };
      entry.operations.set(operationKey, operation);
      this.operationCount += 1;
    }
    return this.reservation(key, entry, operation, operation.generation);
  }

  /** Same-process reconciliation for a previously dispatched capability operation. */
  operationStatus(token: string, operationId: string): ShareOperationStatus | undefined {
    if (this.closed || !TOKEN_PATTERN.test(token) || !OPERATION_PATTERN.test(operationId)) return undefined;
    this.removeExpired(this.now());
    const entry = this.entries.get(capabilityId(token));
    const operation = entry?.operations.get(operationIdHash(operationId));
    return operation ? Object.freeze({ state: operation.state }) : undefined;
  }

  /** Revokes all capabilities and permanently prevents new state admission. */
  close(reason = new P2PError('DISCONNECTED', 'Shared file registry is closed')): void {
    if (this.closed) return;
    this.closed = reason;
    for (const [key, entry] of [...this.entries]) this.removeEntry(key, entry, reason);
  }

  private reservation(
    key: string,
    entry: ShareEntry<TMetadata>,
    operation: ShareOperation,
    generation: number
  ): ShareReservation<TMetadata> {
    let settled = false;
    const controller = operation.controller;
    entry.activeReservations.add(controller);
    this.activeReservationCount += 1;
    const settle = (state: 'completed' | 'reconnectable'): void => {
      if (settled) return;
      settled = true;
      entry.activeReservations.delete(controller);
      this.activeReservationCount -= 1;
      if (this.entries.get(key) !== entry && entry.activeReservations.size === 0) {
        this.releaseOperationRecords(entry);
      }
      const removeIfExpired = (): void => {
        if (
          this.entries.get(key) === entry &&
          entry.policy.expiresAt <= this.now() &&
          entry.activeReservations.size === 0
        ) {
          this.deleteEntry(key, entry);
        }
      };
      if (operation.state !== 'active' || operation.generation !== generation) return;
      if (state === 'completed') {
        operation.state = 'completed';
        removeIfExpired();
        return;
      }
      const now = this.now();
      operation.reconnectUntil ??= Math.min(entry.policy.expiresAt, now + this.reconnectLeaseMs);
      operation.state = operation.reconnectUntil > now ? 'reconnectable' : 'completed';
      removeIfExpired();
    };
    return Object.freeze({
      source: entry.source,
      signal: controller.signal,
      complete: () => settle('completed'),
      release: () => settle('reconnectable')
    });
  }

  private removeExpired(now: number): void {
    while (this.expiryHeap[0]?.expiresAt !== undefined && this.expiryHeap[0].expiresAt <= now) {
      const expired = this.popExpiry()!;
      if (this.entries.get(expired.key) !== expired.entry) continue;
      if (expired.entry.activeReservations.size === 0) this.deleteEntry(expired.key, expired.entry);
    }
  }

  private removeEntry(key: string, entry: ShareEntry<TMetadata>, reason: P2PError): void {
    if (!this.deleteEntry(key, entry)) return;
    for (const operation of entry.operations.values()) operation.controller.abort(reason);
  }

  private deleteEntry(key: string, entry: ShareEntry<TMetadata>): boolean {
    if (this.entries.get(key) !== entry || !this.entries.delete(key)) return false;
    this.removeExpiry(entry);
    if (entry.activeReservations.size === 0) this.releaseOperationRecords(entry);
    return true;
  }

  private releaseOperationRecords(entry: ShareEntry<TMetadata>): void {
    if (!entry.operationRecordsCounted) return;
    entry.operationRecordsCounted = false;
    this.operationCount -= entry.operations.size;
  }

  private assertOpen(): void {
    if (this.closed) throw this.closed;
  }

  private pushExpiry(item: ExpiryItem<TMetadata>): void {
    let index = this.expiryHeap.push(item) - 1;
    this.expiryItems.set(item.entry, item);
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (this.expiryHeap[parent]!.expiresAt <= item.expiresAt) break;
      this.expiryHeap[index] = this.expiryHeap[parent]!;
      this.expiryHeap[index]!.index = index;
      index = parent;
    }
    this.expiryHeap[index] = item;
    item.index = index;
  }

  private popExpiry(): ExpiryItem<TMetadata> | undefined {
    return this.removeExpiryAt(0);
  }

  private removeExpiry(entry: ShareEntry<TMetadata>): void {
    const item = this.expiryItems.get(entry);
    if (item) this.removeExpiryAt(item.index);
  }

  private removeExpiryAt(index: number): ExpiryItem<TMetadata> | undefined {
    const removed = this.expiryHeap[index];
    if (!removed) return undefined;
    const last = this.expiryHeap.pop()!;
    this.expiryItems.delete(removed.entry);
    removed.index = -1;
    if (removed === last) return removed;
    this.expiryHeap[index] = last;
    last.index = index;
    const parent = index > 0 ? Math.floor((index - 1) / 2) : -1;
    if (parent >= 0 && this.expiryHeap[parent]!.expiresAt > last.expiresAt) {
      while (index > 0) {
        const nextParent = Math.floor((index - 1) / 2);
        if (this.expiryHeap[nextParent]!.expiresAt <= last.expiresAt) break;
        this.expiryHeap[index] = this.expiryHeap[nextParent]!;
        this.expiryHeap[index]!.index = index;
        index = nextParent;
      }
      this.expiryHeap[index] = last;
      last.index = index;
      return removed;
    }
    while (true) {
      const left = index * 2 + 1;
      if (left >= this.expiryHeap.length) break;
      const right = left + 1;
      const child = right < this.expiryHeap.length &&
        this.expiryHeap[right]!.expiresAt < this.expiryHeap[left]!.expiresAt
        ? right
        : left;
      if (this.expiryHeap[child]!.expiresAt >= last.expiresAt) break;
      this.expiryHeap[index] = this.expiryHeap[child]!;
      this.expiryHeap[index]!.index = index;
      index = child;
    }
    this.expiryHeap[index] = last;
    last.index = index;
    return removed;
  }
}

function normalizePolicy(policy: SharePolicy, now: number, defaultTtlMs: number, maxTtlMs: number): NormalizedSharePolicy {
  if (!isPlainObject(policy)) {
    throw new P2PError('INVALID_FRAME', 'Shared file policy must be an object');
  }
  assertOnlyKeys(
    policy,
    ['expiresAt', 'allowedPrincipals', 'maxDownloads', 'allowedPeerIds', 'allowBearer'],
    'Shared file policy'
  );
  const peers = policy.allowedPeerIds;
  let allowedPeerIds: ReadonlySet<string> | undefined;
  if (peers !== undefined) {
    if (!Array.isArray(peers) || peers.length === 0 || peers.length > 256 || peers.some((peerId) => !validPeerId(peerId))) {
      throw new P2PError('INVALID_FRAME', 'Invalid shared file peer restrictions');
    }
    allowedPeerIds = new Set(peers);
  }
  if (!allowedPeerIds && policy.allowBearer !== true) {
    throw new P2PError('UNAUTHORIZED', 'A shared file must be peer-bound unless allowBearer is explicitly enabled');
  }
  let allowedPrincipalBindings: ReadonlySet<string> | undefined;
  if (policy.allowedPrincipals !== undefined) {
    if (
      !Array.isArray(policy.allowedPrincipals) ||
      policy.allowedPrincipals.length === 0 ||
      policy.allowedPrincipals.length > 256 ||
      policy.allowedPrincipals.some((principal) => !validFilePrincipal(principal))
    ) {
      throw new P2PError('INVALID_FRAME', 'Invalid shared file principal restrictions');
    }
    allowedPrincipalBindings = new Set(policy.allowedPrincipals.map((principal) => principalBinding({
      principalId: principal.id,
      subject: principal.subject,
      issuer: principal.issuer,
      clientId: principal.clientId,
      tenantId: principal.tenantId
    })));
  }
  const expiresAt = policy.expiresAt === undefined ? now + defaultTtlMs : policy.expiresAt;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt - now > maxTtlMs) {
    throw new P2PError('RESOURCE_LIMIT', 'Shared file expiry is invalid or exceeds the maximum lifetime');
  }
  const maxDownloads = validatePositiveInteger(
    policy.maxDownloads === undefined ? 1 : policy.maxDownloads,
    'shared file download count',
    10_000
  );
  return {
    expiresAt,
    maxDownloads,
    ...(allowedPeerIds ? { allowedPeerIds } : {}),
    ...(allowedPrincipalBindings ? { allowedPrincipalBindings } : {})
  };
}

function validSubject(value: string): boolean {
  return validPrincipalField(value, 2048);
}

function validPrincipalId(value: string): boolean {
  return validPrincipalField(value, 2048);
}

function validFilePrincipal(value: FilePrincipalIdentity): boolean {
  return isPlainObject(value) &&
    hasOnlyKeys(value, ['id', 'subject', 'issuer', 'clientId', 'tenantId', 'expiresAt', 'scopes', 'claims']) &&
    validPrincipalId(value.id) &&
    validSubject(value.subject) &&
    (value.issuer === undefined || validPrincipalField(value.issuer, 4096)) &&
    (value.clientId === undefined || validPrincipalField(value.clientId, 2048)) &&
    (value.tenantId === undefined || validPrincipalField(value.tenantId, 2048));
}

function isPlainObject(value: unknown): boolean {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasOnlyKeys(value: object, allowed: readonly string[]): boolean {
  const keys = new Set(allowed);
  return Object.keys(value).every((key) => keys.has(key));
}

function assertOnlyKeys(value: object, allowed: readonly string[], label: string): void {
  if (!hasOnlyKeys(value, allowed)) {
    throw new P2PError('INVALID_FRAME', `${label} contains an unknown field`);
  }
}

function validPrincipalField(value: unknown, maximumBytes: number): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value) <= maximumBytes &&
    !hasControlCharacters(value);
}

function principalBinding(value: {
  readonly principalId: string;
  readonly subject: string | undefined;
  readonly issuer: string | undefined;
  readonly clientId: string | undefined;
  readonly tenantId: string | undefined;
}): string {
  return createHash('sha256')
    .update('p2prpc-file-principal-v3\n')
    .update(JSON.stringify([
      value.principalId,
      value.issuer ?? null,
      value.subject ?? null,
      value.clientId ?? null,
      value.tenantId ?? null
    ]))
    .digest('base64url');
}

function validFingerprint(value: string): boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !hasControlCharacters(value);
}

/** A non-secret stable identifier suitable for authorization and audit records. */
export function capabilityId(token: string): string {
  return createHash('sha256')
    .update('p2prpc-file-capability-v3\n')
    .update(token, 'utf8')
    .digest('base64url');
}

function operationIdHash(operationId: string): string {
  return createHash('sha256')
    .update('p2prpc-file-operation-v3\n')
    .update(operationId, 'utf8')
    .digest('base64url');
}

function invalidCapability(): P2PError {
  return new P2PError('UNAUTHORIZED', 'Shared file capability is invalid or unavailable');
}

function validPeerId(value: string): boolean {
  return typeof value === 'string' && value.length > 0 && value.length <= 512 && !hasControlCharacters(value);
}

function validateDuration(value: number, label: string): number {
  return validatePositiveInteger(value, label, 24 * 60 * 60_000);
}

function validatePositiveInteger(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `Invalid ${label}: ${String(value)}`);
  }
  return value;
}

function validateNonNegativeInteger(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `Invalid ${label}: ${String(value)}`);
  }
  return value;
}
