import { createHash, randomBytes } from 'node:crypto';
import { P2PError } from '../errors.js';
import type {
  FilePrincipalIdentity,
  FileSource,
  PeerSharePolicy,
  SharePolicy,
  SharedFileHandle
} from './types.js';
import { hasControlCharacters } from './validation.js';

interface NormalizedSharePolicy {
  readonly expiresAt: number;
  readonly allowedPeerIds?: ReadonlySet<string>;
  readonly allowedPrincipalBindings?: ReadonlySet<string>;
  readonly allowedSubjects?: ReadonlySet<string>;
  readonly maxDownloads: number;
}

interface ShareEntry<TMetadata> {
  readonly source: FileSource<TMetadata>;
  readonly policy: NormalizedSharePolicy;
  readonly operations: Map<string, ShareOperation>;
  readonly activeReservations: Set<AbortController>;
}

interface ShareOperation {
  readonly peerId: string;
  readonly principalBinding: string;
  readonly fingerprint: string;
  state: 'active' | 'reconnectable' | 'completed';
  generation: number;
  attempts: number;
  reconnectUntil?: number;
}

export interface ShareRegistryOptions {
  readonly defaultTtlMs?: number;
  readonly maxTtlMs?: number;
  /** Maximum window after the first disconnect in which the same operation may reconnect. */
  readonly reconnectLeaseMs?: number;
  /** Maximum reconnect reservations after the initial reservation. Defaults to five. */
  readonly maxReconnects?: number;
  readonly maxEntries?: number;
  readonly now?: () => number;
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
  private readonly now: () => number;

  constructor(options: ShareRegistryOptions = {}) {
    if (typeof options !== 'object' || options === null || Array.isArray(options)) {
      throw new P2PError('INVALID_FRAME', 'Shared file registry options must be an object');
    }
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
    if (options.now !== undefined && typeof options.now !== 'function') {
      throw new P2PError('INVALID_FRAME', 'Shared file registry clock must be a function');
    }
    this.now = options.now === undefined ? Date.now : options.now;
  }

  share(source: FileSource<TMetadata>, policy: SharePolicy): SharedFileHandle {
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
    this.entries.set(key, {
      source,
      policy: normalized,
      operations: new Map(),
      activeReservations: new Set()
    });
    return Object.freeze({ token, expiresAt: normalized.expiresAt });
  }

  shareForPeer(source: FileSource<TMetadata>, peerId: string, policy: PeerSharePolicy = {}): SharedFileHandle {
    return this.share(source, { ...policy, allowedPeerIds: [peerId] });
  }

  revoke(handle: SharedFileHandle): boolean {
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
    const key = capabilityId(token);
    const entry = this.entries.get(key);
    if (!entry || entry.policy.expiresAt <= now) {
      // Expiry prevents new or reconnect reservations, but an already
      // authorized operation may finish. Keep active entries addressable so an
      // explicit revoke can still abort them.
      if (entry && entry.activeReservations.size === 0) this.entries.delete(key);
      throw invalidCapability();
    }
    if (entry.policy.allowedPeerIds && !entry.policy.allowedPeerIds.has(peerId)) throw invalidCapability();
    const binding = principalBinding({ principalId, subject, issuer, clientId, tenantId });
    if (entry.policy.allowedPrincipalBindings && !entry.policy.allowedPrincipalBindings.has(binding)) throw invalidCapability();
    if (entry.policy.allowedSubjects && (!subject || !entry.policy.allowedSubjects.has(subject))) throw invalidCapability();

    let operation = entry.operations.get(operationId);
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
      operation = {
        peerId,
        principalBinding: binding,
        fingerprint,
        state: 'active',
        generation: 1,
        attempts: 1
      };
      entry.operations.set(operationId, operation);
    }
    return this.reservation(key, entry, operation, operation.generation);
  }

  private reservation(
    key: string,
    entry: ShareEntry<TMetadata>,
    operation: ShareOperation,
    generation: number
  ): ShareReservation<TMetadata> {
    let settled = false;
    const controller = new AbortController();
    entry.activeReservations.add(controller);
    const settle = (state: 'completed' | 'reconnectable'): void => {
      if (settled) return;
      settled = true;
      entry.activeReservations.delete(controller);
      const removeIfExpired = (): void => {
        if (
          this.entries.get(key) === entry &&
          entry.policy.expiresAt <= this.now() &&
          entry.activeReservations.size === 0
        ) {
          this.entries.delete(key);
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
    for (const [key, entry] of this.entries) {
      if (entry.policy.expiresAt <= now && entry.activeReservations.size === 0) this.entries.delete(key);
    }
  }

  private removeEntry(key: string, entry: ShareEntry<TMetadata>, reason: P2PError): void {
    if (!this.entries.delete(key)) return;
    for (const controller of entry.activeReservations) controller.abort(reason);
    entry.activeReservations.clear();
  }
}

function normalizePolicy(policy: SharePolicy, now: number, defaultTtlMs: number, maxTtlMs: number): NormalizedSharePolicy {
  if (typeof policy !== 'object' || policy === null || Array.isArray(policy)) {
    throw new P2PError('INVALID_FRAME', 'Shared file policy must be an object');
  }
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
  let allowedSubjects: ReadonlySet<string> | undefined;
  if (policy.allowedSubjects !== undefined) {
    if (
      !Array.isArray(policy.allowedSubjects) ||
      policy.allowedSubjects.length === 0 ||
      policy.allowedSubjects.length > 256 ||
      policy.allowedSubjects.some((subject) => !validSubject(subject))
    ) {
      throw new P2PError('INVALID_FRAME', 'Invalid shared file subject restrictions');
    }
    allowedSubjects = new Set(policy.allowedSubjects);
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
    ...(allowedPrincipalBindings ? { allowedPrincipalBindings } : {}),
    ...(allowedSubjects ? { allowedSubjects } : {})
  };
}

function validSubject(value: string): boolean {
  return validPrincipalField(value, 2048);
}

function validPrincipalId(value: string): boolean {
  return validPrincipalField(value, 2048);
}

function validFilePrincipal(value: FilePrincipalIdentity): boolean {
  return typeof value === 'object' && value !== null &&
    validPrincipalId(value.id) &&
    validSubject(value.subject) &&
    (value.issuer === undefined || validPrincipalField(value.issuer, 4096)) &&
    (value.clientId === undefined || validPrincipalField(value.clientId, 2048)) &&
    (value.tenantId === undefined || validPrincipalField(value.tenantId, 2048));
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
    .update('p2prpc-file-principal-v1\n')
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
    .update('p2prpc-file-capability-v1\n')
    .update(token, 'utf8')
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
