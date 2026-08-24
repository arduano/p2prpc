import type { FileManifest } from '../files/types.js';
import type { RpcHeaders } from '../rpc/headers.js';
import { containsUnsafeDisplayCharacters } from '../text.js';

export interface SessionCredential {
  /** Credential scheme understood by the configured authenticator. */
  readonly scheme: string;
  /** Secret credential material. It is sent only inside the encrypted session handshake. */
  readonly value: string;
}

export interface SessionPrincipal {
  /** Stable local identifier for authorization and audit records. */
  readonly id: string;
  /** OAuth/OIDC subject, service-account ID, or equivalent identity. */
  readonly subject: string;
  readonly issuer?: string;
  /** Verified OAuth client_id/azp identifying the authorized calling application. */
  readonly clientId?: string;
  readonly tenantId?: string;
  /** Absolute Unix time in milliseconds after which the session must stop accepting work. */
  readonly expiresAt: number;
  readonly scopes: ReadonlySet<string>;
  /** Verified claims. Never place unverified request metadata in this object. */
  readonly claims: Readonly<Record<string, unknown>>;
}

export type SessionRole = 'initiator' | 'responder';

/** Canonical immutable v3 transcript visible to credential providers and authenticators. */
export interface SessionCredentialContext {
  readonly localPeerId: string;
  readonly remotePeerId: string;
  readonly direction: 'inbound' | 'outbound';
  readonly protocol: string;
  /** The role whose credential is being produced. */
  readonly role: SessionRole;
  readonly initiatorPeerId: string;
  readonly responderPeerId: string;
  readonly initiatorNonce: string;
  readonly responderNonce: string;
  readonly initiatorPresentedAt: number;
  readonly responderPresentedAt: number;
  /** SHA-256 commitment to every preceding v3 handshake field. */
  readonly transcriptHash: string;
  /** Aborted when the handshake times out or otherwise terminates. */
  readonly signal: AbortSignal;
}

export type CredentialRequestContext = SessionCredentialContext;
export type SessionAuthenticationContext = SessionCredentialContext;

export type AuthorizationAction<TFileMetadata = unknown> =
  | {
      readonly kind: 'rpc';
      readonly path: string;
      readonly type: 'query' | 'mutation' | 'subscription';
      /** Untrusted, bounded application metadata supplied by the caller. */
      readonly headers: RpcHeaders;
    }
  | {
      readonly kind: 'file.push';
      readonly manifest: FileManifest<TFileMetadata>;
    }
  | {
      readonly kind: 'file.pull';
      /** A non-secret hash of the presented capability, suitable for audit correlation. */
      readonly capabilityId: string;
    };

export interface AuthorizationContext<TFileMetadata = unknown> {
  readonly principal: SessionPrincipal;
  readonly localPeerId: string;
  readonly remotePeerId: string;
  readonly sessionId: string;
  readonly action: AuthorizationAction<TFileMetadata>;
  /** Aborted when the authorization deadline, request, or session terminates. */
  readonly signal: AbortSignal;
}

export type AuthorizationResult = boolean | { readonly allowed: boolean; readonly reason?: string };

/**
 * Application authentication and authorization for an encrypted Iroh session.
 *
 * Implementations commonly verify short-lived OAuth access tokens, but may use
 * workload identities, mTLS-derived assertions, or an enterprise introspection
 * service. Transport peer IDs are passed into every check so credentials can be
 * proof-of-possession bound to the exact Iroh endpoint key.
 */
export interface SessionSecurity<TFileMetadata = unknown> {
  getCredential(context: CredentialRequestContext): Promise<SessionCredential> | SessionCredential;
  authenticate(
    credential: SessionCredential,
    context: SessionAuthenticationContext
  ): Promise<SessionPrincipal> | SessionPrincipal;
  authorize(context: AuthorizationContext<TFileMetadata>): Promise<AuthorizationResult> | AuthorizationResult;
}

const peerBoundSessionSecurityBrand: unique symbol = Symbol('p2prpc.peer-bound-session-security');
const peerBoundSessionSecurities = new WeakSet<object>();

/**
 * Nominal result of a root security factory whose identity is cryptographically
 * bound to the authenticated Iroh endpoint key.
 */
export interface PeerBoundSessionSecurity<TFileMetadata = unknown> extends SessionSecurity<TFileMetadata> {
  readonly [peerBoundSessionSecurityBrand]: true;
}

/** @internal Used only by reviewed root security factories. */
export function markPeerBoundSessionSecurity<TFileMetadata>(
  implementation: SessionSecurity<TFileMetadata>
): PeerBoundSessionSecurity<TFileMetadata> {
  peerBoundSessionSecurities.add(implementation);
  return Object.freeze(implementation) as PeerBoundSessionSecurity<TFileMetadata>;
}

export function isPeerBoundSessionSecurity(value: unknown): value is PeerBoundSessionSecurity<unknown> {
  return typeof value === 'object' && value !== null && peerBoundSessionSecurities.has(value);
}

export interface AuthenticatedSession {
  readonly id: string;
  readonly establishedAt: number;
  readonly expiresAt: number;
  readonly principal: SessionPrincipal;
}

export function authorizationAllowed(result: AuthorizationResult): { allowed: boolean; reason?: string } {
  if (typeof result === 'boolean') return { allowed: result };
  if (!result || typeof result !== 'object' || typeof result.allowed !== 'boolean') {
    throw new TypeError('Security authorizer returned an invalid decision');
  }
  if (result.reason !== undefined && typeof result.reason !== 'string') {
    throw new TypeError('Security authorizer returned an invalid reason');
  }
  return result.reason === undefined ? { allowed: result.allowed } : { allowed: result.allowed, reason: result.reason };
}

export function freezePrincipal(principal: SessionPrincipal): SessionPrincipal {
  if (!principal || typeof principal !== 'object') throw new TypeError('Authenticator returned an invalid principal');
  if (!validIdentityField(principal.id, 2048) || !validIdentityField(principal.subject, 2048)) {
    throw new TypeError('Authenticated principal must have bounded id and subject strings');
  }
  if (principal.issuer !== undefined && !validIdentityField(principal.issuer, 4096)) {
    throw new TypeError('Authenticated principal has an invalid issuer');
  }
  if (principal.clientId !== undefined && !validIdentityField(principal.clientId, 2048)) {
    throw new TypeError('Authenticated principal has an invalid OAuth client ID');
  }
  if (principal.tenantId !== undefined && !validIdentityField(principal.tenantId, 2048)) {
    throw new TypeError('Authenticated principal has an invalid tenant ID');
  }
  if (!Number.isSafeInteger(principal.expiresAt)) throw new TypeError('Authenticated principal must have an integer expiresAt');
  if (!isPlainRecord(principal.claims)) {
    throw new TypeError('Authenticated principal claims must be a record');
  }
  const scopeValues = snapshotScopes(principal.scopes);
  const claims = snapshotClaims(principal.claims);
  const scopes = immutableSet(scopeValues);
  return Object.freeze({
    id: principal.id,
    subject: principal.subject,
    ...(principal.issuer !== undefined ? { issuer: principal.issuer } : {}),
    ...(principal.clientId !== undefined ? { clientId: principal.clientId } : {}),
    ...(principal.tenantId !== undefined ? { tenantId: principal.tenantId } : {}),
    expiresAt: principal.expiresAt,
    scopes,
    claims
  });
}

const MAX_PRINCIPAL_SCOPES = 1024;
const MAX_SCOPE_BYTES = 1024;
const MAX_CLAIM_DEPTH = 16;
const MAX_CLAIM_ITEMS = 8192;
const MAX_CLAIM_BYTES = 64 * 1024;

function snapshotScopes(value: unknown): readonly string[] {
  if (!value || typeof value !== 'object') throw new TypeError('Authenticated principal has invalid scopes');
  let iterator: Iterator<unknown>;
  try {
    const factory = (value as { [Symbol.iterator]?: unknown })[Symbol.iterator];
    if (typeof factory !== 'function') throw new TypeError('Authenticated principal has invalid scopes');
    iterator = factory.call(value) as Iterator<unknown>;
  } catch (cause) {
    throw new TypeError('Authenticated principal has invalid scopes', { cause });
  }

  const output: string[] = [];
  try {
    for (let index = 0; index <= MAX_PRINCIPAL_SCOPES; index += 1) {
      let next: IteratorResult<unknown>;
      try {
        next = iterator.next();
      } catch (cause) {
        throw new TypeError('Authenticated principal has invalid scopes', { cause });
      }
      if (!next || typeof next !== 'object' || typeof next.done !== 'boolean') {
        throw new TypeError('Authenticated principal has invalid scopes');
      }
      if (next.done) return output;
      if (!validIdentityField(next.value, MAX_SCOPE_BYTES)) {
        throw new TypeError('Authenticated principal has invalid scopes');
      }
      output.push(next.value);
    }
    throw new TypeError('Authenticated principal has too many scopes');
  } finally {
    try {
      iterator.return?.();
    } catch {
      // The bounded snapshot has already failed closed; iterator cleanup is best effort.
    }
  }
}

function validIdentityField(value: unknown, maximumBytes: number): value is string {
  return typeof value === 'string' &&
    value.length > 0 &&
    Buffer.byteLength(value) <= maximumBytes &&
    !containsUnsafeDisplayCharacters(value);
}

function immutableSet<T>(values: Iterable<T>): ReadonlySet<T> {
  const inner = new Set(values);
  const view: ReadonlySet<T> = {
    get size() { return inner.size; },
    has: (value) => inner.has(value),
    entries: () => inner.entries(),
    keys: () => inner.keys(),
    values: () => inner.values(),
    forEach(callback, thisArg) {
      inner.forEach((value) => callback.call(thisArg, value, value, view));
    },
    [Symbol.iterator]: () => inner[Symbol.iterator]()
  };
  return Object.freeze(view);
}

interface ClaimSnapshotState {
  items: number;
  bytes: number;
  readonly seen: WeakSet<object>;
}

function snapshotClaims(value: Readonly<Record<string, unknown>>): Readonly<Record<string, unknown>> {
  const state: ClaimSnapshotState = { items: 0, bytes: 0, seen: new WeakSet() };
  return snapshotClaimValue(value, 0, state) as Readonly<Record<string, unknown>>;
}

function snapshotClaimValue(value: unknown, depth: number, state: ClaimSnapshotState): unknown {
  state.items += 1;
  consumeClaimBytes(state, 1);
  if (state.items > MAX_CLAIM_ITEMS) throw new TypeError('Authenticated claims exceed the maximum item count');
  if (depth > MAX_CLAIM_DEPTH) throw new TypeError('Authenticated claims exceed the maximum nesting depth');

  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    consumeClaimBytes(state, Buffer.byteLength(value));
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Authenticated claims must contain finite numbers');
    consumeClaimBytes(state, 8);
    return value;
  }
  if (!value || typeof value !== 'object') {
    throw new TypeError('Authenticated claims must contain only plain JSON data');
  }
  if (state.seen.has(value)) throw new TypeError('Authenticated claims must not contain cycles or aliases');
  state.seen.add(value);

  if (Array.isArray(value)) {
    if (value.length > MAX_CLAIM_ITEMS - state.items) {
      throw new TypeError('Authenticated claims exceed the maximum item count');
    }
    const copy: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
        throw new TypeError('Authenticated claim arrays must be dense plain data without accessors');
      }
      copy.push(snapshotClaimValue(descriptor.value, depth + 1, state));
    }
    return Object.freeze(copy);
  }

  if (!isPlainRecord(value)) throw new TypeError('Authenticated claims must contain only plain objects and arrays');
  if (state.items >= MAX_CLAIM_ITEMS) throw new TypeError('Authenticated claims exceed the maximum item count');
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  let ownKeys = 0;
  let scannedKeys = 0;
  // `for..in` lets us stop before materializing an attacker-controlled full
  // property-name array. The allowed prototypes have no library-owned
  // enumerable fields; inherited pollution is explicitly skipped.
  for (const key in value) {
    scannedKeys += 1;
    if (scannedKeys > MAX_CLAIM_ITEMS) {
      throw new TypeError('Authenticated claims exceed the maximum item count');
    }
    if (!Object.hasOwn(value, key)) continue;
    ownKeys += 1;
    if (ownKeys > MAX_CLAIM_ITEMS) {
      throw new TypeError('Authenticated claims exceed the maximum item count');
    }
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      throw new TypeError('Authenticated claims contain an unsafe key');
    }
    consumeClaimBytes(state, Buffer.byteLength(key));
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('Authenticated claims must not contain accessors');
    }
    copy[key] = snapshotClaimValue(descriptor.value, depth + 1, state);
  }
  return Object.freeze(copy);
}

function consumeClaimBytes(state: ClaimSnapshotState, bytes: number): void {
  state.bytes += bytes;
  if (state.bytes > MAX_CLAIM_BYTES) throw new TypeError('Authenticated claims exceed the maximum byte size');
}

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
