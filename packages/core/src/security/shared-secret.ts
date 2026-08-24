import { createHmac, timingSafeEqual } from 'node:crypto';
import { P2PError } from '../errors.js';
import type {
  AuthorizationContext,
  AuthorizationResult,
  CredentialRequestContext,
  SessionPrincipal,
  SessionSecurity
} from './types.js';
import { markPeerBoundSessionSecurity, type PeerBoundSessionSecurity } from './types.js';

export interface SharedSecretSecurityOptions<TFileMetadata = unknown> {
  readonly sessionTtlMs?: number;
  readonly clockSkewMs?: number;
  /** Authentication proves secret membership; this callback grants each operation. */
  readonly authorize: (context: AuthorizationContext<TFileMetadata>) => Promise<AuthorizationResult> | AuthorizationResult;
}

/**
 * HMAC challenge authentication for deployments that have a securely
 * provisioned application secret but no OIDC issuer. Each side proves the
 * secret over the complete role-specific v3 challenge transcript, including
 * both fresh nonces and both authenticated Iroh IDs.
 */
export function createSharedSecretSecurity<TFileMetadata = unknown>(
  secret: Uint8Array | string,
  options: SharedSecretSecurityOptions<TFileMetadata>
): PeerBoundSessionSecurity<TFileMetadata> {
  validateOptions(options, ['sessionTtlMs', 'clockSkewMs', 'authorize'], 'Shared-secret security options');
  if (typeof options.authorize !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'Shared-secret authorize policy is required and must be a function');
  }
  const customAuthorize = options.authorize;
  const key = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : Buffer.from(secret);
  if (key.byteLength < 32) throw new P2PError('INVALID_FRAME', 'Session shared secret must contain at least 32 bytes');
  const ttl = options.sessionTtlMs === undefined ? 15 * 60_000 : options.sessionTtlMs;
  const skew = options.clockSkewMs === undefined ? 30_000 : options.clockSkewMs;
  validateDuration(ttl, 'Session TTL', 24 * 60 * 60_000);
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 10 * 60_000) {
    throw new P2PError('RESOURCE_LIMIT', 'Shared-secret clock skew must be between 0 and 10 minutes');
  }

  return markPeerBoundSessionSecurity({
    getCredential(context) {
      validateContextRole(context, context.localPeerId);
      const timestamp = Date.now();
      return {
        scheme: 'P2PRPC-HMAC-SHA256',
        value: `${timestamp}.${mac(key, context, timestamp)}`
      };
    },
    authenticate(credential, context) {
      if (credential.scheme !== 'P2PRPC-HMAC-SHA256') throw new P2PError('UNAUTHORIZED', 'Unsupported session credential');
      validateContextRole(context, context.remotePeerId);
      const separator = credential.value.indexOf('.');
      const timestamp = Number(credential.value.slice(0, separator));
      const received = credential.value.slice(separator + 1);
      if (separator < 1 || !Number.isSafeInteger(timestamp) || Math.abs(Date.now() - timestamp) > skew) {
        throw new P2PError('UNAUTHORIZED', 'Session credential is stale');
      }
      const expected = mac(key, context, timestamp);
      if (!safeEqual(received, expected)) throw new P2PError('UNAUTHORIZED', 'Invalid session credential');
      const principal: SessionPrincipal = {
        id: context.remotePeerId,
        subject: context.remotePeerId,
        expiresAt: Date.now() + ttl,
        scopes: new Set(['p2prpc:*']),
        claims: Object.freeze({ authentication: 'shared-secret' })
      };
      return principal;
    },
    authorize(context) {
      // Authentication and authorization are intentionally separate. A
      // shared secret proves membership only; policy must grant each action.
      return customAuthorize(context);
    }
  });
}

/** Explicit test/development escape hatch. Never use this in production. */
export function dangerouslyAllowInsecureSessions<TFileMetadata = unknown>(options: { sessionTtlMs?: number } = {}): SessionSecurity<TFileMetadata> {
  validateOptions(options, ['sessionTtlMs'], 'Insecure session options');
  const ttl = options.sessionTtlMs === undefined ? 60 * 60_000 : options.sessionTtlMs;
  validateDuration(ttl, 'Insecure session TTL', 24 * 60 * 60_000);
  return {
    getCredential: () => ({ scheme: 'P2PRPC-INSECURE', value: 'explicitly-insecure' }),
    authenticate(credential, context) {
      if (credential.scheme !== 'P2PRPC-INSECURE' || credential.value !== 'explicitly-insecure') {
        throw new P2PError('UNAUTHORIZED', 'Invalid insecure development credential');
      }
      return {
        id: context.remotePeerId,
        subject: context.remotePeerId,
        expiresAt: Date.now() + ttl,
        scopes: new Set(['p2prpc:*']),
        claims: Object.freeze({ authentication: 'insecure-development-only' })
      };
    },
    authorize: () => true
  };
}

function validateOptions(value: unknown, allowed: readonly string[], label: string): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new P2PError('INVALID_FRAME', `${label} contains an unknown field`);
  }
}

function validateDuration(value: number, label: string, maximum: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new P2PError('RESOURCE_LIMIT', `${label} must be an integer between 1 and ${maximum} milliseconds`);
  }
}

function mac(key: Uint8Array, context: CredentialRequestContext, timestamp: number): string {
  return createHmac('sha256', key)
    .update('p2prpc-session-credential-v3\n')
    .update(JSON.stringify([
      3,
      context.protocol,
      context.role,
      context.initiatorPeerId,
      context.responderPeerId,
      context.initiatorNonce,
      context.responderNonce,
      context.initiatorPresentedAt,
      context.responderPresentedAt,
      context.transcriptHash,
      timestamp
    ]))
    .digest('base64url');
}

function validateContextRole(
  context: CredentialRequestContext,
  presenterPeerId: string
): void {
  if (context.role !== 'initiator' && context.role !== 'responder') {
    throw new P2PError('UNAUTHORIZED', 'Session credential has an invalid handshake role');
  }
  const expected = context.role === 'initiator' ? context.initiatorPeerId : context.responderPeerId;
  if (presenterPeerId !== expected || context.initiatorPeerId === context.responderPeerId) {
    throw new P2PError('UNAUTHORIZED', 'Session credential role does not match the authenticated peer');
  }
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}
