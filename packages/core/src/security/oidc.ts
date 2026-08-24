import { createHash, createPublicKey, KeyObject, timingSafeEqual, type JsonWebKey } from 'node:crypto';
import { PublicKey } from '@momics/iroh-http-node';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  createRemoteJWKSet,
  customFetch,
  decodeJwt,
  jwtVerify,
  type CryptoKey as JoseCryptoKey,
  type JWK,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JSONWebKeySet,
  type KeyInput,
  type FetchImplementation
} from 'jose';
import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';
import type {
  AuthorizationContext,
  AuthorizationResult,
  CredentialRequestContext,
  SessionAuthenticationContext,
  SessionPrincipal
} from './types.js';
import { markPeerBoundSessionSecurity, type PeerBoundSessionSecurity } from './types.js';

export type OidcAlgorithm =
  | 'RS256' | 'RS384' | 'RS512'
  | 'PS256' | 'PS384' | 'PS512'
  | 'ES256' | 'ES384' | 'ES512'
  | 'EdDSA';

interface OidcStaticJwkBase {
  readonly kid?: string;
  readonly use?: 'sig';
  readonly key_ops?: readonly ['verify'];
  readonly ext?: boolean;
  readonly x5c?: readonly string[];
  readonly x5t?: string;
  readonly 'x5t#S256'?: string;
  readonly x5u?: string;
}

export type OidcStaticJwk =
  | (OidcStaticJwkBase & {
      readonly kty: 'RSA';
      readonly alg: Extract<OidcAlgorithm, `RS${number}` | `PS${number}`>;
      readonly n: string;
      readonly e: string;
    })
  | (OidcStaticJwkBase & {
      readonly kty: 'EC';
      readonly alg: 'ES256';
      readonly crv: 'P-256';
      readonly x: string;
      readonly y: string;
    })
  | (OidcStaticJwkBase & {
      readonly kty: 'EC';
      readonly alg: 'ES384';
      readonly crv: 'P-384';
      readonly x: string;
      readonly y: string;
    })
  | (OidcStaticJwkBase & {
      readonly kty: 'EC';
      readonly alg: 'ES512';
      readonly crv: 'P-521';
      readonly x: string;
      readonly y: string;
    })
  | (OidcStaticJwkBase & {
      readonly kty: 'OKP';
      readonly alg: 'EdDSA';
      readonly crv: 'Ed25519';
      readonly x: string;
    });

export interface OidcStaticJwks {
  readonly keys: readonly OidcStaticJwk[];
}

export type OidcVerificationKey = JoseCryptoKey | KeyObject | OidcStaticJwk;

interface OidcIssuerConfigurationBase {
  readonly issuer: string;
  readonly audience: string | readonly [string, ...string[]];
  /** Explicit algorithm allow-list. For example: ['RS256', 'ES256']. */
  readonly algorithms: readonly [OidcAlgorithm, ...OidcAlgorithm[]];
}

export type OidcIssuerConfiguration = OidcIssuerConfigurationBase & (
  | {
      /** A configured HTTPS JWKS endpoint. Token-controlled jku/x5u values are ignored. */
      readonly jwksUri: string | URL;
      readonly jwks?: never;
      readonly verificationKey?: never;
    }
  | {
      /** A static local JWKS. p2prpc constructs the resolver; token URLs are never consulted. */
      readonly jwks: OidcStaticJwks;
      readonly jwksUri?: never;
      readonly verificationKey?: never;
    }
  | {
      /** One static/local public verification key, primarily for private issuers and tests. */
      readonly verificationKey: OidcVerificationKey;
      readonly jwksUri?: never;
      readonly jwks?: never;
    }
);

export type OidcClaimValue =
  | null | boolean | number | string
  | readonly OidcClaimValue[]
  | { readonly [name: string]: OidcClaimValue };

/**
 * Detached, bounded, deeply immutable JSON claims passed to application policy.
 * Standard JWT claims are refined here so callers do not need to cast values
 * which p2prpc has already validated.
 */
export interface OidcVerifiedClaims {
  readonly [name: string]: OidcClaimValue | undefined;
  readonly iss?: string;
  readonly sub?: string;
  readonly aud?: string | readonly string[];
  readonly jti?: string;
  readonly nbf?: number;
  readonly exp?: number;
  readonly iat?: number;
}

export interface OidcSessionSecurityOptions<TFileMetadata = unknown> {
  readonly issuers: readonly [OidcIssuerConfiguration, ...OidcIssuerConfiguration[]];
  readonly getAccessToken: (context: CredentialRequestContext) => Promise<string> | string;
  /** Defaults to requiring p2prpc:connect. */
  readonly requiredConnectionScopes?: readonly [string, ...string[]];
  /**
   * Authoritative enterprise-directory binding for issuers which cannot mint
   * cnf-bound tokens. It is consulted only when cnf is entirely absent and
   * must bind the immutable verified claims to the authenticated Iroh peer ID.
   */
  readonly bindPrincipalToPeer?: (
    claims: OidcVerifiedClaims,
    context: SessionAuthenticationContext
  ) => Promise<boolean> | boolean;
  readonly tenantClaim?: string;
  readonly clockToleranceSeconds?: number;
  /** Maximum age since iat. Defaults to one hour and is capped at 24 hours. */
  readonly maxTokenAge?: string | number;
  /** JOSE typ values accepted as OAuth access tokens. Defaults to only at+jwt. */
  readonly acceptedTokenTypes?: readonly [string, ...string[]];
  readonly authorize?: (context: AuthorizationContext<TFileMetadata>) => Promise<AuthorizationResult> | AuthorizationResult;
}

interface NormalizedIssuer {
  readonly issuer: string;
  readonly audience: string | string[];
  readonly algorithms: string[];
  readonly key: KeyInput | JWTVerifyGetKey;
}

const MAX_ACCESS_TOKEN_BYTES = 48 * 1024;
const MAX_CLAIM_DEPTH = 16;
const MAX_CLAIM_ITEMS = 4_096;
const MAX_CLAIM_CONTAINER_ITEMS = 1_024;
const MAX_CLAIM_BYTES = 64 * 1024;
const MAX_SCOPE_COUNT = 1_024;
const MAX_SCOPE_BYTES = 16 * 1024;
const MAX_STATIC_JWKS_KEYS = 64;
const MAX_STATIC_JWKS_DEPTH = 4;
const MAX_STATIC_JWKS_ITEMS = 4_096;
const MAX_STATIC_JWKS_CONTAINER_ITEMS = 1_024;
const MAX_STATIC_JWKS_BYTES = 256 * 1024;
const MAX_JWK_KID_BYTES = 256;
const REMOTE_JWKS_FAILURE_COOLDOWN_MS = 30_000;

/** RFC 7638 thumbprint used by cnf.jkt to bind a token to an Iroh endpoint key. */
export async function irohPeerIdJwkThumbprint(peerId: string): Promise<string> {
  try {
    const bytes = PublicKey.fromString(peerId).bytes;
    return await calculateJwkThumbprint({
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(bytes).toString('base64url')
    });
  } catch (cause) {
    throw new P2PError('UNAUTHORIZED', 'Iroh peer ID is not a valid Ed25519 public key', { cause });
  }
}

/**
 * OAuth 2.0/OIDC-inspired mutual workload authentication for p2prpc.
 *
 * This is intentionally a resource-server helper: applications obtain and
 * refresh access tokens; the library only presents and verifies them. Refresh
 * tokens, browser redirects, and device flows never enter the P2P protocol.
 */
export function createOidcSessionSecurity<TFileMetadata = unknown>(
  options: OidcSessionSecurityOptions<TFileMetadata>
): PeerBoundSessionSecurity<TFileMetadata> {
  const configured = captureOptions(
    options,
    [
      'issuers',
      'getAccessToken',
      'requiredConnectionScopes',
      'bindPrincipalToPeer',
      'tenantClaim',
      'clockToleranceSeconds',
      'maxTokenAge',
      'acceptedTokenTypes',
      'authorize'
    ],
    'OIDC session security options'
  );
  if (typeof configured.getAccessToken !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC access-token provider must be a function');
  }
  if (configured.bindPrincipalToPeer !== undefined && typeof configured.bindPrincipalToPeer !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC principal-to-peer binding must be a function');
  }
  if (configured.authorize !== undefined && typeof configured.authorize !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC authorize policy must be a function');
  }
  const getAccessToken = configured.getAccessToken as OidcSessionSecurityOptions<TFileMetadata>['getAccessToken'];
  const bindPrincipalToPeer = configured.bindPrincipalToPeer as OidcSessionSecurityOptions<TFileMetadata>['bindPrincipalToPeer'];
  const customAuthorize = configured.authorize as OidcSessionSecurityOptions<TFileMetadata>['authorize'];
  const clockToleranceSeconds = normalizeClockTolerance(configured.clockToleranceSeconds);
  const maxTokenAgeSeconds = normalizeMaxTokenAge(configured.maxTokenAge);
  const issuers = normalizeIssuers(configured.issuers);
  const connectionScopes = normalizeRequiredConnectionScopes(configured.requiredConnectionScopes);
  const tenantClaim = normalizeTenantClaim(configured.tenantClaim);
  const acceptedTokenTypes = normalizeAcceptedTokenTypes(configured.acceptedTokenTypes);

  return markPeerBoundSessionSecurity({
    async getCredential(context) {
      const token = await getAccessToken(context);
      if (typeof token !== 'string' || token.length < 1 || Buffer.byteLength(token) > MAX_ACCESS_TOKEN_BYTES) {
        throw new P2PError('UNAUTHORIZED', 'Access-token provider returned an invalid token');
      }
      return { scheme: 'Bearer', value: token };
    },

    async authenticate(credential, context) {
      if (
        !isRecord(credential) ||
        typeof credential.scheme !== 'string' ||
        credential.scheme.length < 1 ||
        Buffer.byteLength(credential.scheme) > 128 ||
        typeof credential.value !== 'string' ||
        credential.value.length < 1 ||
        Buffer.byteLength(credential.value) > MAX_ACCESS_TOKEN_BYTES
      ) {
        throw new P2PError('UNAUTHORIZED', 'Presented OAuth access token is invalid or exceeds 48 KiB');
      }
      if (credential.scheme.toLowerCase() !== 'bearer') throw new P2PError('UNAUTHORIZED', 'Expected an OAuth bearer access token');
      let unverified: JWTPayload;
      try {
        unverified = decodeJwt(credential.value);
      } catch (cause) {
        throw new P2PError('UNAUTHORIZED', 'Malformed OAuth access token', { cause });
      }
      const configuration = issuers.get(unverified.iss ?? '');
      if (!configuration) throw new P2PError('UNAUTHORIZED', 'Access token issuer is not trusted');

      let verifiedClaims: JWTPayload;
      try {
        const verified = await jwtVerify(credential.value, configuration.key, {
          issuer: configuration.issuer,
          audience: configuration.audience,
          algorithms: configuration.algorithms,
          requiredClaims: ['exp', 'iat'],
          clockTolerance: clockToleranceSeconds,
          maxTokenAge: maxTokenAgeSeconds
        });
        const tokenType = verified.protectedHeader.typ?.toLowerCase();
        if (!tokenType || !acceptedTokenTypes.has(tokenType)) {
          throw new P2PError('UNAUTHORIZED', 'JWT is not an accepted OAuth access-token type');
        }
        verifiedClaims = verified.payload;
      } catch (cause) {
        throw new P2PError('UNAUTHORIZED', 'OAuth access token verification failed', { cause });
      }

      // Nothing application-controlled observes JOSE's payload object. A
      // detached, deeply frozen, plain-data snapshot closes mutation, accessor,
      // prototype, cycle, and unbounded-traversal ambiguity at the trust edge.
      const claims = snapshotVerifiedClaims(verifiedClaims);
      const clientId = readClientId(claims);
      const subject = readSubject(claims, clientId);
      if (claims.exp === undefined) throw new P2PError('UNAUTHORIZED', 'Access token has no expiry');
      const expiresAt = Math.floor(claims.exp * 1000);
      if (!Number.isSafeInteger(expiresAt)) {
        throw new P2PError('UNAUTHORIZED', 'Access token expiry is outside the supported time range');
      }
      const scopes = readScopes(claims);
      for (const required of connectionScopes) {
        if (!hasScope(scopes, required)) throw new P2PError('UNAUTHORIZED', `Access token lacks required scope ${required}`);
      }
      const tenant = Object.hasOwn(claims, tenantClaim) ? claims[tenantClaim] : undefined;
      if (
        tenant !== undefined &&
        (
          typeof tenant !== 'string' ||
          tenant.length === 0 ||
          Buffer.byteLength(tenant) > 2048 ||
          containsUnsafeDisplayCharacters(tenant)
        )
      ) {
        throw new P2PError('UNAUTHORIZED', `OAuth ${tenantClaim} claim must be a bounded string`);
      }
      // The directory sees only claims which can produce a valid principal;
      // malformed identity data cannot trigger policy side effects first.
      await verifyPeerBinding(claims, context, bindPrincipalToPeer);

      const principal: SessionPrincipal = Object.freeze({
        id: stablePrincipalId(
          configuration.issuer,
          subject,
          clientId,
          typeof tenant === 'string' ? tenant : undefined
        ),
        subject,
        issuer: configuration.issuer,
        ...(clientId !== undefined ? { clientId } : {}),
        ...(typeof tenant === 'string' ? { tenantId: tenant } : {}),
        expiresAt,
        scopes,
        claims
      });
      return principal;
    },

    authorize(context) {
      const scopes = context.principal.scopes;
      let scopeAllowed: boolean;
      if (context.action.kind === 'rpc') {
        scopeAllowed = hasScope(scopes, 'p2prpc:rpc') || hasScope(scopes, `p2prpc:rpc:${context.action.path}`);
      } else if (context.action.kind === 'file.push') {
        scopeAllowed = hasScope(scopes, 'p2prpc:file:push');
      } else {
        scopeAllowed = hasScope(scopes, 'p2prpc:file:pull');
      }
      if (!scopeAllowed) return false;
      return customAuthorize === undefined ? true : customAuthorize(context);
    }
  });
}

function normalizeClockTolerance(value: unknown): number {
  if (value === undefined) return 30;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > 10 * 60) {
    throw new P2PError('RESOURCE_LIMIT', 'OIDC clock tolerance must be an integer between 0 and 600 seconds');
  }
  return value;
}

function normalizeMaxTokenAge(value: unknown): number {
  if (value === undefined) return 60 * 60;
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value) && value >= 1 && value <= 24 * 60 * 60) return value;
    throw new P2PError('RESOURCE_LIMIT', 'OAuth maximum token age must be between one second and 24 hours');
  }
  if (typeof value !== 'string' || value.length > 64) {
    throw new P2PError('RESOURCE_LIMIT', 'OAuth maximum token age is invalid');
  }
  const match = /^(\d+)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days)$/i.exec(value);
  if (!match) throw new P2PError('RESOURCE_LIMIT', 'OAuth maximum token age is invalid');
  const amount = Number(match[1]);
  const unit = match[2]!.toLowerCase();
  const multiplier = unit.startsWith('s') ? 1 : unit.startsWith('m') ? 60 : unit.startsWith('h') ? 60 * 60 : 24 * 60 * 60;
  const seconds = amount * multiplier;
  if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 24 * 60 * 60) {
    throw new P2PError('RESOURCE_LIMIT', 'OAuth maximum token age must be between one second and 24 hours');
  }
  return seconds;
}

function normalizeRequiredConnectionScopes(value: unknown): ReadonlySet<string> {
  const configured: unknown = value === undefined ? ['p2prpc:connect'] : value;
  const entries = captureDenseArray(configured, 1, 64, 'OIDC required connection scopes');
  const scopes = new Set<string>();
  for (const scope of entries) {
    if (
      typeof scope !== 'string' ||
      Buffer.byteLength(scope) < 1 ||
      Buffer.byteLength(scope) > 512 ||
      !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope) ||
      scopes.has(scope)
    ) {
      throw new P2PError('UNAUTHORIZED', 'OIDC required connection scopes are invalid or duplicated');
    }
    scopes.add(scope);
  }
  return scopes;
}

function normalizeTenantClaim(value: unknown): string {
  if (value === undefined) return 'tenant_id';
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value) < 1 ||
    Buffer.byteLength(value) > 256 ||
    !/^[\x21-\x7e]+$/.test(value) ||
    value === '__proto__' ||
    value === 'constructor' ||
    value === 'prototype'
  ) {
    throw new P2PError('UNAUTHORIZED', 'OIDC tenant claim name is invalid');
  }
  return value;
}

function normalizeAcceptedTokenTypes(value: unknown): ReadonlySet<string> {
  const configured: unknown = value === undefined ? ['at+jwt'] : value;
  const entries = captureDenseArray(configured, 1, 16, 'OIDC accepted token types');
  const output = new Set<string>();
  for (const item of entries) {
    if (
      typeof item !== 'string' ||
      Buffer.byteLength(item) < 1 ||
      Buffer.byteLength(item) > 128 ||
      !/^[\x21-\x7e]+$/.test(item)
    ) {
      throw new P2PError('UNAUTHORIZED', 'OIDC accepted token types are invalid');
    }
    const normalized = item.toLowerCase();
    if (output.has(normalized)) throw new P2PError('UNAUTHORIZED', 'OIDC accepted token types are duplicated');
    output.add(normalized);
  }
  return output;
}

function stablePrincipalId(
  issuer: string,
  subject: string,
  clientId: string | undefined,
  tenantId: string | undefined
): string {
  const digest = createHash('sha256')
    .update('p2prpc-oidc-principal-v2\n')
    .update(JSON.stringify([issuer, subject, clientId ?? null, tenantId ?? null]))
    .digest('base64url');
  return `oidc:${digest}`;
}

function readClientId(claims: OidcVerifiedClaims): string | undefined {
  const clientId = claims.client_id;
  const authorizedParty = claims.azp;
  if (clientId !== undefined && !validIdentityClaim(clientId)) {
    throw new P2PError('UNAUTHORIZED', 'OAuth client_id claim must be a bounded non-empty string');
  }
  if (authorizedParty !== undefined && !validIdentityClaim(authorizedParty)) {
    throw new P2PError('UNAUTHORIZED', 'OAuth azp claim must be a bounded non-empty string');
  }
  if (clientId !== undefined && authorizedParty !== undefined && clientId !== authorizedParty) {
    throw new P2PError('UNAUTHORIZED', 'OAuth client_id and azp claims do not identify the same client');
  }
  return clientId ?? authorizedParty;
}

function readSubject(claims: OidcVerifiedClaims, clientId: string | undefined): string {
  if (claims.sub !== undefined) {
    if (!validIdentityClaim(claims.sub)) {
      throw new P2PError('UNAUTHORIZED', 'OAuth sub claim must be a bounded non-empty string');
    }
    return claims.sub;
  }
  if (clientId !== undefined) return clientId;
  throw new P2PError('UNAUTHORIZED', 'Access token has no subject');
}

function validIdentityClaim(value: unknown): value is string {
  return typeof value === 'string' &&
    Buffer.byteLength(value) > 0 &&
    Buffer.byteLength(value) <= 2048 &&
    !containsUnsafeDisplayCharacters(value);
}

async function verifyPeerBinding(
  claims: OidcVerifiedClaims,
  context: SessionAuthenticationContext,
  directoryBinding: OidcSessionSecurityOptions['bindPrincipalToPeer']
): Promise<void> {
  const jkt = readConfirmationThumbprint(claims);
  if (jkt !== undefined) {
    let expected: string;
    try {
      expected = await irohPeerIdJwkThumbprint(context.remotePeerId);
    } catch (cause) {
      throw new P2PError('UNAUTHORIZED', 'Invalid authenticated Iroh peer key', { cause });
    }
    if (!safeEqual(jkt, expected)) throw new P2PError('UNAUTHORIZED', 'Access token is bound to a different peer key');
    return;
  }
  if (directoryBinding === undefined) {
    throw new P2PError('UNAUTHORIZED', 'Access token is not bound to this peer');
  }
  let bound: boolean;
  try {
    bound = await directoryBinding(claims, context);
  } catch (cause) {
    throw new P2PError('UNAUTHORIZED', 'OIDC principal-to-peer directory binding failed', { cause });
  }
  if (bound !== true) throw new P2PError('UNAUTHORIZED', 'OIDC directory did not bind the principal to this peer');
}

function readConfirmationThumbprint(claims: OidcVerifiedClaims): string | undefined {
  if (!Object.hasOwn(claims, 'cnf')) return undefined;
  const confirmation = claims.cnf;
  if (!isRecord(confirmation)) {
    throw new P2PError('UNAUTHORIZED', 'OAuth cnf claim must contain exactly one supported jkt method');
  }
  const keys = Object.keys(confirmation);
  if (keys.length !== 1 || keys[0] !== 'jkt') {
    throw new P2PError('UNAUTHORIZED', 'OAuth cnf claim must contain exactly one supported jkt method');
  }
  const jkt = confirmation.jkt;
  if (!validJwkThumbprint(jkt)) {
    throw new P2PError('UNAUTHORIZED', 'OAuth cnf.jkt claim must be a SHA-256 JWK thumbprint');
  }
  return jkt;
}

function validJwkThumbprint(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.byteLength === 32 && decoded.toString('base64url') === value;
}

function normalizeIssuers(value: unknown): Map<string, NormalizedIssuer> {
  const configuredIssuers = captureDenseArray(value, 1, 32, 'OIDC issuers');
  const output = new Map<string, NormalizedIssuer>();
  for (const issuerConfiguration of configuredIssuers) {
    const configuration = captureOptions(
      issuerConfiguration,
      ['issuer', 'audience', 'algorithms', 'jwksUri', 'jwks', 'verificationKey'],
      'OIDC issuer configuration'
    );
    if (typeof configuration.issuer !== 'string') {
      throw new P2PError('UNAUTHORIZED', 'OIDC issuer must be a string');
    }
    const issuerUrl = validHttpsUrl(configuration.issuer, 'issuer');
    if (issuerUrl.search) throw new P2PError('UNAUTHORIZED', 'OIDC issuer must not contain a query');
    const issuer = configuration.issuer;
    if (output.has(issuer)) throw new P2PError('UNAUTHORIZED', `Duplicate OIDC issuer ${issuer}`);
    const configuredAlgorithms = captureDenseArray(
      configuration.algorithms,
      1,
      16,
      'OIDC issuer algorithm allow-list'
    );
    const algorithms = new Set<string>();
    for (const algorithm of configuredAlgorithms) {
      if (typeof algorithm !== 'string' || !safeAlgorithm(algorithm) || algorithms.has(algorithm)) {
        throw new P2PError('UNAUTHORIZED', 'OIDC issuer needs a unique explicit safe JWT algorithm allow-list');
      }
      algorithms.add(algorithm);
    }
    // Read each source once so an accessor/proxy cannot pass validation with
    // one value and substitute a resolver callback afterward.
    const jwksUri = configuration.jwksUri;
    const jwks = configuration.jwks;
    const verificationKey: unknown = configuration.verificationKey;
    const configuredKeySources = [jwksUri, jwks, verificationKey]
      .filter((value) => value !== undefined).length;
    if (configuredKeySources !== 1) {
      throw new P2PError(
        'UNAUTHORIZED',
        'Configure exactly one of jwksUri, jwks, or verificationKey for each issuer'
      );
    }
    if (jwksUri !== undefined && typeof jwksUri !== 'string' && !(jwksUri instanceof URL)) {
      throw new P2PError('UNAUTHORIZED', 'OIDC JWKS URI must be a string or URL');
    }
    // jwtVerify also accepts an arbitrary key-resolver callback, but JOSE calls
    // it with attacker-controlled protected headers before signature
    // verification. Production root configuration deliberately accepts only
    // configured key material or p2prpc-constructed local/remote JWKS
    // resolvers, so a token-controlled jku/x5u can never choose trust roots.
    if (typeof verificationKey === 'function') {
      throw new P2PError('UNAUTHORIZED', 'OIDC verificationKey callbacks are not allowed');
    }
    let key: KeyInput | JWTVerifyGetKey;
    try {
      key = verificationKey !== undefined
        ? normalizeVerificationKey(verificationKey, algorithms)
        : jwks !== undefined
          ? createBoundedLocalJwkSet(normalizeStaticJwks(jwks, algorithms, true, false))
          : createBoundedJwksResolver(
              createRemoteJWKSet(
                validHttpsUrl(jwksUri!, 'JWKS URI'),
                {
                  timeoutDuration: 5_000,
                  cooldownDuration: 30_000,
                  cacheMaxAge: 10 * 60_000,
                  [customFetch]: createBoundedJwksFetch(algorithms)
                }
              ),
              true
            );
    } catch (cause) {
      if (cause instanceof P2PError) throw cause;
      throw new P2PError('UNAUTHORIZED', 'OIDC verification key material is invalid', { cause });
    }
    const audience = normalizeAudience(configuration.audience);
    output.set(issuer, { issuer, audience, algorithms: [...algorithms], key });
  }
  return output;
}

interface StaticJwksBudget {
  items: number;
  bytes: number;
  readonly active: WeakSet<object>;
}

const PRIVATE_JWK_MEMBERS = new Set(['d', 'dp', 'dq', 'k', 'oth', 'p', 'priv', 'q', 'qi']);

function createBoundedLocalJwkSet(jwks: JSONWebKeySet): JWTVerifyGetKey {
  return createBoundedJwksResolver(createLocalJWKSet(jwks), jwks.keys.length > 1);
}

function createBoundedJwksResolver(resolver: JWTVerifyGetKey, requireKeyId: boolean): JWTVerifyGetKey {
  return (protectedHeader, token) => {
    const keyId = protectedHeader?.kid;
    if ((requireKeyId && keyId === undefined) || (keyId !== undefined && !validJwkKid(keyId))) {
      throw new P2PError('UNAUTHORIZED', 'OAuth JWT kid header is missing or invalid');
    }
    return resolver(protectedHeader, token);
  };
}

function createBoundedJwksFetch(algorithms: ReadonlySet<string>): FetchImplementation {
  // JOSE coalesces concurrent reloads for this resolver. This additional
  // negative cache prevents sequential bad tokens or an unhealthy issuer from
  // turning every authentication attempt into another outbound HTTPS request.
  let retryAfter = 0;
  return async (url, options) => {
    if (Date.now() < retryAfter) {
      throw new P2PError('UNAUTHORIZED', 'Remote OIDC JWKS is inside its failure cooldown');
    }
    try {
      // The configured HTTPS URL is the trust and egress boundary. Following
      // redirects would let that origin select a different key server (or a
      // private-network target) after configuration validation.
      const response = await fetch(url, { ...options, redirect: 'error' });
      if (response.status !== 200) {
        await cancelResponseBody(response);
        throw new P2PError('UNAUTHORIZED', 'Remote OIDC JWKS did not return 200 OK');
      }
      const declaredLength = response.headers.get('content-length');
      if (declaredLength !== null) {
        const parsedLength = Number(declaredLength);
        if (!Number.isSafeInteger(parsedLength) || parsedLength < 0 || parsedLength > MAX_STATIC_JWKS_BYTES) {
          await cancelResponseBody(response);
          throw new P2PError('RESOURCE_LIMIT', 'Remote OIDC JWKS exceeds the maximum response size');
        }
      }
      if (response.body === null) {
        throw new P2PError('UNAUTHORIZED', 'Remote OIDC JWKS response has no body');
      }
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      try {
        while (true) {
          const next = await reader.read();
          if (next.done) break;
          bytes += next.value.byteLength;
          if (bytes > MAX_STATIC_JWKS_BYTES) {
            await reader.cancel().catch(() => undefined);
            throw new P2PError('RESOURCE_LIMIT', 'Remote OIDC JWKS exceeds the maximum response size');
          }
          chunks.push(next.value);
        }
      } finally {
        reader.releaseLock();
      }
      let decoded: unknown;
      try {
        const json = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, bytes));
        decoded = JSON.parse(json) as unknown;
      } catch (cause) {
        throw new P2PError('UNAUTHORIZED', 'Remote OIDC JWKS response is not valid UTF-8 JSON', { cause });
      }
      const normalized = normalizeStaticJwks(decoded, algorithms, false, true);
      retryAfter = 0;
      return new Response(JSON.stringify(normalized), {
        status: 200,
        headers: { 'content-type': 'application/json' }
      });
    } catch (cause) {
      retryAfter = Date.now() + REMOTE_JWKS_FAILURE_COOLDOWN_MS;
      throw cause;
    }
  };
}

async function cancelResponseBody(response: Response): Promise<void> {
  if (response.body === null) return;
  await response.body.cancel().catch(() => undefined);
}

function normalizeVerificationKey(value: unknown, algorithms: ReadonlySet<string>): KeyInput | JWTVerifyGetKey {
  if (isPlainRecord(value)) {
    // A JWK is mutable plain data. Route it through the same eager snapshot as
    // a static JWKS so post-construction mutation cannot replace the trust root.
    return createBoundedLocalJwkSet(normalizeStaticJwks(
      { keys: [value as unknown as OidcStaticJwk] },
      algorithms,
      true,
      false
    ));
  }
  if (value instanceof KeyObject || value instanceof CryptoKey) {
    if (value.type !== 'public') {
      throw new P2PError('UNAUTHORIZED', 'OIDC verificationKey must be a public verification key');
    }
    validateNativeVerificationKey(value, algorithms);
    return value;
  }
  throw new P2PError(
    'UNAUTHORIZED',
    'OIDC verificationKey must be a public CryptoKey, KeyObject, or static public JWK'
  );
}

function validateNativeVerificationKey(value: JoseCryptoKey | KeyObject, algorithms: ReadonlySet<string>): void {
  let family: 'RSA' | 'EC' | 'OKP' | undefined;
  let rsaMode: 'RS' | 'PS' | 'both' | undefined;
  let curve: string | undefined;
  let modulusLength: number | undefined;
  let boundHash: string | undefined;
  let pssHash: string | undefined;
  let pssMgfHash: string | undefined;
  let pssMinimumSaltLength: number | undefined;
  if (value instanceof CryptoKey) {
    if (!value.usages.includes('verify')) {
      throw new P2PError('UNAUTHORIZED', 'OIDC verification CryptoKey usages must include verify');
    }
    const details = value.algorithm as {
      readonly name: string;
      readonly namedCurve?: string;
      readonly modulusLength?: number;
      readonly hash?: { readonly name?: string };
    };
    if (details.name === 'RSASSA-PKCS1-v1_5') {
      family = 'RSA';
      rsaMode = 'RS';
      modulusLength = details.modulusLength;
      boundHash = normalizeHashName(details.hash?.name);
    } else if (details.name === 'RSA-PSS') {
      family = 'RSA';
      rsaMode = 'PS';
      modulusLength = details.modulusLength;
      boundHash = normalizeHashName(details.hash?.name);
    } else if (details.name === 'ECDSA') {
      family = 'EC';
      curve = normalizeCurveName(details.namedCurve);
    } else if (details.name === 'Ed25519') {
      family = 'OKP';
      curve = 'Ed25519';
    }
  } else {
    const asymmetricType = value.asymmetricKeyType;
    if (asymmetricType === 'rsa') {
      family = 'RSA';
      rsaMode = 'both';
      modulusLength = value.asymmetricKeyDetails?.modulusLength;
    } else if (asymmetricType === 'rsa-pss') {
      family = 'RSA';
      rsaMode = 'PS';
      modulusLength = value.asymmetricKeyDetails?.modulusLength;
      pssHash = normalizeHashName(value.asymmetricKeyDetails?.hashAlgorithm);
      pssMgfHash = normalizeHashName(value.asymmetricKeyDetails?.mgf1HashAlgorithm);
      pssMinimumSaltLength = value.asymmetricKeyDetails?.saltLength;
    } else if (asymmetricType === 'ec') {
      family = 'EC';
      curve = normalizeCurveName(value.asymmetricKeyDetails?.namedCurve);
    } else if (asymmetricType === 'ed25519') {
      family = 'OKP';
      curve = 'Ed25519';
    }
  }
  if (
    family === undefined ||
    (family === 'RSA' && ((modulusLength ?? 0) < 2_048 || (modulusLength ?? Infinity) > 8_192))
  ) {
    throw new P2PError('UNAUTHORIZED', 'OIDC verificationKey uses an unsupported or undersized public key');
  }
  for (const algorithm of algorithms) {
    if (!algorithmMatchesKey(algorithm, family, curve, rsaMode)) {
      throw new P2PError('UNAUTHORIZED', 'OIDC verificationKey is incompatible with the algorithm allow-list');
    }
    if (family === 'RSA') {
      const expectedHash = jwtAlgorithmHash(algorithm);
      if (boundHash !== undefined && boundHash !== expectedHash) {
        throw new P2PError('UNAUTHORIZED', 'OIDC verification CryptoKey hash does not match the algorithm allow-list');
      }
      if (value instanceof CryptoKey && boundHash === undefined) {
        throw new P2PError('UNAUTHORIZED', 'OIDC RSA CryptoKey must expose its bound hash');
      }
      if (rsaMode === 'PS' && !(value instanceof CryptoKey)) {
        if (pssHash !== expectedHash || pssMgfHash !== expectedHash) {
          throw new P2PError('UNAUTHORIZED', 'OIDC RSA-PSS key restrictions do not match the algorithm allow-list');
        }
        const expectedSaltLength = Number(algorithm.slice(2)) / 8;
        if (pssMinimumSaltLength !== undefined && pssMinimumSaltLength > expectedSaltLength) {
          throw new P2PError('UNAUTHORIZED', 'OIDC RSA-PSS minimum salt exceeds the JWT algorithm salt length');
        }
      }
    }
  }
}

function normalizeCurveName(value: string | undefined): string | undefined {
  if (value === 'prime256v1') return 'P-256';
  if (value === 'secp384r1') return 'P-384';
  if (value === 'secp521r1') return 'P-521';
  return value;
}

function normalizeHashName(value: string | undefined): string | undefined {
  return value?.toLowerCase().replaceAll('-', '');
}

function jwtAlgorithmHash(algorithm: string): string {
  return `sha${algorithm.slice(2)}`;
}

/**
 * Snapshot configured static trust roots without evaluating nested accessors.
 * JOSE snapshots again, but this first pass gives p2prpc deterministic resource
 * bounds and construction-time rejection of private verification material.
 */
function normalizeStaticJwks(
  value: unknown,
  algorithms: ReadonlySet<string>,
  requireExplicitAlgorithm: boolean,
  requireEveryKeyId: boolean
): JSONWebKeySet {
  if (!isPlainRecord(value)) {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must be a plain object');
  }
  const rootKeys = Reflect.ownKeys(value);
  if (rootKeys.length !== 1 || rootKeys[0] !== 'keys') {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain only a keys field');
  }
  const keysDescriptor = Object.getOwnPropertyDescriptor(value, 'keys');
  if (!keysDescriptor?.enumerable || !Object.hasOwn(keysDescriptor, 'value')) {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS keys must be an enumerable data property');
  }
  const keys = captureDenseArray(
    keysDescriptor.value,
    1,
    MAX_STATIC_JWKS_KEYS,
    'OIDC static JWKS keys'
  );

  const budget: StaticJwksBudget = { items: 0, bytes: 0, active: new WeakSet() };
  const snapshots: JWK[] = [];
  const keyIds = new Set<string>();
  for (const key of keys) {
    const snapshot = snapshotStaticJwkValue(key, 0, budget);
    if (!isRecord(snapshot)) {
      throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS members must be plain objects');
    }
    for (const member of PRIVATE_JWK_MEMBERS) {
      if (Object.hasOwn(snapshot, member)) {
        throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain public verification keys only');
      }
    }
    const keyId = validateStaticJwk(snapshot, algorithms, requireExplicitAlgorithm);
    if (keyId !== undefined) {
      if (keyIds.has(keyId)) throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS key IDs must be unique');
      keyIds.add(keyId);
    }
    snapshots.push(snapshot as JWK);
  }
  if ((requireEveryKeyId || snapshots.length > 1) && keyIds.size !== snapshots.length) {
    throw new P2PError('UNAUTHORIZED', 'OIDC JWKS requires a unique bounded kid on every key');
  }
  return { keys: snapshots };
}

function validateStaticJwk(
  jwk: Record<string, unknown>,
  algorithms: ReadonlySet<string>,
  requireExplicitAlgorithm: boolean
): string | undefined {
  const algorithm = jwk.alg;
  if (algorithm !== undefined && (typeof algorithm !== 'string' || !algorithms.has(algorithm))) {
    throw new P2PError('UNAUTHORIZED', 'Every OIDC static JWK requires an alg from the issuer allow-list');
  }
  if (requireExplicitAlgorithm && algorithm === undefined) {
    throw new P2PError('UNAUTHORIZED', 'Every OIDC static JWK requires an alg from the issuer allow-list');
  }
  const keyType = jwk.kty;
  if (keyType !== 'RSA' && keyType !== 'EC' && keyType !== 'OKP') {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWK uses an unsupported kty');
  }
  const curve = typeof jwk.crv === 'string' ? jwk.crv : undefined;
  const compatible = algorithm === undefined
    ? [...algorithms].some((candidate) => algorithmMatchesKey(
        candidate,
        keyType,
        curve,
        keyType === 'RSA' ? 'both' : undefined
      ))
    : algorithmMatchesKey(algorithm, keyType, curve, keyType === 'RSA' ? 'both' : undefined);
  if (!compatible) {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWK is incompatible with its configured alg');
  }
  if (keyType === 'RSA') {
    if (!validOddBase64UrlInteger(jwk.n, 256, 1_024) || !validRsaExponent(jwk.e)) {
      throw new P2PError('UNAUTHORIZED', 'OIDC RSA JWK requires a 2048-8192 bit modulus and bounded exponent');
    }
  } else if (keyType === 'EC') {
    const coordinateBytes = curve === 'P-256' ? 32 : curve === 'P-384' ? 48 : curve === 'P-521' ? 66 : 0;
    if (
      coordinateBytes === 0 ||
      !validBase64UrlBytes(jwk.x, coordinateBytes, coordinateBytes) ||
      !validBase64UrlBytes(jwk.y, coordinateBytes, coordinateBytes)
    ) {
      throw new P2PError('UNAUTHORIZED', 'OIDC EC JWK has invalid curve or public coordinates');
    }
  } else if (curve !== 'Ed25519' || !validBase64UrlBytes(jwk.x, 32, 32)) {
    throw new P2PError('UNAUTHORIZED', 'OIDC EdDSA JWK must contain an Ed25519 public key');
  }

  if (jwk.use !== undefined && jwk.use !== 'sig') {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWK use must be sig');
  }
  if (jwk.ext !== undefined && typeof jwk.ext !== 'boolean') {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWK ext must be boolean');
  }
  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops) || jwk.key_ops.length !== 1 || jwk.key_ops[0] !== 'verify') {
      throw new P2PError('UNAUTHORIZED', 'OIDC static JWK key_ops must contain only verify');
    }
  }
  let imported: KeyObject;
  try {
    imported = createPublicKey({ key: jwk as JsonWebKey, format: 'jwk' });
  } catch (cause) {
    throw new P2PError('UNAUTHORIZED', 'OIDC JWK is not importable public key material', { cause });
  }
  const compatibleAlgorithms = new Set(
    algorithm === undefined
      ? [...algorithms].filter((candidate) => algorithmMatchesKey(
          candidate,
          keyType,
          curve,
          keyType === 'RSA' ? 'both' : undefined
        ))
      : [algorithm]
  );
  validateNativeVerificationKey(imported, compatibleAlgorithms);
  if (jwk.kid === undefined) return undefined;
  if (!validJwkKid(jwk.kid)) {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWK kid is invalid or exceeds 256 bytes');
  }
  return jwk.kid;
}

function algorithmMatchesKey(
  algorithm: string,
  family: 'RSA' | 'EC' | 'OKP',
  curve: string | undefined,
  rsaMode: 'RS' | 'PS' | 'both' | undefined
): boolean {
  if (algorithm.startsWith('RS')) return family === 'RSA' && (rsaMode === 'RS' || rsaMode === 'both');
  if (algorithm.startsWith('PS')) return family === 'RSA' && (rsaMode === 'PS' || rsaMode === 'both');
  if (algorithm === 'ES256') return family === 'EC' && curve === 'P-256';
  if (algorithm === 'ES384') return family === 'EC' && curve === 'P-384';
  if (algorithm === 'ES512') return family === 'EC' && curve === 'P-521';
  return algorithm === 'EdDSA' && family === 'OKP' && curve === 'Ed25519';
}

function validJwkKid(value: unknown): value is string {
  return typeof value === 'string' &&
    Buffer.byteLength(value) > 0 &&
    Buffer.byteLength(value) <= MAX_JWK_KID_BYTES &&
    !containsUnsafeDisplayCharacters(value);
}

function validBase64UrlBytes(value: unknown, minimum: number, maximum: number): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.byteLength >= minimum &&
    decoded.byteLength <= maximum &&
    decoded.toString('base64url') === value;
}

function validOddBase64UrlInteger(value: unknown, minimum: number, maximum: number): value is string {
  if (!validBase64UrlBytes(value, minimum, maximum)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded[0] !== 0 && (decoded[decoded.length - 1]! & 1) === 1;
}

function validRsaExponent(value: unknown): value is string {
  if (!validOddBase64UrlInteger(value, 1, 8)) return false;
  let exponent = 0n;
  for (const byte of Buffer.from(value, 'base64url')) exponent = (exponent << 8n) | BigInt(byte);
  return exponent >= 3n;
}

function snapshotStaticJwkValue(value: unknown, depth: number, budget: StaticJwksBudget): unknown {
  budget.items += 1;
  if (budget.items > MAX_STATIC_JWKS_ITEMS) {
    throw new P2PError('RESOURCE_LIMIT', 'OIDC static JWKS contains too many items');
  }
  if (depth > MAX_STATIC_JWKS_DEPTH) {
    throw new P2PError('RESOURCE_LIMIT', 'OIDC static JWKS exceeds the maximum nesting depth');
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    addStaticJwksBytes(budget, Buffer.byteLength(value));
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain JSON data');
    addStaticJwksBytes(budget, 8);
    return value;
  }
  if (typeof value !== 'object') {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain JSON data');
  }
  if (budget.active.has(value)) {
    throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must not contain cycles');
  }

  budget.active.add(value);
  try {
    if (Array.isArray(value)) {
      const items = captureDenseArray(value, 0, MAX_STATIC_JWKS_CONTAINER_ITEMS, 'OIDC static JWKS array');
      const output: unknown[] = [];
      for (const item of items) output.push(snapshotStaticJwkValue(item, depth + 1, budget));
      return output;
    }
    if (!isPlainRecord(value)) {
      throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain only plain JSON objects');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) {
      throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must not contain symbol properties');
    }
    if (keys.length > MAX_STATIC_JWKS_CONTAINER_ITEMS) {
      throw new P2PError('RESOURCE_LIMIT', 'OIDC static JWKS object contains too many fields');
    }
    const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys as string[]) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS contains an unsafe property name');
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw new P2PError('UNAUTHORIZED', 'OIDC static JWKS must contain only enumerable data properties');
      }
      addStaticJwksBytes(budget, Buffer.byteLength(key));
      output[key] = snapshotStaticJwkValue(descriptor.value, depth + 1, budget);
    }
    return output;
  } finally {
    budget.active.delete(value);
  }
}

function addStaticJwksBytes(budget: StaticJwksBudget, bytes: number): void {
  budget.bytes += bytes;
  if (budget.bytes > MAX_STATIC_JWKS_BYTES) {
    throw new P2PError('RESOURCE_LIMIT', 'OIDC static JWKS exceeds the maximum decoded size');
  }
}

function normalizeAudience(value: unknown): string | string[] {
  const valid = (item: unknown): item is string => typeof item === 'string' &&
    Buffer.byteLength(item) > 0 &&
    Buffer.byteLength(item) <= 2048 &&
    !containsUnsafeDisplayCharacters(item);
  if (valid(value)) return value;
  let entries: unknown[];
  try {
    entries = captureDenseArray(value, 1, 32, 'OIDC audience');
  } catch {
    throw new P2PError('UNAUTHORIZED', 'OIDC audience must be explicit, bounded, and non-empty');
  }
  if (entries.some((item) => !valid(item)) || new Set(entries).size !== entries.length) {
    throw new P2PError('UNAUTHORIZED', 'OIDC audience must be explicit, bounded, and non-empty');
  }
  return entries as string[];
}

function readScopes(claims: OidcVerifiedClaims): ReadonlySet<string> {
  const values = new Set<string>();
  const budget = { bytes: 0, count: 0 };
  if (claims.scope !== undefined) {
    if (typeof claims.scope !== 'string') throw invalidScopeClaim();
    addSpaceDelimitedScopes(values, claims.scope, budget);
  }
  if (claims.scp !== undefined) {
    if (typeof claims.scp === 'string') {
      addSpaceDelimitedScopes(values, claims.scp, budget);
    } else if (Array.isArray(claims.scp) && claims.scp.length > 0 && claims.scp.length <= MAX_SCOPE_COUNT) {
      for (const scope of claims.scp) {
        addScope(values, scope, budget);
      }
    } else {
      throw invalidScopeClaim();
    }
  }
  return immutableSet(values);
}

interface ScopeBudget {
  bytes: number;
  count: number;
}

function addSpaceDelimitedScopes(output: Set<string>, claim: string, budget: ScopeBudget): void {
  budget.bytes += Buffer.byteLength(claim);
  if (budget.bytes > MAX_SCOPE_BYTES) throw invalidScopeClaim();
  if (!/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(claim)) {
    throw invalidScopeClaim();
  }
  for (const scope of claim.split(' ')) {
    addScope(output, scope, budget, false);
  }
}

function addScope(output: Set<string>, scope: unknown, budget: ScopeBudget, countBytes = true): void {
  if (!validScopeToken(scope)) throw invalidScopeClaim();
  budget.count += 1;
  if (countBytes) budget.bytes += Buffer.byteLength(scope);
  if (budget.count > MAX_SCOPE_COUNT || budget.bytes > MAX_SCOPE_BYTES) throw invalidScopeClaim();
  output.add(scope);
}

function validScopeToken(value: unknown): value is string {
  return typeof value === 'string' &&
    Buffer.byteLength(value) <= 1024 &&
    /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(value);
}

function invalidScopeClaim(): P2PError {
  return new P2PError('UNAUTHORIZED', 'OAuth scope and scp claims must contain bounded RFC 6749 scope tokens');
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

function hasScope(scopes: ReadonlySet<string>, required: string): boolean {
  return scopes.has(required) || (required.startsWith('p2prpc:') && scopes.has('p2prpc:*'));
}

function safeAlgorithm(value: string): boolean {
  return /^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/.test(value);
}

function validHttpsUrl(value: string | URL, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new P2PError('UNAUTHORIZED', `Invalid OIDC ${label}`, { cause });
  }
  if (url.username || url.password || url.hash || url.protocol !== 'https:') {
    throw new P2PError('UNAUTHORIZED', `OIDC ${label} must be an HTTPS URL without credentials or a fragment`);
  }
  return url;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

interface ClaimBudget {
  items: number;
  bytes: number;
  readonly active: WeakSet<object>;
}

/** Build a bounded JSON-data snapshot before verified claims cross the trust boundary. */
function snapshotVerifiedClaims(value: unknown): OidcVerifiedClaims {
  const budget: ClaimBudget = { items: 0, bytes: 0, active: new WeakSet() };
  const snapshot = snapshotClaimValue(value, 0, budget);
  if (!isRecord(snapshot)) throw invalidClaims('OAuth claims payload must be a plain object');
  return snapshot as OidcVerifiedClaims;
}

function snapshotClaimValue(value: unknown, depth: number, budget: ClaimBudget): unknown {
  budget.items += 1;
  if (budget.items > MAX_CLAIM_ITEMS) throw claimsLimit('OAuth claims contain too many items');
  if (depth > MAX_CLAIM_DEPTH) throw claimsLimit('OAuth claims exceed the maximum nesting depth');

  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    addClaimBytes(budget, Buffer.byteLength(value));
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw invalidClaims('OAuth claims must contain only finite JSON numbers');
    addClaimBytes(budget, 8);
    return value;
  }
  if (typeof value !== 'object') throw invalidClaims('OAuth claims must contain only plain JSON data');
  if (budget.active.has(value)) throw invalidClaims('OAuth claims must not contain cycles');

  budget.active.add(value);
  try {
    if (Array.isArray(value)) return snapshotClaimArray(value, depth, budget);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw invalidClaims('OAuth claims must contain only plain JSON objects');
    }
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string')) {
      throw invalidClaims('OAuth claims must not contain symbol properties');
    }
    if (keys.length > MAX_CLAIM_CONTAINER_ITEMS) throw claimsLimit('OAuth claims object contains too many fields');
    const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of keys as string[]) {
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        throw invalidClaims('OAuth claims contain an unsafe property name');
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
        throw invalidClaims('OAuth claims must contain only enumerable data properties');
      }
      addClaimBytes(budget, Buffer.byteLength(key));
      output[key] = snapshotClaimValue(descriptor.value, depth + 1, budget);
    }
    return Object.freeze(output);
  } finally {
    budget.active.delete(value);
  }
}

function snapshotClaimArray(value: unknown[], depth: number, budget: ClaimBudget): readonly unknown[] {
  if (value.length > MAX_CLAIM_CONTAINER_ITEMS) throw claimsLimit('OAuth claims array contains too many items');
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== 'string') ||
    keys.length !== value.length + 1 ||
    !keys.includes('length')
  ) {
    throw invalidClaims('OAuth claim arrays must be dense and contain no extra properties');
  }
  const output: unknown[] = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw invalidClaims('OAuth claim arrays must contain only enumerable data items');
    }
    output.push(snapshotClaimValue(descriptor.value, depth + 1, budget));
  }
  return Object.freeze(output);
}

function addClaimBytes(budget: ClaimBudget, bytes: number): void {
  budget.bytes += bytes;
  if (budget.bytes > MAX_CLAIM_BYTES) throw claimsLimit('OAuth claims exceed the maximum decoded size');
}

function invalidClaims(message: string): P2PError {
  return new P2PError('UNAUTHORIZED', message);
}

function claimsLimit(message: string): P2PError {
  return new P2PError('RESOURCE_LIMIT', message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function captureOptions(value: unknown, allowed: readonly string[], label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const allowedKeys = new Set(allowed);
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !allowedKeys.has(key)) {
      const suffix = typeof key === 'string' ? ` ${key}` : '';
      throw new P2PError('INVALID_FRAME', `${label} contains unknown field${suffix}`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new P2PError('INVALID_FRAME', `${label} must contain only enumerable data properties`);
    }
    output[key] = descriptor.value;
  }
  return Object.freeze(output);
}

function captureDenseArray(value: unknown, minimum: number, maximum: number, label: string): unknown[] {
  if (!Array.isArray(value)) {
    throw new P2PError('UNAUTHORIZED', `${label} must contain between ${minimum} and ${maximum} entries`);
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
  const length = lengthDescriptor?.value;
  if (!Number.isSafeInteger(length) || length < minimum || length > maximum) {
    throw new P2PError('UNAUTHORIZED', `${label} must contain between ${minimum} and ${maximum} entries`);
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== 'string') ||
    keys.length !== length + 1 ||
    !keys.includes('length')
  ) {
    throw new P2PError('UNAUTHORIZED', `${label} must be a dense array without extra properties`);
  }
  const output: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new P2PError('UNAUTHORIZED', `${label} must contain only enumerable data items`);
    }
    output.push(descriptor.value);
  }
  return output;
}
