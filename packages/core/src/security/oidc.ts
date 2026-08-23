import { createHash, timingSafeEqual } from 'node:crypto';
import { PublicKey } from '@momics/iroh-http-node';
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  decodeJwt,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
  type KeyInput
} from 'jose';
import { P2PError } from '../errors.js';
import { containsUnsafeDisplayCharacters } from '../text.js';
import type {
  AuthorizationContext,
  AuthorizationResult,
  CredentialRequestContext,
  SessionAuthenticationContext,
  SessionPrincipal,
  SessionSecurity
} from './types.js';

export interface OidcIssuerConfiguration {
  readonly issuer: string;
  readonly audience: string | readonly string[];
  /** Explicit algorithm allow-list. For example: ['RS256', 'ES256']. */
  readonly algorithms: readonly string[];
  /** A configured HTTPS JWKS endpoint. Token-controlled jku/x5u values are ignored. */
  readonly jwksUri?: string | URL;
  /** Static/local verification material, primarily for private issuers and tests. */
  readonly verificationKey?: KeyInput | JWTVerifyGetKey;
}

export interface OidcSessionSecurityOptions<TFileMetadata = unknown> {
  readonly issuers: readonly OidcIssuerConfiguration[];
  readonly getAccessToken: (context: CredentialRequestContext) => Promise<string> | string;
  /** Defaults to requiring p2prpc:connect. */
  readonly requiredConnectionScopes?: readonly string[];
  /** Defaults to requiring RFC 7800 cnf.jkt binding to the Iroh Ed25519 peer key. */
  readonly peerBinding?: 'required' | 'optional' | 'disabled';
  /**
   * Enterprise-directory fallback when the issuer cannot mint cnf-bound tokens.
   * It must bind the verified subject/client to the authenticated Iroh peer ID.
   */
  readonly bindPrincipalToPeer?: (
    claims: Readonly<JWTPayload>,
    context: SessionAuthenticationContext
  ) => Promise<boolean> | boolean;
  readonly tenantClaim?: string;
  readonly clockToleranceSeconds?: number;
  /** Maximum age since iat. Defaults to one hour and is capped at 24 hours. */
  readonly maxTokenAge?: string | number;
  /** JOSE typ values accepted as OAuth access tokens. Defaults to only at+jwt. */
  readonly acceptedTokenTypes?: readonly string[];
  readonly authorize?: (context: AuthorizationContext<TFileMetadata>) => Promise<AuthorizationResult> | AuthorizationResult;
  /** Allows http:// JWKS only for isolated tests. */
  readonly dangerouslyAllowInsecureJwks?: boolean;
}

interface NormalizedIssuer {
  readonly issuer: string;
  readonly audience: string | string[];
  readonly algorithms: string[];
  readonly key: KeyInput | JWTVerifyGetKey;
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
): SessionSecurity<TFileMetadata> {
  validateOptions(
    options,
    [
      'issuers',
      'getAccessToken',
      'requiredConnectionScopes',
      'peerBinding',
      'bindPrincipalToPeer',
      'tenantClaim',
      'clockToleranceSeconds',
      'maxTokenAge',
      'acceptedTokenTypes',
      'authorize',
      'dangerouslyAllowInsecureJwks'
    ],
    'OIDC session security options'
  );
  if (typeof options.getAccessToken !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC access-token provider must be a function');
  }
  if (options.bindPrincipalToPeer !== undefined && typeof options.bindPrincipalToPeer !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC principal-to-peer binding must be a function');
  }
  if (options.authorize !== undefined && typeof options.authorize !== 'function') {
    throw new P2PError('UNAUTHORIZED', 'OIDC authorize policy must be a function');
  }
  if (
    options.dangerouslyAllowInsecureJwks !== undefined &&
    typeof options.dangerouslyAllowInsecureJwks !== 'boolean'
  ) {
    throw new P2PError('UNAUTHORIZED', 'dangerouslyAllowInsecureJwks must be a boolean');
  }
  const getAccessToken = options.getAccessToken;
  const bindPrincipalToPeer = options.bindPrincipalToPeer;
  const customAuthorize = options.authorize;
  const binding = normalizePeerBinding(options.peerBinding);
  const clockToleranceSeconds = normalizeClockTolerance(options.clockToleranceSeconds);
  const maxTokenAgeSeconds = normalizeMaxTokenAge(options.maxTokenAge);
  const issuers = normalizeIssuers(options);
  const connectionScopes = normalizeRequiredConnectionScopes(options.requiredConnectionScopes);
  const tenantClaim = normalizeTenantClaim(options.tenantClaim);
  const acceptedTokenTypes = normalizeAcceptedTokenTypes(options.acceptedTokenTypes);

  return {
    async getCredential(context) {
      const token = await getAccessToken(context);
      if (typeof token !== 'string' || token.length < 1 || Buffer.byteLength(token) > 48 * 1024) {
        throw new P2PError('UNAUTHORIZED', 'Access-token provider returned an invalid token');
      }
      return { scheme: 'Bearer', value: token };
    },

    async authenticate(credential, context) {
      if (credential.scheme.toLowerCase() !== 'bearer') throw new P2PError('UNAUTHORIZED', 'Expected an OAuth bearer access token');
      let unverified: JWTPayload;
      try {
        unverified = decodeJwt(credential.value);
      } catch (cause) {
        throw new P2PError('UNAUTHORIZED', 'Malformed OAuth access token', { cause });
      }
      const configuration = issuers.get(unverified.iss ?? '');
      if (!configuration) throw new P2PError('UNAUTHORIZED', 'Access token issuer is not trusted');

      let claims: JWTPayload;
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
        claims = verified.payload;
      } catch (cause) {
        throw new P2PError('UNAUTHORIZED', 'OAuth access token verification failed', { cause });
      }

      const clientId = readClientId(claims);
      const subject = readSubject(claims, clientId);
      if (claims.exp === undefined) throw new P2PError('UNAUTHORIZED', 'Access token has no expiry');
      const scopes = readScopes(claims);
      for (const required of connectionScopes) {
        if (!hasScope(scopes, required)) throw new P2PError('UNAUTHORIZED', `Access token lacks required scope ${required}`);
      }
      await verifyPeerBinding(claims, context, binding, bindPrincipalToPeer);

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
      const principal: SessionPrincipal = {
        id: stablePrincipalId(configuration.issuer, subject, clientId),
        subject,
        issuer: configuration.issuer,
        ...(clientId !== undefined ? { clientId } : {}),
        ...(typeof tenant === 'string' ? { tenantId: tenant } : {}),
        expiresAt: Math.floor(claims.exp * 1000),
        scopes,
        claims: Object.freeze({ ...claims })
      };
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
  };
}

function normalizePeerBinding(value: unknown): 'required' | 'optional' | 'disabled' {
  if (value === undefined) return 'required';
  if (value !== 'required' && value !== 'optional' && value !== 'disabled') {
    throw new P2PError('UNAUTHORIZED', 'peerBinding must be required, optional, or disabled');
  }
  return value;
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

function normalizeRequiredConnectionScopes(value: readonly string[] | undefined): ReadonlySet<string> {
  const configured: unknown = value === undefined ? ['p2prpc:connect'] : value;
  if (!Array.isArray(configured) || configured.length < 1 || configured.length > 64) {
    throw new P2PError('UNAUTHORIZED', 'OIDC required connection scopes must contain between 1 and 64 entries');
  }
  const scopes = new Set<string>();
  for (const scope of configured) {
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

function normalizeTenantClaim(value: string | undefined): string {
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

function normalizeAcceptedTokenTypes(value: readonly string[] | undefined): ReadonlySet<string> {
  const configured: unknown = value === undefined ? ['at+jwt'] : value;
  if (!Array.isArray(configured) || configured.length < 1 || configured.length > 16) {
    throw new P2PError('UNAUTHORIZED', 'OIDC accepted token types must contain between 1 and 16 entries');
  }
  const output = new Set<string>();
  for (const item of configured) {
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

function stablePrincipalId(issuer: string, subject: string, clientId: string | undefined): string {
  const digest = createHash('sha256')
    .update('p2prpc-oidc-principal-v1\n')
    .update(JSON.stringify([issuer, subject, clientId ?? null]))
    .digest('base64url');
  return `oidc:${digest}`;
}

function readClientId(claims: JWTPayload): string | undefined {
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

function readSubject(claims: JWTPayload, clientId: string | undefined): string {
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
  claims: JWTPayload,
  context: SessionAuthenticationContext,
  mode: 'required' | 'optional' | 'disabled',
  directoryBinding: OidcSessionSecurityOptions['bindPrincipalToPeer']
): Promise<void> {
  const jkt = readConfirmationThumbprint(claims);
  if (mode === 'disabled') return;
  if (jkt) {
    let expected: string;
    try {
      const bytes = PublicKey.fromString(context.remotePeerId).bytes;
      expected = await calculateJwkThumbprint({
        kty: 'OKP',
        crv: 'Ed25519',
        x: Buffer.from(bytes).toString('base64url')
      });
    } catch (cause) {
      throw new P2PError('UNAUTHORIZED', 'Invalid authenticated Iroh peer key', { cause });
    }
    if (!safeEqual(jkt, expected)) throw new P2PError('UNAUTHORIZED', 'Access token is bound to a different peer key');
    return;
  }
  if (directoryBinding && await directoryBinding(Object.freeze({ ...claims }), context) === true) return;
  if (mode === 'required') throw new P2PError('UNAUTHORIZED', 'Access token is not proof-of-possession bound to this peer');
}

function readConfirmationThumbprint(claims: JWTPayload): string | undefined {
  if (!Object.hasOwn(claims, 'cnf')) return undefined;
  const confirmation = claims.cnf;
  if (!isRecord(confirmation) || Object.keys(confirmation).length === 0) {
    throw new P2PError('UNAUTHORIZED', 'OAuth cnf claim must be a non-empty object');
  }
  if (!Object.hasOwn(confirmation, 'jkt')) {
    throw new P2PError('UNAUTHORIZED', 'OAuth cnf claim uses an unsupported confirmation method');
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

function normalizeIssuers<TFileMetadata>(options: OidcSessionSecurityOptions<TFileMetadata>): Map<string, NormalizedIssuer> {
  if (!Array.isArray(options.issuers) || options.issuers.length < 1 || options.issuers.length > 32) {
    throw new P2PError('UNAUTHORIZED', 'At least one configured OIDC issuer is required');
  }
  const output = new Map<string, NormalizedIssuer>();
  for (const configuration of options.issuers) {
    validateOptions(
      configuration,
      ['issuer', 'audience', 'algorithms', 'jwksUri', 'verificationKey'],
      'OIDC issuer configuration'
    );
    if (typeof configuration.issuer !== 'string') {
      throw new P2PError('UNAUTHORIZED', 'OIDC issuer must be a string');
    }
    const issuerUrl = validHttpsUrl(configuration.issuer, options.dangerouslyAllowInsecureJwks === true, 'issuer');
    if (issuerUrl.search) throw new P2PError('UNAUTHORIZED', 'OIDC issuer must not contain a query');
    const issuer = configuration.issuer;
    if (output.has(issuer)) throw new P2PError('UNAUTHORIZED', `Duplicate OIDC issuer ${issuer}`);
    if (
      !Array.isArray(configuration.algorithms) ||
      !configuration.algorithms.length ||
      configuration.algorithms.length > 16 ||
      configuration.algorithms.some((algorithm: unknown) => typeof algorithm !== 'string' || !safeAlgorithm(algorithm))
    ) {
      throw new P2PError('UNAUTHORIZED', 'OIDC issuer needs an explicit safe JWT algorithm allow-list');
    }
    if ((configuration.jwksUri === undefined) === (configuration.verificationKey === undefined)) {
      throw new P2PError('UNAUTHORIZED', 'Configure exactly one of jwksUri or verificationKey for each issuer');
    }
    const key = configuration.verificationKey ?? createRemoteJWKSet(
      validHttpsUrl(configuration.jwksUri!, options.dangerouslyAllowInsecureJwks === true, 'JWKS URI'),
      { timeoutDuration: 5_000, cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 }
    );
    const audience = normalizeAudience(configuration.audience);
    output.set(issuer, { issuer, audience, algorithms: [...configuration.algorithms], key });
  }
  return output;
}

function normalizeAudience(value: unknown): string | string[] {
  const valid = (item: unknown): item is string => typeof item === 'string' &&
    Buffer.byteLength(item) > 0 &&
    Buffer.byteLength(item) <= 2048 &&
    !containsUnsafeDisplayCharacters(item);
  if (valid(value)) return value;
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > 32 ||
    value.some((item) => !valid(item)) ||
    new Set(value).size !== value.length
  ) {
    throw new P2PError('UNAUTHORIZED', 'OIDC audience must be explicit, bounded, and non-empty');
  }
  return [...value] as string[];
}

function readScopes(claims: JWTPayload): ReadonlySet<string> {
  const values = new Set<string>();
  if (claims.scope !== undefined) {
    if (typeof claims.scope !== 'string') throw invalidScopeClaim();
    addSpaceDelimitedScopes(values, claims.scope);
  }
  if (claims.scp !== undefined) {
    if (typeof claims.scp === 'string') {
      addSpaceDelimitedScopes(values, claims.scp);
    } else if (Array.isArray(claims.scp) && claims.scp.length > 0 && claims.scp.length <= 1024) {
      for (const scope of claims.scp) {
        if (!validScopeToken(scope)) throw invalidScopeClaim();
        values.add(scope);
      }
    } else {
      throw invalidScopeClaim();
    }
  }
  if (values.size > 1024) throw invalidScopeClaim();
  return Object.freeze(values) as ReadonlySet<string>;
}

function addSpaceDelimitedScopes(output: Set<string>, claim: string): void {
  if (!/^[\x21\x23-\x5b\x5d-\x7e]+(?: [\x21\x23-\x5b\x5d-\x7e]+)*$/.test(claim)) {
    throw invalidScopeClaim();
  }
  for (const scope of claim.split(' ')) {
    if (!validScopeToken(scope)) throw invalidScopeClaim();
    output.add(scope);
    if (output.size > 1024) throw invalidScopeClaim();
  }
}

function validScopeToken(value: unknown): value is string {
  return typeof value === 'string' &&
    Buffer.byteLength(value) <= 1024 &&
    /^[\x21\x23-\x5b\x5d-\x7e]+$/.test(value);
}

function invalidScopeClaim(): P2PError {
  return new P2PError('UNAUTHORIZED', 'OAuth scope and scp claims must contain bounded RFC 6749 scope tokens');
}

function hasScope(scopes: ReadonlySet<string>, required: string): boolean {
  return scopes.has(required) || (required.startsWith('p2prpc:') && scopes.has('p2prpc:*'));
}

function safeAlgorithm(value: string): boolean {
  return /^(?:RS|PS|ES)(?:256|384|512)$|^EdDSA$/.test(value);
}

function validHttpsUrl(value: string | URL, allowHttp: boolean, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new P2PError('UNAUTHORIZED', `Invalid OIDC ${label}`, { cause });
  }
  if (url.username || url.password || url.hash || (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:'))) {
    throw new P2PError('UNAUTHORIZED', `OIDC ${label} must be an HTTPS URL without credentials or a fragment`);
  }
  return url;
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.byteLength === rightBytes.byteLength && timingSafeEqual(leftBytes, rightBytes);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateOptions(value: unknown, allowed: readonly string[], label: string): void {
  if (!isRecord(value)) throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new P2PError('INVALID_FRAME', `${label} must be a plain object`);
  }
  const allowedKeys = new Set(allowed);
  const unknown = Object.keys(value).find((key) => !allowedKeys.has(key));
  if (unknown !== undefined) {
    throw new P2PError('INVALID_FRAME', `${label} contains unknown field ${unknown}`);
  }
}
