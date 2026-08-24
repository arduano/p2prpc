import { PublicKey } from '@momics/iroh-http-node';
import { generateKeyPairSync, webcrypto, type KeyObject } from 'node:crypto';
import {
  SignJWT,
  UnsecuredJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair
} from 'jose';
import { describe, expect, it, vi } from 'vitest';
import {
  createOidcSessionSecurity,
  createP2PNode,
  createSharedSecretSecurity,
  irohPeerIdJwkThumbprint
} from '../src/index.js';
import { dangerouslyAllowInsecureSessions } from '../src/security/shared-secret.js';
import { SessionFrameKind, StreamKind, readFrame, readStreamKind, writeFrame, writeStreamKind } from '../src/protocol.js';
import { authenticateConnection } from '../src/security/handshake.js';
import { authorizationAllowed, freezePrincipal, isPeerBoundSessionSecurity } from '../src/security/types.js';
import type { SessionAuthenticationContext } from '../src/security/types.js';
import type {
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicRecvStream,
  QuicSendStream
} from '../src/transport/types.js';

async function rs256PublicJwk(key: Parameters<typeof exportJWK>[0], kid: string) {
  const exported = await exportJWK(key);
  if (exported.kty !== 'RSA' || typeof exported.n !== 'string' || typeof exported.e !== 'string') {
    throw new Error('Expected an RSA public key');
  }
  return {
    kty: 'RSA' as const,
    n: exported.n,
    e: exported.e,
    kid,
    alg: 'RS256' as const,
    use: 'sig' as const
  };
}

describe('session security', () => {
  it('fails closed when JavaScript callers omit security configuration', async () => {
    await expect(createP2PNode({} as never)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('validates security mode and timing options at construction time', async () => {
    const secret = 'a'.repeat(32);
    for (const clockSkewMs of [null, -1, 0.5, 10 * 60_000 + 1, Number.NaN, '30000']) {
      expect(() => createSharedSecretSecurity(secret, {
        clockSkewMs: clockSkewMs as never,
        authorize: () => false
      })).toThrow(/clock skew/);
    }
    for (const sessionTtlMs of [null, 0, 24 * 60 * 60_000 + 1, Number.NaN, '60000']) {
      expect(() => dangerouslyAllowInsecureSessions({ sessionTtlMs: sessionTtlMs as never })).toThrow(/session TTL/i);
    }

    const { publicKey } = await generateKeyPair('RS256');
    const publicJwk = await rs256PublicJwk(publicKey, 'config-key');
    const base = {
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: publicKey
      }],
      getAccessToken: () => 'token'
    } as const;
    for (const peerBinding of ['required', 'optional', 'disabled']) {
      expect(() => createOidcSessionSecurity({
        ...base,
        peerBinding
      } as never)).toThrow(/unknown field peerBinding/);
    }
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], issuer: 'https://identity.example?tenant=a' }]
    })).toThrow(/issuer.*query/i);
    for (const clockToleranceSeconds of [-1, 0.5, 601, Number.NaN, '30']) {
      expect(() => createOidcSessionSecurity({
        ...base,
        clockToleranceSeconds: clockToleranceSeconds as never
      })).toThrow(/clock tolerance/);
    }
    for (const maxTokenAge of [0, 0.5, 24 * 60 * 60 + 1, Number.NaN, 'forever', '2 days']) {
      expect(() => createOidcSessionSecurity({
        ...base,
        maxTokenAge: maxTokenAge as never
      })).toThrow(/token age/);
    }
    for (const requiredConnectionScopes of [[], ['duplicate', 'duplicate'], ['bad scope'], ['line\nbreak'], 'scope']) {
      expect(() => createOidcSessionSecurity({
        ...base,
        requiredConnectionScopes: requiredConnectionScopes as never
      })).toThrow(/connection scopes/);
    }
    for (const malformed of [null, false]) {
      expect(() => createOidcSessionSecurity({ ...base, authorize: malformed as never })).toThrow(/authorize policy/);
      expect(() => createOidcSessionSecurity({
        ...base,
        bindPrincipalToPeer: malformed as never
      })).toThrow(/principal-to-peer binding/);
    }
    expect(() => createOidcSessionSecurity({
      ...base,
      getAccessToken: null as never
    })).toThrow(/token provider/);
    expect(() => createOidcSessionSecurity({
      ...base,
      requiredConnectionScopes: null as never
    })).toThrow(/connection scopes/);
    for (const acceptedTokenTypes of [null, [], [''], ['bad type'], ['AT+JWT', 'at+jwt']]) {
      expect(() => createOidcSessionSecurity({
        ...base,
        acceptedTokenTypes: acceptedTokenTypes as never
      })).toThrow(/token types/);
    }
    for (const tenantClaim of [null, '', 'tenant\nclaim', '__proto__']) {
      expect(() => createOidcSessionSecurity({
        ...base,
        tenantClaim: tenantClaim as never
      })).toThrow(/tenant claim/);
    }
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], audience: ['audience', 1] as never }]
    })).toThrow(/audience/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], algorithms: ['RS256', 'RS256'] }]
    })).toThrow(/unique.*algorithm/i);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], jwks: { keys: [] } }]
    } as never)).toThrow(/exactly one/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [] }
      }]
    })).toThrow(/between 1 and 64 entries/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: Array.from({ length: 65 }, () => ({})) }
      }]
    } as never)).toThrow(/between 1 and 64 entries/);
    let jwksGetterCalls = 0;
    const accessorJwks = Object.defineProperty({}, 'keys', {
      enumerable: true,
      get: () => {
        jwksGetterCalls += 1;
        return [{}];
      }
    });
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: accessorJwks as never
      }]
    })).toThrow(/enumerable data property/);
    expect(jwksGetterCalls).toBe(0);
    const invalidStaticSets: Array<{ algorithms: string[]; jwks: unknown }> = [
      { algorithms: ['RS256'], jwks: { keys: [{}] } },
      { algorithms: ['RS256'], jwks: { keys: [{ ...publicJwk, kid: 'x'.repeat(257) }] } },
      { algorithms: ['RS256'], jwks: { keys: [{ ...publicJwk, key_ops: ['sign'] }] } },
      { algorithms: ['RS256'], jwks: { keys: [publicJwk, { ...publicJwk }] } },
      {
        algorithms: ['RS256'],
        jwks: { keys: [{ ...publicJwk, kid: undefined }, { ...publicJwk, kid: undefined }] }
      },
      {
        algorithms: ['ES384'],
        jwks: { keys: [{
          kty: 'EC',
          alg: 'ES384',
          crv: 'P-256',
          x: Buffer.alloc(32).toString('base64url'),
          y: Buffer.alloc(32).toString('base64url'),
          kid: 'wrong-curve'
        }] }
      },
      {
        algorithms: ['RS256'],
        jwks: { keys: [{ ...publicJwk, kid: 'private-key', d: 'AQ' }] }
      }
    ];
    for (const invalid of invalidStaticSets) {
      expect(() => createOidcSessionSecurity({
        ...base,
        issuers: [{
          issuer: 'https://identity.example',
          audience: 'urn:example:p2prpc',
          algorithms: invalid.algorithms,
          jwks: invalid.jwks
        }]
      } as never)).toThrow();
    }
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], verificationKey: publicKey, jwksUri: 'https://identity.example/jwks' }]
    } as never)).toThrow(/exactly one/);
    expect(() => createOidcSessionSecurity({ ...base, issuers: null as never })).toThrow(/issuer/);
    expect(() => createOidcSessionSecurity({
      ...base,
      authorise: () => false
    } as never)).toThrow(/unknown field authorise/);
    expect(() => createOidcSessionSecurity({
      ...base,
      dangerouslyAllowInsecureJwks: 'true'
    } as never)).toThrow(/unknown field dangerouslyAllowInsecureJwks/);
    expect(() => createOidcSessionSecurity({
      ...base,
      dangerouslyAllowInsecureJwks: true,
      issuers: [{ ...base.issuers[0], issuer: 'http://identity.example' }]
    } as never)).toThrow(/unknown field dangerouslyAllowInsecureJwks/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwksUri: 'http://identity.example/.well-known/jwks.json'
      }]
    })).toThrow(/JWKS URI must be an HTTPS URL/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], algorithims: ['RS256'] }]
    } as never)).toThrow(/unknown field algorithims/);
    expect(() => createOidcSessionSecurity(Object.assign(
      Object.create({}),
      base
    ) as never)).toThrow(/plain object/);
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [Object.assign(Object.create({}), base.issuers[0])]
    } as never)).toThrow(/plain object/);
    let optionGetterCalls = 0;
    const accessorOptions = Object.defineProperty({ ...base }, 'getAccessToken', {
      enumerable: true,
      get: () => {
        optionGetterCalls += 1;
        return () => 'token';
      }
    });
    expect(() => createOidcSessionSecurity(accessorOptions as never)).toThrow(/enumerable data properties/);
    expect(optionGetterCalls).toBe(0);
    let algorithmGetterCalls = 0;
    const accessorAlgorithms = ['RS256'];
    Object.defineProperty(accessorAlgorithms, '0', {
      enumerable: true,
      get: () => {
        algorithmGetterCalls += 1;
        return 'RS256';
      }
    });
    expect(() => createOidcSessionSecurity({
      ...base,
      issuers: [{ ...base.issuers[0], algorithms: accessorAlgorithms as never }]
    })).toThrow(/enumerable data items/);
    expect(algorithmGetterCalls).toBe(0);
    expect(() => createSharedSecretSecurity(secret, { authorize: null as never })).toThrow(/authorize policy/);
    expect(() => createSharedSecretSecurity(secret, {} as never)).toThrow(/authorize policy/);
    expect(() => createSharedSecretSecurity(secret, undefined as never)).toThrow(/plain object/);
    expect(() => createSharedSecretSecurity(secret, { authorise: () => false } as never)).toThrow(/unknown field/);
    expect(() => dangerouslyAllowInsecureSessions({ ttlMs: 60_000 } as never)).toThrow(/unknown field/);
  });

  it('binds shared-secret credentials to both nonces, the transcript, role, protocol, and Iroh peer IDs', async () => {
    const security = createSharedSecretSecurity('a'.repeat(32), { authorize: () => true });
    const now = Date.now();
    const issued = await security.getCredential({
      localPeerId: 'peer-a',
      remotePeerId: 'peer-b',
      direction: 'outbound',
      protocol: 'p2prpc/3/test/1',
      role: 'initiator',
      initiatorPeerId: 'peer-a',
      responderPeerId: 'peer-b',
      initiatorNonce: 'nonce-a',
      responderNonce: 'nonce-b',
      initiatorPresentedAt: now,
      responderPresentedAt: now + 1,
      transcriptHash: 'transcript-a',
      signal: new AbortController().signal
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'peer-b',
      remotePeerId: 'peer-a',
      direction: 'inbound',
      protocol: 'p2prpc/3/test/1',
      role: 'initiator',
      initiatorPeerId: 'peer-a',
      responderPeerId: 'peer-b',
      initiatorNonce: 'nonce-a',
      responderNonce: 'nonce-b',
      initiatorPresentedAt: now,
      responderPresentedAt: now + 1,
      transcriptHash: 'transcript-a',
      signal: new AbortController().signal
    };
    expect(await security.authenticate(issued, context)).toMatchObject({ subject: 'peer-a' });
    for (const changed of [
      { protocol: 'p2prpc/3/other/1' },
      { initiatorNonce: 'nonce-changed' },
      { responderNonce: 'nonce-changed' },
      { transcriptHash: 'transcript-changed' },
      { role: 'responder' as const }
    ]) {
      await expect(Promise.resolve().then(() => security.authenticate(issued, { ...context, ...changed })))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
  });

  it('fails closed when a configured shared-secret authorization hook returns no decision', async () => {
    const security = createSharedSecretSecurity('a'.repeat(32), {
      authorize: () => undefined as never
    });
    const result = await security.authorize({
      principal: freezePrincipal({
        id: 'principal',
        subject: 'subject',
        expiresAt: Date.now() + 60_000,
        scopes: new Set(['p2prpc:*']),
        claims: {}
      }),
      localPeerId: 'local',
      remotePeerId: 'remote',
      sessionId: 'session',
      action: { kind: 'rpc', path: 'ping', type: 'query', headers: {} },
      signal: new AbortController().signal
    });
    expect(() => authorizationAllowed(result)).toThrow(/invalid decision/);
  });

  it('uses the mandatory shared-secret authorization policy for every operation', async () => {
    const security = createSharedSecretSecurity('a'.repeat(32), { authorize: () => false });
    expect(isPeerBoundSessionSecurity(security)).toBe(true);
    expect(Object.isFrozen(security)).toBe(true);
    expect(isPeerBoundSessionSecurity(dangerouslyAllowInsecureSessions())).toBe(false);
    const reflectedClone = Object.freeze(Object.defineProperties(
      {
        getCredential: security.getCredential,
        authenticate: security.authenticate,
        authorize: security.authorize
      },
      Object.getOwnPropertyDescriptors(security)
    ));
    expect(isPeerBoundSessionSecurity(reflectedClone)).toBe(false);
    const result = await security.authorize({
      principal: freezePrincipal({
        id: 'principal',
        subject: 'subject',
        expiresAt: Date.now() + 60_000,
        scopes: new Set(['p2prpc:*']),
        claims: {}
      }),
      localPeerId: 'local',
      remotePeerId: 'remote',
      sessionId: 'session',
      action: { kind: 'rpc', path: 'ping', type: 'query', headers: {} },
      signal: new AbortController().signal
    });
    expect(result).toBe(false);
  });

  it('strictly verifies issuer, audience, scopes, expiry, and cnf.jkt peer binding', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'test-key');
    const peerKeys = await generateKeyPair('EdDSA');
    const peerJwk = await exportJWK(peerKeys.publicKey);
    const peerId = PublicKey.fromBytes(Buffer.from(peerJwk.x!, 'base64url')).toString();
    const jkt = await calculateJwkThumbprint(peerJwk);
    expect(await irohPeerIdJwkThumbprint(peerId)).toBe(jkt);
    const token = await new SignJWT({
      scope: 'p2prpc:connect p2prpc:rpc:invoice.get p2prpc:file:pull',
      tenant_id: 'tenant-a',
      cnf: { jkt }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => token
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: peerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };
    const principal = await security.authenticate({ scheme: 'Bearer', value: token }, context);
    expect(principal).toMatchObject({ subject: 'service-a', tenantId: 'tenant-a', issuer });
    expect((await security.authenticate({ scheme: 'Bearer', value: token }, context)).id).toBe(principal.id);
    const otherTenantToken = await new SignJWT({
      scope: 'p2prpc:connect',
      tenant_id: 'tenant-b',
      cnf: { jkt }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const noTenantToken = await new SignJWT({
      scope: 'p2prpc:connect',
      cnf: { jkt }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const otherTenantPrincipal = await security.authenticate(
      { scheme: 'Bearer', value: otherTenantToken },
      context
    );
    const noTenantPrincipal = await security.authenticate(
      { scheme: 'Bearer', value: noTenantToken },
      context
    );
    expect(otherTenantPrincipal.id).not.toBe(principal.id);
    expect(noTenantPrincipal.id).not.toBe(principal.id);
    expect(noTenantPrincipal.id).not.toBe(otherTenantPrincipal.id);
    const malformedTenant = await new SignJWT({
      scope: 'p2prpc:connect',
      tenant_id: ['tenant-a'],
      cnf: { jkt }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    await expect(security.authenticate({ scheme: 'Bearer', value: malformedTenant }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(await security.authorize({
      principal,
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      sessionId: 'session',
      action: { kind: 'rpc', path: 'invoice.get', type: 'query', headers: {} },
      signal: new AbortController().signal
    })).toBe(true);
    expect(await security.authorize({
      principal,
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      sessionId: 'session',
      action: { kind: 'file.push', manifest: emptyManifest() },
      signal: new AbortController().signal
    })).toBe(false);
    const customPolicy = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => token,
      authorize: () => true
    });
    expect(await customPolicy.authorize({
      principal,
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      sessionId: 'session',
      action: { kind: 'file.push', manifest: emptyManifest() },
      signal: new AbortController().signal
    })).toBe(false);
    await expect(security.authenticate({ scheme: 'Bearer', value: token }, { ...context, remotePeerId: differentPeerId(peerId) }))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const wrongAudience = await new SignJWT({
      scope: 'p2prpc:connect',
      cnf: { jkt }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:other-service')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    await expect(security.authenticate({ scheme: 'Bearer', value: wrongAudience }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const now = Math.floor(Date.now() / 1000);
    const expired = await new SignJWT({ scope: 'p2prpc:connect', cnf: { jkt } })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt(now - 300)
      .setExpirationTime(now - 60)
      .sign(privateKey);
    await expect(security.authenticate({ scheme: 'Bearer', value: expired }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const stale = await new SignJWT({ scope: 'p2prpc:connect', cnf: { jkt } })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt(now - 2 * 60 * 60)
      .setExpirationTime(now + 5 * 60)
      .sign(privateKey);
    await expect(security.authenticate({ scheme: 'Bearer', value: stale }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const unsecured = new UnsecuredJWT({ scope: 'p2prpc:connect', cnf: { jkt } })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .encode();
    await expect(security.authenticate({ scheme: 'Bearer', value: unsecured }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('never lets an arbitrary key resolver or token jku choose an OIDC trust root', async () => {
    const issuer = 'https://identity.example';
    const trusted = await generateKeyPair('RS256');
    const attacker = await generateKeyPair('RS256');
    const trustedJwk = await rs256PublicJwk(trusted.publicKey, 'trusted-key');
    const peerKeys = await generateKeyPair('EdDSA');
    const peerJwk = await exportJWK(peerKeys.publicKey);
    const peerId = PublicKey.fromBytes(Buffer.from(peerJwk.x!, 'base64url')).toString();
    const jkt = await calculateJwkThumbprint(peerJwk);
    const forged = await new SignJWT({
      scope: 'p2prpc:connect p2prpc:rpc:admin.grant',
      cnf: { jkt }
    })
      .setProtectedHeader({
        alg: 'RS256',
        kid: 'attacker-key',
        typ: 'at+jwt',
        jku: 'https://attacker.example/jwks.json'
      })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('forged-admin')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(attacker.privateKey);

    let resolverCalls = 0;
    expect(() => createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: (() => {
          resolverCalls += 1;
          return attacker.publicKey;
        }) as never
      }],
      getAccessToken: () => forged
    })).toThrow(/verificationKey callbacks are not allowed/);
    expect(resolverCalls).toBe(0);

    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [trustedJwk] }
      }],
      getAccessToken: () => forged
    });
    await expect(security.authenticate({ scheme: 'Bearer', value: forged }, {
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      direction: 'inbound',
      protocol: 'p2prpc/4/enterprise/1',
      initiatorPeerId: peerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const mutableVerificationJwk = { ...trustedJwk };
    const singleKeySecurity = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: mutableVerificationJwk
      }],
      getAccessToken: () => forged
    });
    Object.assign(mutableVerificationJwk, {
      ...await exportJWK(attacker.publicKey),
      kid: 'attacker-key',
      alg: 'RS256',
      use: 'sig'
    });
    await expect(singleKeySecurity.authenticate({ scheme: 'Bearer', value: forged }, {
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      direction: 'inbound',
      protocol: 'p2prpc/4/enterprise/1',
      initiatorPeerId: peerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    expect(() => createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: attacker.privateKey
      }],
      getAccessToken: () => forged
    })).toThrow(/public verification key/);
  });

  it('bounds and validates fetched JWKS before JOSE can use them', async () => {
    const issuer = 'https://identity.example';
    const signingKeys = await generateKeyPair('RS256');
    const remoteJwk = { ...await exportJWK(signingKeys.publicKey), kid: 'remote-key', use: 'sig' };
    const peerKeys = await generateKeyPair('EdDSA');
    const peerJwk = await exportJWK(peerKeys.publicKey);
    const peerId = PublicKey.fromBytes(Buffer.from(peerJwk.x!, 'base64url')).toString();
    const jkt = await calculateJwkThumbprint(peerJwk);
    const token = await new SignJWT({ scope: 'p2prpc:connect', cnf: { jkt } })
      .setProtectedHeader({ alg: 'RS256', kid: 'remote-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKeys.privateKey);
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      direction: 'inbound',
      protocol: 'p2prpc/4/enterprise/1',
      initiatorPeerId: peerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };
    const createSecurity = () => createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwksUri: 'https://identity.example/.well-known/jwks.json'
      }],
      getAccessToken: () => token
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    try {
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ keys: [remoteJwk] }), { status: 200 }));
      await expect(createSecurity().authenticate({ scheme: 'Bearer', value: token }, context))
        .resolves.toMatchObject({ subject: 'service-a' });
      expect(fetchSpy).toHaveBeenCalledWith(
        'https://identity.example/.well-known/jwks.json',
        expect.objectContaining({ redirect: 'error' })
      );

      fetchSpy.mockResolvedValueOnce(new Response('x'.repeat(256 * 1024 + 1), { status: 200 }));
      await expect(createSecurity().authenticate({ scheme: 'Bearer', value: token }, context))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('validates native verification-key family, curve, hash, usage, and RSA-PSS restrictions eagerly', async () => {
    for (const [algorithm, curve] of [
      ['ES256', 'prime256v1'],
      ['ES384', 'secp384r1'],
      ['ES512', 'secp521r1']
    ] as const) {
      const { publicKey } = generateKeyPairSync('ec', { namedCurve: curve });
      expect(() => createOidcSessionSecurity({
        issuers: [{
          issuer: 'https://identity.example',
          audience: 'urn:example:p2prpc',
          algorithms: [algorithm],
          verificationKey: publicKey
        }],
        getAccessToken: () => 'unused'
      })).not.toThrow();
    }

    const rsa = await webcrypto.subtle.generateKey({
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    }, true, ['sign', 'verify']);
    const rsaJwk = await webcrypto.subtle.exportKey('jwk', rsa.publicKey);
    const noVerify = await webcrypto.subtle.importKey(
      'jwk',
      rsaJwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      []
    );
    const rsaMaterial = { ...rsaJwk };
    delete rsaMaterial.alg;
    const wrongHash = await webcrypto.subtle.importKey(
      'jwk',
      rsaMaterial,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
      true,
      ['verify']
    );
    for (const verificationKey of [noVerify, wrongHash]) {
      expect(() => createOidcSessionSecurity({
        issuers: [{
          issuer: 'https://identity.example',
          audience: 'urn:example:p2prpc',
          algorithms: ['RS256'],
          verificationKey
        }],
        getAccessToken: () => 'unused'
      })).toThrow(/usages|hash/);
    }

    const validPss = (generateKeyPairSync as unknown as (
      type: string,
      options: Record<string, unknown>
    ) => { readonly publicKey: KeyObject })('rsa-pss', {
      modulusLength: 2048,
      publicExponent: 0x10001,
      hashAlgorithm: 'sha256',
      mgf1HashAlgorithm: 'sha256',
      saltLength: 32
    }).publicKey;
    expect(() => createOidcSessionSecurity({
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['PS256'],
        verificationKey: validPss
      }],
      getAccessToken: () => 'unused'
    })).not.toThrow();
    for (const algorithms of [['RS256'], ['PS384']] as const) {
      expect(() => createOidcSessionSecurity({
        issuers: [{
          issuer: 'https://identity.example',
          audience: 'urn:example:p2prpc',
          algorithms,
          verificationKey: validPss
        }],
        getAccessToken: () => 'unused'
      })).toThrow(/incompatible|restrictions/);
    }
  });

  it('rejects invalid EC points, malformed RSA exponents, and proxy-switched JWKS bounds eagerly', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const validRsa = await rs256PublicJwk(publicKey, 'valid-rsa');
    for (const jwks of [
      { keys: [{ ...validRsa, e: 'Ag' }] },
      { keys: [{
        kty: 'EC',
        alg: 'ES256',
        crv: 'P-256',
        x: Buffer.alloc(32).toString('base64url'),
        y: Buffer.alloc(32).toString('base64url'),
        kid: 'invalid-point'
      }] }
    ]) {
      expect(() => createOidcSessionSecurity({
        issuers: [{
          issuer: 'https://identity.example',
          audience: 'urn:example:p2prpc',
          algorithms: jwks.keys[0]!.kty === 'RSA' ? ['RS256'] : ['ES256'],
          jwks
        }],
        getAccessToken: () => 'unused'
      } as never)).toThrow(/RSA JWK|importable public key/);
    }

    const keys = [validRsa];
    const switched = new Proxy(keys, {
      ownKeys(target) {
        while (target.length < 65) target.push({ ...validRsa, kid: `key-${target.length}` });
        return Reflect.ownKeys(target);
      }
    });
    expect(() => createOidcSessionSecurity({
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: switched }
      }],
      getAccessToken: () => 'unused'
    })).toThrow(/dense array|between 1 and 64 entries/);
  });

  it('requires kid on every fetched key and cools down failed remote JWKS without leaking bodies', async () => {
    const issuer = 'https://identity.example';
    const signingKeys = await generateKeyPair('RS256');
    const remoteJwk = await rs256PublicJwk(signingKeys.publicKey, 'remote-key');
    const token = await new SignJWT({ scope: 'p2prpc:connect' })
      .setProtectedHeader({ alg: 'RS256', kid: 'remote-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(signingKeys.privateKey);
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/4/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };
    const createSecurity = () => createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwksUri: 'https://identity.example/.well-known/jwks.json'
      }],
      getAccessToken: () => token,
      bindPrincipalToPeer: () => true
    });
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    try {
      const missingKid = {
        kty: remoteJwk.kty,
        n: remoteJwk.n,
        e: remoteJwk.e,
        alg: remoteJwk.alg,
        use: remoteJwk.use
      };
      fetchSpy.mockResolvedValueOnce(new Response(JSON.stringify({ keys: [missingKid] }), { status: 200 }));
      await expect(createSecurity().authenticate({ scheme: 'Bearer', value: token }, context))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      let cancellations = 0;
      const body = new ReadableStream<Uint8Array>({
        pull() { /* The non-200 path must cancel before reading. */ },
        cancel() { cancellations += 1; }
      });
      fetchSpy.mockReset();
      fetchSpy.mockResolvedValue(new Response(body, { status: 503 }));
      const security = createSecurity();
      await expect(security.authenticate({ scheme: 'Bearer', value: token }, context))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      await expect(security.authenticate({ scheme: 'Bearer', value: token }, context))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(fetchSpy).toHaveBeenCalledTimes(1);
      expect(cancellations).toBe(1);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it('rejects malformed identity, scope, and confirmation claims instead of treating them as absent', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'strict-key');
    const sign = (claims: Record<string, unknown>) => new SignJWT({
      sub: 'service-a',
      scope: 'p2prpc:connect',
      ...claims
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'strict-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    let directoryBindingAttempts = 0;
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => '',
      bindPrincipalToPeer: () => {
        directoryBindingAttempts += 1;
        return true;
      }
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };
    const authenticate = async (claims: Record<string, unknown>) => security.authenticate(
      { scheme: 'Bearer', value: await sign(claims) },
      context
    );

    await expect(authenticate({ sub: undefined, client_id: 'workload-a' }))
      .resolves.toMatchObject({ subject: 'workload-a', clientId: 'workload-a' });
    expect(directoryBindingAttempts).toBe(1);

    for (const sub of [null, 7, '', [], 'subject\nforged']) {
      await expect(authenticate({ sub, client_id: 'workload-a' })).rejects.toThrow(/sub claim/);
    }
    for (const client_id of [null, 7, '', [], 'client\nforged', 'x'.repeat(2049)]) {
      await expect(authenticate({ sub: undefined, client_id })).rejects.toThrow(/client_id claim/);
    }
    for (const malformedScope of [
      { scope: null },
      { scope: ['p2prpc:connect'] },
      { scope: 'p2prpc:connect\tp2prpc:rpc' },
      { scope: 'x'.repeat(1025) },
      { scp: [] },
      { scp: ['p2prpc:connect', 7] }
    ]) {
      await expect(authenticate(malformedScope)).rejects.toThrow(/scope and scp claims/);
    }
    await expect(authenticate({ tenant_id: [] })).rejects.toThrow(/tenant_id claim/);
    for (const cnf of [null, [], {}, { kid: 'unsupported' }, { jkt: '' }, { jkt: 7 }, { jkt: 'x'.repeat(43) }]) {
      await expect(authenticate({ cnf })).rejects.toThrow(/cnf/);
    }
    expect(directoryBindingAttempts).toBe(1);
  });

  it('requires every OIDC session to use cnf.jkt or an authoritative directory binding', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'binding-key');
    const token = await new SignJWT({ scope: 'p2prpc:connect' })
      .setProtectedHeader({ alg: 'RS256', kid: 'binding-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const options = {
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => token
    } as const;
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };

    await expect(createOidcSessionSecurity(options).authenticate(
      { scheme: 'Bearer', value: token },
      context
    )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    for (const decision of [false, undefined, null, 'yes']) {
      const security = createOidcSessionSecurity({
        ...options,
        bindPrincipalToPeer: () => decision as never
      });
      await expect(security.authenticate({ scheme: 'Bearer', value: token }, context))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }

    const directoryBound = createOidcSessionSecurity({
      ...options,
      bindPrincipalToPeer: (claims, authenticationContext) =>
        claims.sub === 'service-a' && authenticationContext.remotePeerId === 'remote-peer'
    });
    await expect(directoryBound.authenticate({ scheme: 'Bearer', value: token }, context))
      .resolves.toMatchObject({ subject: 'service-a' });
  });

  it('never lets a directory callback override a present malformed or mismatched cnf claim', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'cnf-key');
    const remoteKeys = await generateKeyPair('EdDSA');
    const otherKeys = await generateKeyPair('EdDSA');
    const remoteJwk = await exportJWK(remoteKeys.publicKey);
    const otherJwk = await exportJWK(otherKeys.publicKey);
    const remotePeerId = PublicKey.fromBytes(Buffer.from(remoteJwk.x!, 'base64url')).toString();
    const otherJkt = await calculateJwkThumbprint(otherJwk);
    const sign = (cnf: unknown) => new SignJWT({ scope: 'p2prpc:connect', cnf })
      .setProtectedHeader({ alg: 'RS256', kid: 'cnf-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    let directoryCalls = 0;
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => '',
      bindPrincipalToPeer: () => {
        directoryCalls += 1;
        return true;
      }
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId,
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: remotePeerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };

    for (const cnf of [
      { jkt: otherJkt },
      { jkt: otherJkt, kid: 'ambiguous' },
      { kid: 'unsupported' },
      null
    ]) {
      await expect(security.authenticate(
        { scheme: 'Bearer', value: await sign(cnf) },
        context
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
    expect(directoryCalls).toBe(0);
  });

  it('passes only bounded detached deeply immutable plain claims to OIDC policy', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'claims-key');
    const token = await new SignJWT({
      scope: 'p2prpc:connect',
      profile: { roles: ['reader'], attributes: { department: 'finance' } }
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'claims-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject('service-a')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    let callbackClaims: Readonly<Record<string, unknown>> | undefined;
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => token,
      bindPrincipalToPeer: (claims) => {
        callbackClaims = claims;
        const profile = claims.profile as Readonly<Record<string, unknown>>;
        const roles = profile.roles as readonly string[];
        const nested = profile.attributes as Readonly<Record<string, unknown>>;
        expect(Object.getPrototypeOf(claims)).toBeNull();
        expect(Object.getPrototypeOf(profile)).toBeNull();
        expect(Object.getPrototypeOf(nested)).toBeNull();
        expect(Object.isFrozen(claims)).toBe(true);
        expect(Object.isFrozen(profile)).toBe(true);
        expect(Object.isFrozen(roles)).toBe(true);
        expect(Object.isFrozen(nested)).toBe(true);
        expect(() => (roles as string[]).push('admin')).toThrow();
        return true;
      }
    });
    const principal = await security.authenticate({ scheme: 'Bearer', value: token }, {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    });
    expect(principal.claims).toBe(callbackClaims);
    expect(Object.isFrozen(principal)).toBe(true);
  });

  it('rejects decoded OIDC claims and scopes before they can create unbounded work', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'limits-key');
    const sign = (claims: Record<string, unknown>) => new SignJWT({
      sub: 'service-a',
      scope: 'p2prpc:connect',
      ...claims
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'limits-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => '',
      bindPrincipalToPeer: () => true
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };

    let nested: Record<string, unknown> = { leaf: true };
    for (let index = 0; index < 18; index += 1) nested = { nested };
    const tooManyItems = Array.from({ length: 1_025 }, () => null);
    const tooManyScopes = Array.from({ length: 1_025 }, () => 'x').join(' ');
    const tooManyScopeBytes = Array.from({ length: 900 }, (_, index) => `scope-${index.toString().padStart(14, '0')}`).join(' ');
    for (const claims of [{ nested }, { tooManyItems }]) {
      await expect(security.authenticate(
        { scheme: 'Bearer', value: await sign(claims) },
        context
      )).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    }
    for (const scope of [tooManyScopes, tooManyScopeBytes]) {
      await expect(security.authenticate(
        { scheme: 'Bearer', value: await sign({ scope }) },
        context
      )).rejects.toThrow(/scope and scp claims/);
    }
    const unsafeProperty = JSON.parse('{"profile":{"__proto__":{"admin":true}}}') as Record<string, unknown>;
    await expect(security.authenticate(
      { scheme: 'Bearer', value: await sign(unsafeProperty) },
      context
    )).rejects.toThrow(/unsafe property name/);
    await expect(security.authenticate(
      { scheme: 'Bearer', value: 'x'.repeat(48 * 1024 + 1) },
      context
    )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('preserves verified OAuth client identity and rejects conflicting client claims', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = await rs256PublicJwk(publicKey, 'client-key');
    const sign = (claims: Record<string, unknown>, subject = 'service-a') => new SignJWT({
      scope: 'p2prpc:connect',
      ...claims
    })
      .setProtectedHeader({ alg: 'RS256', kid: 'client-key', typ: 'at+jwt' })
      .setIssuer(issuer)
      .setAudience('urn:example:p2prpc')
      .setSubject(subject)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => '',
      bindPrincipalToPeer: () => true
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/3/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      role: 'initiator',
      initiatorPresentedAt: Date.now(),
      responderPresentedAt: Date.now(),
      transcriptHash: 'transcript',
      signal: new AbortController().signal
    };

    const matching = await sign({ client_id: 'workload-a', azp: 'workload-a' });
    const authenticated = await security.authenticate({ scheme: 'Bearer', value: matching }, context);
    expect(authenticated).toMatchObject({ clientId: 'workload-a' });
    expect(authenticated.id).toMatch(/^oidc:[A-Za-z0-9_-]{43}$/);

    const formerlyAmbiguousA = await security.authenticate(
      { scheme: 'Bearer', value: await sign({ client_id: 'b' }, 'service|a') },
      context
    );
    const formerlyAmbiguousB = await security.authenticate(
      { scheme: 'Bearer', value: await sign({ client_id: 'a|b' }, 'service') },
      context
    );
    expect(formerlyAmbiguousA.id).not.toBe(formerlyAmbiguousB.id);

    const conflicting = await sign({ client_id: 'workload-a', azp: 'workload-b' });
    await expect(security.authenticate({ scheme: 'Bearer', value: conflicting }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });

    const customScopeSecurity = createOidcSessionSecurity({
      issuers: [{
        issuer,
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        jwks: { keys: [verificationJwk] }
      }],
      getAccessToken: () => '',
      bindPrincipalToPeer: () => true,
      requiredConnectionScopes: ['org:approved']
    });
    const libraryWildcard = await sign({ scope: 'p2prpc:*' });
    await expect(customScopeSecurity.authenticate({ scheme: 'Bearer', value: libraryWildcard }, context))
      .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    const explicitlyApproved = await sign({ scope: 'p2prpc:* org:approved' });
    await expect(customScopeSecurity.authenticate({ scheme: 'Bearer', value: explicitlyApproved }, context))
      .resolves.toMatchObject({ subject: 'service-a' });
  });

  it('fails closed when a configured OIDC authorization hook returns no decision', async () => {
    const { publicKey } = await generateKeyPair('RS256');
    const security = createOidcSessionSecurity({
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: publicKey
      }],
      getAccessToken: () => 'unused',
      authorize: () => undefined as never
    });
    const result = await security.authorize({
      principal: freezePrincipal({
        id: 'principal',
        subject: 'subject',
        issuer: 'https://identity.example',
        expiresAt: Date.now() + 60_000,
        scopes: new Set(['p2prpc:rpc']),
        claims: {}
      }),
      localPeerId: 'local',
      remotePeerId: 'remote',
      sessionId: 'session',
      action: { kind: 'rpc', path: 'ping', type: 'query', headers: {} },
      signal: new AbortController().signal
    });
    expect(() => authorizationAllowed(result)).toThrow(/invalid decision/);
  });

  it('rejects unsafe OAuth client IDs in authenticated principals', () => {
    const principal = {
      id: 'principal',
      subject: 'subject',
      expiresAt: Date.now() + 60_000,
      scopes: new Set<string>(),
      claims: {}
    };
    expect(() => freezePrincipal({ ...principal, clientId: 'client\nforged' })).toThrow(/client ID/);
    expect(() => freezePrincipal({ ...principal, id: 'principal\u202eforged' })).toThrow(/id and subject/);
    expect(() => freezePrincipal({ ...principal, scopes: new Set(['p2prpc:rpc\u0085forged']) })).toThrow(/scopes/);
    expect(() => freezePrincipal({ ...principal, clientId: 'x'.repeat(2049) })).toThrow(/client ID/);
    expect(() => freezePrincipal({ ...principal, claims: null as never })).toThrow(/claims/);
    expect(() => freezePrincipal({ ...principal, claims: [] as never })).toThrow(/claims/);
  });

  it('bounds principal scope iteration and rejects cyclic, aliased, accessor, or oversized claims', () => {
    const base = {
      id: 'principal',
      subject: 'subject',
      expiresAt: Date.now() + 60_000,
      scopes: new Set(['p2prpc:connect']),
      claims: {}
    };
    const infiniteScopes = {
      *[Symbol.iterator](): Generator<string, never> {
        while (true) yield 'p2prpc:connect';
      }
    };
    expect(() => freezePrincipal({ ...base, scopes: infiniteScopes as never })).toThrow(/too many scopes/);

    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => freezePrincipal({ ...base, claims: cyclic })).toThrow(/cycles or aliases/);

    const shared = { value: true };
    expect(() => freezePrincipal({ ...base, claims: { left: shared, right: shared } }))
      .toThrow(/cycles or aliases/);

    let getterCalls = 0;
    const accessorClaims: Record<string, unknown> = {};
    Object.defineProperty(accessorClaims, 'secret', {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return 'must-not-run';
      }
    });
    expect(() => freezePrincipal({ ...base, claims: accessorClaims })).toThrow(/accessors/);
    expect(getterCalls).toBe(0);
    expect(() => freezePrincipal({ ...base, claims: { huge: 'x'.repeat(64 * 1024) } }))
      .toThrow(/byte size/);
  });

  it('does not disclose a responder credential until the challenged initiator authenticates', async () => {
    const clientToServer = new HandshakePipe();
    const serverToClient = new HandshakePipe();
    const server = handshakeConnection('server', 'client-peer', { send: serverToClient, recv: clientToServer });
    let credentialCalls = 0;
    const authentication = authenticateConnection(server, 'inbound', {
      localPeerId: 'server-peer',
      protocol: 'p2prpc/3/challenge-first/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 64 * 1024 },
      security: {
        getCredential: () => {
          credentialCalls += 1;
          return { scheme: 'Bearer', value: 'must-not-be-disclosed' };
        },
        authenticate: () => { throw new Error('invalid initiator credential'); },
        authorize: () => false
      }
    });

    const initiatorNonce = Buffer.alloc(32, 1).toString('base64url');
    await writeStreamKind(clientToServer, StreamKind.SessionAuth);
    await writeFrame(clientToServer, SessionFrameKind.ClientHello, {
      version: 3,
      protocol: 'p2prpc/3/challenge-first/1',
      nonce: initiatorNonce,
      presentedAt: Date.now()
    });
    const challenge = await readFrame<Record<string, unknown>>(serverToClient);
    expect(challenge.kind).toBe(SessionFrameKind.ServerChallenge);
    expect(Object.keys(challenge.value).sort()).toEqual(['echo', 'nonce', 'presentedAt', 'protocol', 'version']);
    expect(challenge.value.echo).toBe(initiatorNonce);
    expect(credentialCalls).toBe(0);

    await writeFrame(clientToServer, SessionFrameKind.ClientCredential, {
      credential: { scheme: 'Bearer', value: 'invalid' }
    });
    await clientToServer.finish();
    await expect(authentication).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(credentialCalls).toBe(0);
  });

  it('rejects unknown handshake fields before invoking a credential provider', async () => {
    const clientToServer = new HandshakePipe();
    const serverToClient = new HandshakePipe();
    const client = handshakeConnection('client', 'server-peer', { send: clientToServer, recv: serverToClient });
    let credentialCalls = 0;
    const authentication = authenticateConnection(client, 'outbound', {
      localPeerId: 'client-peer',
      protocol: 'p2prpc/3/closed-frames/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 64 * 1024 },
      security: {
        getCredential: () => {
          credentialCalls += 1;
          return { scheme: 'Bearer', value: 'credential' };
        },
        authenticate: () => { throw new Error('unexpected authentication'); },
        authorize: () => false
      }
    });

    expect(await readStreamKind(clientToServer)).toBe(StreamKind.SessionAuth);
    const hello = await readFrame<Record<string, unknown>>(clientToServer);
    await writeFrame(serverToClient, SessionFrameKind.ServerChallenge, {
      version: 3,
      protocol: 'p2prpc/3/closed-frames/1',
      nonce: Buffer.alloc(32, 2).toString('base64url'),
      echo: hello.value.nonce,
      presentedAt: Date.now(),
      unknown: true
    });

    await expect(authentication).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    expect(credentialCalls).toBe(0);

    const attackerToResponder = new HandshakePipe();
    const responderToAttacker = new HandshakePipe();
    const responder = handshakeConnection('server', 'attacker-peer', {
      send: responderToAttacker,
      recv: attackerToResponder
    });
    let authenticationCalls = 0;
    const responderAuthentication = authenticateConnection(responder, 'inbound', {
      localPeerId: 'responder-peer',
      protocol: 'p2prpc/3/closed-frames/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 64 * 1024 },
      security: {
        getCredential: () => {
          credentialCalls += 1;
          return { scheme: 'Bearer', value: 'credential' };
        },
        authenticate: () => {
          authenticationCalls += 1;
          throw new Error('must not authenticate a non-canonical hello');
        },
        authorize: () => false
      }
    });
    await writeStreamKind(attackerToResponder, StreamKind.SessionAuth);
    await writeFrame(attackerToResponder, SessionFrameKind.ClientHello, {
      version: 3,
      protocol: 'p2prpc/3/closed-frames/1',
      nonce: Buffer.alloc(32, 3).toString('base64url'),
      presentedAt: Date.now(),
      credential: { scheme: 'Bearer', value: 'v2-smuggled-credential' }
    });
    await expect(responderAuthentication).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    expect(authenticationCalls).toBe(0);
    expect(credentialCalls).toBe(0);
  });

  it('aborts a hanging credential provider when the session handshake times out', async () => {
    let observedAbort = false;
    const clientToServer = new HandshakePipe();
    const serverToClient = new HandshakePipe();
    const client = handshakeConnection('client', 'server-peer', { send: clientToServer, recv: serverToClient });
    const server = handshakeConnection('server', 'client-peer', { send: serverToClient, recv: clientToServer });
    const common = {
      protocol: 'p2prpc/3/timeout/1',
      timeoutMs: 50,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 1024 }
    } as const;
    const clientAuthentication = authenticateConnection(client, 'outbound', {
      ...common,
      localPeerId: 'client-peer',
      security: {
        getCredential: (context) => new Promise((_resolve, reject) => {
          context.signal.addEventListener('abort', () => {
            observedAbort = true;
            reject(context.signal.reason);
          }, { once: true });
        }),
        authenticate: () => { throw new Error('unexpected authentication'); },
        authorize: () => false
      }
    });
    const serverAuthentication = authenticateConnection(server, 'inbound', {
      ...common,
      localPeerId: 'server-peer',
      security: dangerouslyAllowInsecureSessions()
    });

    await expect(clientAuthentication).rejects.toMatchObject({ code: 'TIMEOUT' });
    await expect(serverAuthentication).rejects.toBeDefined();
    expect(observedAbort).toBe(true);
  });

  it.each([
    { side: 'client' as const, direction: 'outbound' as const },
    { side: 'server' as const, direction: 'inbound' as const }
  ])('does not let deferred $side stream cleanup extend the handshake timeout', async ({ side, direction }) => {
    const resetStarted = deferredSignal();
    const stopStarted = deferredSignal();
    const releaseReset = deferredSignal();
    const releaseStop = deferredSignal();
    const never = new Promise<never>(() => undefined);
    let resetCalls = 0;
    let stopCalls = 0;
    const stream: QuicBiStream = {
      send: {
        writeAll: () => never,
        finish: () => never,
        reset: async () => {
          resetCalls += 1;
          resetStarted.resolve();
          await releaseReset.promise;
        },
        setPriority: () => never
      },
      recv: {
        readExact: () => never,
        expectEnd: () => never,
        stop: async () => {
          stopCalls += 1;
          stopStarted.resolve();
          await releaseStop.promise;
        }
      }
    };
    const connection = handshakeConnection(side, 'remote-peer', stream);
    let settled = false;
    const authentication = authenticateConnection(connection, direction, {
      localPeerId: 'local-peer',
      protocol: 'p2prpc/3/deferred-cleanup/1',
      timeoutMs: 25,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 1024 },
      security: createSharedSecretSecurity('s'.repeat(32), { authorize: () => true })
    }).then(
      () => { settled = true; throw new Error('unexpected authentication success'); },
      (error: unknown) => { settled = true; return error; }
    );

    await Promise.all([resetStarted.promise, stopStarted.promise]);
    await expect(authentication).resolves.toMatchObject({ code: 'TIMEOUT' });
    expect(settled).toBe(true);
    expect(resetCalls).toBe(1);
    expect(stopCalls).toBe(1);

    releaseReset.resolve();
    releaseStop.resolve();
    await Promise.resolve();
    expect(resetCalls).toBe(1);
    expect(stopCalls).toBe(1);
  });

  it('finishes and consumes both successful authentication stream halves exactly once', async () => {
    const clientToServer = new HandshakePipe();
    const serverToClient = new HandshakePipe();
    const clientStream: QuicBiStream = { send: clientToServer, recv: serverToClient };
    const serverStream: QuicBiStream = { send: serverToClient, recv: clientToServer };
    const client = handshakeConnection('client', 'server-peer', clientStream);
    const server = handshakeConnection('server', 'client-peer', serverStream);
    const security = createSharedSecretSecurity('s'.repeat(32), { authorize: () => true });
    const common = {
      protocol: 'p2prpc/3/stream-lifecycle/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 64 * 1024 },
      security
    } as const;

    const [clientSession, serverSession] = await Promise.all([
      authenticateConnection(client, 'outbound', { ...common, localPeerId: 'client-peer' }),
      authenticateConnection(server, 'inbound', { ...common, localPeerId: 'server-peer' })
    ]);

    expect(clientSession.id).toBe(serverSession.id);
    for (const pipe of [clientToServer, serverToClient]) {
      expect(pipe.finishCalls).toBe(1);
      expect(pipe.expectEndCalls).toBe(1);
      expect(pipe.resetCalls).toBe(0);
      expect(pipe.stopCalls).toBe(0);
    }
  });

  it('rejects trailing authentication bytes before granting a session', async () => {
    const clientToServer = new HandshakePipe(true);
    const serverToClient = new HandshakePipe();
    const client = handshakeConnection('client', 'server-peer', {
      send: clientToServer,
      recv: serverToClient
    });
    const server = handshakeConnection('server', 'client-peer', {
      send: serverToClient,
      recv: clientToServer
    });
    const security = createSharedSecretSecurity('s'.repeat(32), { authorize: () => true });
    const common = {
      protocol: 'p2prpc/3/trailing-auth/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 64 * 1024 },
      security
    } as const;

    const outcomes = await Promise.allSettled([
      authenticateConnection(client, 'outbound', { ...common, localPeerId: 'client-peer' }),
      authenticateConnection(server, 'inbound', { ...common, localPeerId: 'server-peer' })
    ]);

    expect(outcomes.every((outcome) => outcome.status === 'rejected')).toBe(true);
    expect(clientToServer.expectEndCalls).toBe(1);
    expect(clientToServer.stopCalls).toBeGreaterThan(0);
    expect(serverToClient.resetCalls).toBeGreaterThan(0);
  });

  it('applies configured control-frame limits to outbound handshake credentials', async () => {
    const clientToServer = new HandshakePipe();
    const serverToClient = new HandshakePipe();
    const client = handshakeConnection('client', 'server-peer', { send: clientToServer, recv: serverToClient });
    const server = handshakeConnection('server', 'client-peer', { send: serverToClient, recv: clientToServer });
    const common = {
      protocol: 'p2prpc/3/frame-limit/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 1024 }
    } as const;
    const clientAuthentication = authenticateConnection(client, 'outbound', {
      ...common,
      localPeerId: 'client-peer',
      security: {
        getCredential: () => ({ scheme: 'Bearer', value: 'x'.repeat(2_000) }),
        authenticate: () => { throw new Error('unexpected authentication'); },
        authorize: () => false
      }
    });
    const serverAuthentication = authenticateConnection(server, 'inbound', {
      ...common,
      localPeerId: 'server-peer',
      security: dangerouslyAllowInsecureSessions()
    });

    await expect(clientAuthentication).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    await expect(serverAuthentication).rejects.toBeDefined();
    expect(clientToServer.writtenBytes).toBeGreaterThan(1);
    expect(clientToServer.resetCalls).toBe(1);
    expect(serverToClient.stopCalls).toBeGreaterThanOrEqual(1);
  });
});

class HandshakePipe implements QuicSendStream, QuicRecvStream {
  finishCalls = 0;
  expectEndCalls = 0;
  resetCalls = 0;
  stopCalls = 0;
  writtenBytes = 0;
  private readonly bytes: number[] = [];
  private readonly waiters: Array<() => void> = [];
  private ended = false;

  constructor(private readonly appendTrailingByteOnFinish = false) {}

  async writeAll(data: Uint8Array): Promise<void> {
    this.writtenBytes += data.byteLength;
    this.bytes.push(...data);
    this.wake();
  }

  async readExact(size: number): Promise<Uint8Array> {
    while (this.bytes.length < size) {
      if (this.ended) throw new Error('EOF');
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    return Uint8Array.from(this.bytes.splice(0, size));
  }

  async finish(): Promise<void> {
    this.finishCalls += 1;
    if (this.appendTrailingByteOnFinish) this.bytes.push(0xff);
    this.ended = true;
    this.wake();
  }

  async expectEnd(): Promise<void> {
    this.expectEndCalls += 1;
    while (!this.ended && this.bytes.length === 0) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    if (!this.ended || this.bytes.length !== 0) throw new Error('Expected clean EOF');
  }

  async reset(): Promise<void> {
    this.resetCalls += 1;
    this.ended = true;
    this.wake();
  }

  async stop(): Promise<void> {
    this.stopCalls += 1;
    this.ended = true;
    this.wake();
  }

  async setPriority(): Promise<void> {}

  private wake(): void {
    for (const waiter of this.waiters.splice(0)) waiter();
  }
}

function handshakeConnection(side: 'client' | 'server', remoteId: string, stream: QuicBiStream): QuicConnection {
  return {
    remoteId,
    side,
    openBi: async () => {
      if (side !== 'client') throw new Error('unexpected openBi');
      return stream;
    },
    acceptBi: async () => {
      if (side !== 'server') throw new Error('unexpected acceptBi');
      return stream;
    },
    openUni: () => Promise.reject(new Error('unexpected openUni')),
    acceptUni: () => Promise.reject(new Error('unexpected acceptUni')),
    closed: () => new Promise(() => undefined),
    close: () => undefined,
    stats: async () => testConnectionStats()
  };
}

function testConnectionStats(): ConnectionStats {
  return {
    connectionId: 'test-connection',
    rttMs: null,
    sentBytes: 0,
    receivedBytes: 0,
    lostPackets: 0,
    sentPackets: 0,
    congestionWindow: null,
    relay: null,
    relayUrl: null,
    paths: [],
    streams: {
      openedBi: 0,
      acceptedBi: 0,
      openedUni: 0,
      acceptedUni: 0,
      activeSend: 0,
      activeRecv: 0,
      sendFinished: 0,
      sendReset: 0,
      recvEof: 0,
      recvStopped: 0
    }
  };
}

function deferredSignal(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((accept) => { resolve = accept; });
  return { promise, resolve };
}

function emptyManifest() {
  return { transferId: 'transfer', name: 'empty', size: 0, digest: '0'.repeat(64), chunkSize: 64 * 1024, chunkCount: 0 };
}

function differentPeerId(peerId: string): string {
  const bytes = PublicKey.fromString(peerId).bytes;
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return PublicKey.fromBytes(bytes).toString();
}
