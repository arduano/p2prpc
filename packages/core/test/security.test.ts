import { PublicKey } from '@momics/iroh-http-node';
import {
  SignJWT,
  UnsecuredJWT,
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair
} from 'jose';
import { describe, expect, it } from 'vitest';
import {
  createOidcSessionSecurity,
  createP2PNode,
  createSharedSecretSecurity,
  dangerouslyAllowInsecureSessions
} from '../src/index.js';
import { authenticateConnection } from '../src/security/handshake.js';
import { authorizationAllowed, freezePrincipal } from '../src/security/types.js';
import type { SessionAuthenticationContext } from '../src/security/types.js';
import type { QuicConnection } from '../src/transport/types.js';

describe('session security', () => {
  it('fails closed when JavaScript callers omit security configuration', async () => {
    await expect(createP2PNode({} as never)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('validates security mode and timing options at construction time', async () => {
    const secret = 'a'.repeat(32);
    for (const clockSkewMs of [null, -1, 0.5, 10 * 60_000 + 1, Number.NaN, '30000']) {
      expect(() => createSharedSecretSecurity(secret, { clockSkewMs: clockSkewMs as never })).toThrow(/clock skew/);
    }
    for (const sessionTtlMs of [null, 0, 24 * 60 * 60_000 + 1, Number.NaN, '60000']) {
      expect(() => dangerouslyAllowInsecureSessions({ sessionTtlMs: sessionTtlMs as never })).toThrow(/session TTL/i);
    }

    const { publicKey } = await generateKeyPair('RS256');
    const base = {
      issuers: [{
        issuer: 'https://identity.example',
        audience: 'urn:example:p2prpc',
        algorithms: ['RS256'],
        verificationKey: publicKey
      }],
      getAccessToken: () => 'token'
    } as const;
    expect(() => createOidcSessionSecurity({ ...base, peerBinding: 'requiredd' as never })).toThrow(/peerBinding/);
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
    expect(() => createOidcSessionSecurity({ ...base, issuers: null as never })).toThrow(/issuer/);
    expect(() => createSharedSecretSecurity(secret, { authorize: null as never })).toThrow(/authorize policy/);
  });

  it('binds shared-secret challenges to the nonce, protocol, and Iroh peer IDs', async () => {
    const security = createSharedSecretSecurity('a'.repeat(32));
    const issued = await security.getCredential({
      localPeerId: 'peer-a',
      remotePeerId: 'peer-b',
      direction: 'outbound',
      protocol: 'p2prpc/2/test/1',
      nonce: 'nonce-a',
      signal: new AbortController().signal
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'peer-b',
      remotePeerId: 'peer-a',
      direction: 'inbound',
      protocol: 'p2prpc/2/test/1',
      initiatorPeerId: 'peer-a',
      responderPeerId: 'peer-b',
      initiatorNonce: 'nonce-a',
      responderNonce: 'nonce-b',
      presentedAt: Date.now(),
      signal: new AbortController().signal
    };
    expect(await security.authenticate(issued, context)).toMatchObject({ subject: 'peer-a' });
    await expect(Promise.resolve().then(() => security.authenticate(issued, { ...context, protocol: 'p2prpc/2/other/1' }))).rejects.toMatchObject({
      code: 'UNAUTHORIZED'
    });
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

  it('strictly verifies issuer, audience, scopes, expiry, and cnf.jkt peer binding', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = { ...await exportJWK(publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
    const peerKeys = await generateKeyPair('EdDSA');
    const peerJwk = await exportJWK(peerKeys.publicKey);
    const peerId = PublicKey.fromBytes(Buffer.from(peerJwk.x!, 'base64url')).toString();
    const jkt = await calculateJwkThumbprint(peerJwk);
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
        verificationKey: createLocalJWKSet({ keys: [verificationJwk] })
      }],
      getAccessToken: () => token
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: peerId,
      direction: 'inbound',
      protocol: 'p2prpc/2/enterprise/1',
      initiatorPeerId: peerId,
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      presentedAt: Date.now(),
      signal: new AbortController().signal
    };
    const principal = await security.authenticate({ scheme: 'Bearer', value: token }, context);
    expect(principal).toMatchObject({ subject: 'service-a', tenantId: 'tenant-a', issuer });
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
        verificationKey: createLocalJWKSet({ keys: [verificationJwk] })
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

  it('rejects malformed identity, scope, and confirmation claims instead of treating them as absent', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = { ...await exportJWK(publicKey), kid: 'strict-key', alg: 'RS256', use: 'sig' };
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
        verificationKey: createLocalJWKSet({ keys: [verificationJwk] })
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
      protocol: 'p2prpc/2/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      presentedAt: Date.now(),
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
    for (const cnf of [null, [], {}, { kid: 'unsupported' }, { jkt: '' }, { jkt: 7 }, { jkt: 'x'.repeat(43) }]) {
      await expect(authenticate({ cnf })).rejects.toThrow(/cnf/);
    }
    expect(directoryBindingAttempts).toBe(1);
  });

  it('preserves verified OAuth client identity and rejects conflicting client claims', async () => {
    const issuer = 'https://identity.example';
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const verificationJwk = { ...await exportJWK(publicKey), kid: 'client-key', alg: 'RS256', use: 'sig' };
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
        verificationKey: createLocalJWKSet({ keys: [verificationJwk] })
      }],
      getAccessToken: () => '',
      peerBinding: 'disabled'
    });
    const context: SessionAuthenticationContext = {
      localPeerId: 'local-peer',
      remotePeerId: 'remote-peer',
      direction: 'inbound',
      protocol: 'p2prpc/2/enterprise/1',
      initiatorPeerId: 'remote-peer',
      responderPeerId: 'local-peer',
      initiatorNonce: 'a',
      responderNonce: 'b',
      presentedAt: Date.now(),
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
        verificationKey: createLocalJWKSet({ keys: [verificationJwk] })
      }],
      getAccessToken: () => '',
      peerBinding: 'disabled',
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

  it('aborts a hanging credential provider when the session handshake times out', async () => {
    let observedAbort = false;
    const connection: QuicConnection = {
      remoteId: 'remote-peer',
      side: 'client',
      openBi: () => Promise.reject(new Error('credential provider should time out before opening a stream')),
      acceptBi: () => Promise.reject(new Error('unexpected acceptBi')),
      openUni: () => Promise.reject(new Error('unexpected openUni')),
      acceptUni: () => Promise.reject(new Error('unexpected acceptUni')),
      closed: () => new Promise(() => undefined),
      close: () => undefined,
      stats: async () => ({ rttMs: null, sentBytes: 0, receivedBytes: 0, lostPackets: 0 }),
      configure: () => undefined
    };

    await expect(authenticateConnection(connection, 'outbound', {
      localPeerId: 'local-peer',
      protocol: 'p2prpc/2/timeout/1',
      timeoutMs: 10,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 1024 },
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
    })).rejects.toMatchObject({ code: 'TIMEOUT' });
    expect(observedAbort).toBe(true);
  });

  it('applies configured control-frame limits to outbound handshake credentials', async () => {
    let writtenBytes = 0;
    const connection: QuicConnection = {
      remoteId: 'remote-peer',
      side: 'client',
      openBi: async () => ({
        send: {
          writeAll: async (bytes: Uint8Array) => { writtenBytes += bytes.byteLength; },
          finish: async () => undefined,
          reset: async () => undefined,
          setPriority: async () => undefined
        },
        recv: {
          readExact: async () => { throw new Error('handshake frame should be rejected before a read'); },
          stop: async () => undefined
        }
      }),
      acceptBi: () => Promise.reject(new Error('unexpected acceptBi')),
      openUni: () => Promise.reject(new Error('unexpected openUni')),
      acceptUni: () => Promise.reject(new Error('unexpected acceptUni')),
      closed: () => new Promise(() => undefined),
      close: () => undefined,
      stats: async () => ({ rttMs: null, sentBytes: 0, receivedBytes: 0, lostPackets: 0 }),
      configure: () => undefined
    };

    await expect(authenticateConnection(connection, 'outbound', {
      localPeerId: 'local-peer',
      protocol: 'p2prpc/2/frame-limit/1',
      timeoutMs: 1_000,
      maxSessionTtlMs: 60_000,
      clockSkewMs: 30_000,
      frameLimits: { maxControlFrameBytes: 1024 },
      security: {
        getCredential: () => ({ scheme: 'Bearer', value: 'x'.repeat(2_000) }),
        authenticate: () => { throw new Error('unexpected authentication'); },
        authorize: () => false
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(writtenBytes).toBe(1);
  });
});

function emptyManifest() {
  return { transferId: 'transfer', name: 'empty', size: 0, digest: '0'.repeat(64), chunkSize: 64 * 1024, chunkCount: 0 };
}

function differentPeerId(peerId: string): string {
  const bytes = PublicKey.fromString(peerId).bytes;
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return PublicKey.fromBytes(bytes).toString();
}
