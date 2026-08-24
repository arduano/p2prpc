import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import {
  P2PError,
  type AuthenticatedSession,
  type ConnectOptions,
  type SecurityAuditEvent
} from '../src/index.js';
import {
  createAdvancedP2PNode as createP2PNode,
  type AdvancedP2PNodeOptions as P2PNodeOptions
} from '../src/node.js';
import { StreamKind, TransferFrameKind, readFrame, writeFrame, writeStreamKind } from '../src/protocol.js';
import type { ShareRegistry } from '../src/files/share.js';
import type {
  ConnectionStats,
  QuicBiStream,
  QuicConnection,
  QuicEndpoint,
  EndpointLocator,
  QuicRecvStream,
  QuicSendStream
} from '../src/transport/types.js';
import { IrohEndpoint } from '../src/transport/iroh.js';

const t = initTRPC.create();
const router = t.router({
  ping: t.procedure.query(() => 'pong')
});
const DEFAULT_MINIMUM_FILE_BUFFER = 3 * 1024 * 1024 + 2 * (4 * 1024 * 1024 + 64 * 1024);

describe('node security boundaries', () => {
  it('passes a signal to peer admission and aborts it at the handshake deadline', async () => {
    const connection = new AdmissionConnection();
    const endpoint = new AdmissionEndpoint(connection);
    let admissionSignal: AbortSignal | undefined;
    let admissionPeerFrozen = false;
    const admission = deferred<boolean>();
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      preAuthorizePeer: (peer, signal) => {
        admissionPeerFrozen = Object.isFrozen(peer);
        admissionSignal = signal;
        return admission.promise;
      },
      limits: { handshakeTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      resources: { snapshot(): { active: { handshakes: number; callbacks: number } } };
    };

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(admissionSignal).toBeDefined();
      expect(admissionSignal?.aborted).toBe(true);
      expect(admissionPeerFrozen).toBe(true);
      expect(connection.closeCalls).toBe(1);
      expect(internals.resources.snapshot().active).toMatchObject({ handshakes: 1, callbacks: 1 });
      admission.resolve(false);
      await expect.poll(() => internals.resources.snapshot().active).toMatchObject({ handshakes: 0, callbacks: 0 });
    } finally {
      await node.close();
    }
  });

  it('keeps existing one-argument peer admission callbacks source compatible', () => {
    const admission: NonNullable<P2PNodeOptions<typeof router>['preAuthorizePeer']> = () => true;
    expect(admission({ id: 'remote', direction: 'inbound' }, new AbortController().signal)).toBe(true);
  });

  it('bounds rate-limited native close drains before accepting another connection', async () => {
    const endpoint = new InboundEndpoint();
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: {
        maxPendingHandshakes: 1,
        handshakeGlobalBurst: 4,
        handshakeGlobalRatePerSecond: 1,
        handshakePeerBurst: 1,
        handshakePeerRatePerSecond: 1
      },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      rejectedConnections: Set<Promise<void>>;
    };
    internals.authenticate = async () => {
      throw new P2PError('UNAUTHORIZED', 'reject the admitted test connection');
    };
    const admitted = new AdmissionConnection(false, 'remote', 'server');
    const stalledRejection = new AdmissionConnection(false, 'remote', 'server', false);
    const queued = new AdmissionConnection(false, 'remote', 'server');

    try {
      endpoint.queue(admitted);
      await expect.poll(() => admitted.closeCalls).toBe(1);

      endpoint.queue(stalledRejection);
      await expect.poll(() => stalledRejection.closeCalls).toBe(1);
      expect(internals.rejectedConnections.size).toBe(1);

      endpoint.queue(queued);
      await Promise.resolve();
      await Promise.resolve();
      expect(endpoint.acceptCalls).toBe(2);
      expect(queued.closeCalls).toBe(0);

      stalledRejection.resolveClosed();
      await expect.poll(() => queued.closeCalls).toBe(1);
      expect(endpoint.acceptCalls).toBeGreaterThanOrEqual(3);
    } finally {
      stalledRejection.resolveClosed();
      await node.close();
    }
  });

  it('rejects an unexpected outbound endpoint before admission or credential disclosure', async () => {
    const connection = new AdmissionConnection(true, 'attacker');
    const endpoint = new AdmissionEndpoint(connection);
    let admissionCalls = 0;
    let credentialCalls = 0;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: {
        ...unusedSecurity(),
        getCredential: () => {
          credentialCalls += 1;
          throw new Error('Credential must not be requested for an unexpected endpoint');
        }
      },
      preAuthorizePeer: () => {
        admissionCalls += 1;
        return true;
      },
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket, 'approved')))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(admissionCalls).toBe(0);
      expect(credentialCalls).toBe(0);
      expect(endpoint.expectedPeerIds).toEqual(['approved']);
      expect(connection.closeCalls).toBe(1);
      expect(node.peersSnapshot()).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects outbound endpoint admission before requesting a credential', async () => {
    const connection = new AdmissionConnection(true);
    const endpoint = new AdmissionEndpoint(connection);
    let credentialCalls = 0;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: {
        ...unusedSecurity(),
        getCredential: () => {
          credentialCalls += 1;
          throw new Error('Credential must not be requested for a rejected endpoint');
        }
      },
      preAuthorizePeer: () => false,
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket)))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(credentialCalls).toBe(0);
      expect(connection.closeCalls).toBe(1);
      expect(node.peersSnapshot()).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects a mismatched authenticated principal before installing or exposing the peer', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    let exposedPeers = 0;
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onPeer: () => { exposedPeers += 1; },
      onSecurityEvent: (event) => events.push(event),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('wrong-principal', 'oauth-client-b');

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket)))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(exposedPeers).toBe(0);
      expect(node.peersSnapshot()).toHaveLength(0);
      expect(events.some((event) => event.type === 'session.authenticated')).toBe(false);
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(1);
      expect(connection.closeCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('matches shared-secret principals without OIDC fields and snapshots the target', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => sharedSecretSession('shared-secret-session', 'remote');
    const target: ConnectOptions = {
      locator: { kind: 'ticket', ticket: endpoint.address.ticket },
      expectedPeerId: 'remote',
      expectedPrincipal: {
        id: 'remote',
        subject: 'remote',
        issuer: null,
        clientId: null,
        tenantId: null
      }
    };

    try {
      const peer = await node.connect(target);
      (target as unknown as { expectedPrincipal: ConnectOptions['expectedPrincipal'] }).expectedPrincipal = {
        ...target.expectedPrincipal,
        subject: 'mutated'
      };
      const saved = (peer as unknown as {
        runtime: { outboundTarget: ConnectOptions };
      }).runtime.outboundTarget;
      expect(saved.expectedPrincipal.subject).toBe('remote');
      expect(Object.isFrozen(saved)).toBe(true);
      expect(Object.isFrozen(saved.expectedPrincipal)).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('reuses an already authenticated runtime instead of dialing a duplicate connection', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    let authenticationCalls = 0;
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => {
      authenticationCalls += 1;
      return authenticatedSession('stable-session', 'oauth-client-a');
    };

    try {
      const first = await node.connect(connectTarget(endpoint.address.ticket));
      const second = await node.connect(connectTarget(endpoint.address.ticket));
      expect(endpoint.connectCalls).toBe(1);
      expect(authenticationCalls).toBe(1);
      expect(second.session.id).toBe(first.session.id);
      expect(node.peersSnapshot()).toHaveLength(1);
    } finally {
      await node.close();
    }
  });

  it('rejects incomplete or misspelled connect targets before dialing', async () => {
    const endpoint = new AdmissionEndpoint(new AdmissionConnection(false));
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(endpoint.address.ticket as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(node.connect({
        ...connectTarget(endpoint.address.ticket),
        expectedPrincipal: { subject: 'subject' }
      } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(node.connect({
        ...connectTarget(endpoint.address.ticket),
        expectedPrinciple: connectTarget(endpoint.address.ticket).expectedPrincipal
      } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(node.connect({
        locator: { kind: 'dns' },
        expectedPrincipal: connectTarget(endpoint.address.ticket).expectedPrincipal
      } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(node.connect({
        locator: { kind: 'dns' },
        expectedPeerId: 'remote'
      } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      await expect(node.connect({
        ...connectTarget(endpoint.address.ticket),
        locator: { kind: 'dns' },
        ticket: endpoint.address.ticket
      } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      expect(endpoint.connectCalls).toBe(0);
    } finally {
      await node.close();
    }
  });

  it.each([
    { kind: 'ticket', ticket: 'signed-ticket' } as const,
    { kind: 'dns' } as const,
    { kind: 'mdns', serviceName: 'corp-p2prpc' } as const
  ])('normalizes and snapshots the $kind locator without deriving trust from discovery', async (locator) => {
    const connection = new AdmissionConnection(false);
    const endpoint = new LocatorEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('locator-session', 'oauth-client-a');
    const target: ConnectOptions = {
      locator,
      expectedPeerId: 'remote',
      expectedPrincipal: connectTarget('unused').expectedPrincipal
    };

    try {
      await node.connect(target);
      expect(endpoint.legacyConnectCalls).toBe(0);
      expect(endpoint.locators).toEqual([locator]);
      expect(endpoint.expectedPeerIds).toEqual(['remote']);
      expect(Object.isFrozen(endpoint.locators[0])).toBe(true);
      expect(endpoint.signals[0]).toBeInstanceOf(AbortSignal);
    } finally {
      await node.close();
    }
  });

  it('rejects malformed locator variants before discovery or dialing', async () => {
    const endpoint = new LocatorEndpoint(new AdmissionConnection(false));
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const principal = connectTarget('unused').expectedPrincipal;

    try {
      for (const locator of [
        { kind: 'ticket' },
        { kind: 'ticket', ticket: 'ticket', peerId: 'discovery-must-not-authorize' },
        { kind: 'dns', ticket: 'unexpected' },
        { kind: 'mdns', serviceName: '_invalid._udp' },
        { kind: 'mdns', serviceName: 'valid', principal: 'untrusted' },
        { kind: 'unknown' }
      ]) {
        await expect(node.connect({
          locator,
          expectedPeerId: 'remote',
          expectedPrincipal: principal
        } as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
      }
      expect(endpoint.locators).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects malformed optional callbacks instead of silently disabling policy', async () => {
    let factoryCalled = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      preAuthorizePeer: null as never,
      endpointFactory: async () => {
        factoryCalled = true;
        return new AdmissionEndpoint(new AdmissionConnection());
      }
    })).rejects.toThrow(/preAuthorizePeer/);
    expect(factoryCalled).toBe(false);
  });

  it('rejects unknown and inherited node, protocol, and limit options before endpoint startup', async () => {
    let factoryCalls = 0;
    const base = {
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => {
        factoryCalls += 1;
        return new AdmissionEndpoint(new AdmissionConnection());
      }
    };
    const malformed = [
      { ...base, preAuthorisePeer: () => true },
      { ...base, protocol: { ...base.protocol, contractVerison: '2' } },
      { ...base, limits: { handshakeTimoutMs: 1 } },
      Object.assign(Object.create({ inherited: true }), base),
      { ...base, protocol: Object.assign(Object.create({}), base.protocol) },
      { ...base, limits: Object.assign(Object.create({}), { handshakeTimeoutMs: 1_000 }) }
    ];

    for (const options of malformed) {
      await expect(createP2PNode(options as never)).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    }
    expect(factoryCalls).toBe(0);
  });

  it('snapshots security methods so later configuration-object mutation cannot widen access', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const security = unusedSecurity() as {
      getCredential: P2PNodeOptions<typeof router>['security']['getCredential'];
      authenticate: P2PNodeOptions<typeof router>['security']['authenticate'];
      authorize: P2PNodeOptions<typeof router>['security']['authorize'];
    };
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security,
      endpointFactory: async () => endpoint
    });
    const session = authenticatedSession('session', 'oauth-client-a');
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      authorize(
        runtime: unknown,
        session: AuthenticatedSession,
        action: { kind: 'file.pull'; capabilityId: string }
      ): Promise<void>;
    };
    internals.authenticate = async () => session;
    security.authorize = () => true;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as { runtime: unknown }).runtime;
      await expect(internals.authorize(runtime, session, { kind: 'file.pull', capabilityId: 'capability' }))
        .rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await node.close();
    }
  });

  it('validates Iroh egress configuration before starting a native endpoint', async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/test/1');
    for (const options of [
      { allowDirectAddress: null },
      { allowRelayUrl: false },
      { secretKey: null },
      { relayUrls: null },
      { relayUrls: [] },
      { relayUrls: ['http://relay.example'] },
      { relayUrls: [' https://relay.example'] },
      { relayUrls: ['https://relay.example/segment/..'] },
      { relayUrls: ['https://@relay.example'] },
      { relayUrls: ['https://relay.example:'] },
      { relayUrls: ['https://.'] },
      { relayUrls: ['https://relay.example:0'] }
    ]) {
      await expect(IrohEndpoint.create(alpn, options as never)).rejects.toBeInstanceOf(P2PError);
    }
  });

  it('rejects unknown or malformed nested Iroh configuration fields', async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/test/1');
    for (const options of [
      { relay: { mode: 'disabled', urls: ['https://relay.example'] } },
      { relay: { mode: 'custom', urls: ['https://relay.example'], fallback: true } },
      { discovery: { dns: { serverUrl: 'https://dns.example', cache: true } } },
      { discovery: { mdns: { serviceName: 'p2prpc', advertise: true, browse: true } } },
      { discovery: { dns: { serverUrl: 'http://dns.example' } } },
      { discovery: { dns: { serverUrl: 'https://user@dns.example' } } }
    ]) {
      await expect(IrohEndpoint.create(alpn, options as never)).rejects.toBeInstanceOf(P2PError);
    }
  });

  it('retains a cancelled late Iroh dial until native session closure is proven', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/late-dial-ownership/1');
    const endpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { dns: true }
    });
    const dialStarted = deferred<void>();
    const dialResult = deferred<unknown>();
    const physicallyClosed = deferred<void>();
    let closeCalls = 0;
    const internal = endpoint as unknown as {
      node: { dial(peerId: string, options: unknown): Promise<unknown> };
    };
    internal.node.dial = () => {
      dialStarted.resolve(undefined);
      return dialResult.promise;
    };
    const session = {
      ready: Promise.resolve(undefined),
      close: () => {
        closeCalls += 1;
        // A broken adapter close must not be mistaken for physical closure.
        throw new Error('synchronous close failure');
      },
      closed: physicallyClosed.promise.then(() => ({ closeCode: 4, reason: 'closed' }))
    };
    const controller = new AbortController();
    const connecting = endpoint.connectLocator(
      { kind: 'dns' },
      alpn,
      endpoint.id,
      controller.signal
    );
    let settled = false;
    void connecting.then(
      () => { settled = true; },
      () => { settled = true; }
    );

    try {
      await dialStarted.promise;
      controller.abort(new P2PError('CANCELLED', 'test cancellation'));
      await Promise.resolve();
      expect(settled).toBe(false);

      dialResult.resolve(session);
      await expect.poll(() => closeCalls).toBe(1);
      expect(settled).toBe(false);

      physicallyClosed.resolve(undefined);
      await expect(connecting).rejects.toMatchObject({ code: 'CANCELLED' });
    } finally {
      await endpoint.close();
    }
  });

  it('does not treat a rejected Iroh closed observation as physical proof', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/rejected-close-observation/1');
    const endpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { dns: true }
    });
    const dialStarted = deferred<void>();
    const dialResult = deferred<unknown>();
    const internal = endpoint as unknown as {
      node: { dial(peerId: string, options: unknown): Promise<unknown> };
    };
    internal.node.dial = () => {
      dialStarted.resolve(undefined);
      return dialResult.promise;
    };
    const controller = new AbortController();
    const connecting = endpoint.connectLocator(
      { kind: 'dns' },
      alpn,
      endpoint.id,
      controller.signal
    );
    let settled = false;
    void connecting.then(
      () => { settled = true; },
      () => { settled = true; }
    );

    try {
      await dialStarted.promise;
      controller.abort(new P2PError('CANCELLED', 'test cancellation'));
      dialResult.resolve({
        ready: Promise.resolve(undefined),
        close: () => undefined,
        closed: Promise.reject(new Error('native close observation failed'))
      });
      for (let turn = 0; turn < 5; turn += 1) await Promise.resolve();
      expect(settled).toBe(false);
    } finally {
      await endpoint.close();
    }
  });

  it('fails DNS discovery closed when resolved routes cannot be checked by application egress policy', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/dns-policy/1');
    for (const options of [
      {
        relay: { mode: 'disabled' },
        discovery: { dns: true },
        allowDirectAddress: () => true
      },
      {
        relay: { mode: 'custom', urls: ['https://relay.example'] },
        discovery: { dns: true }
      },
      {
        relay: { mode: 'custom', urls: ['https://relay.example'] },
        discovery: { dns: { serverUrl: 'https://dns.example' } }
      }
    ] as const) {
      await expect(IrohEndpoint.create(alpn, options)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    }
  });

  it('enforces relay mode on signed ticket route hints', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/ticket-relay-egress/1');
    const issuer = await IrohEndpoint.create(alpn, { relay: { mode: 'default' } });
    const customReceiver = await IrohEndpoint.create(alpn, {
      relay: { mode: 'custom', urls: ['https://RELAY.example:443'] },
      allowRelayUrl: () => true
    });
    const disabledReceiver = await IrohEndpoint.create(alpn, { relay: { mode: 'disabled' } });
    const issuerInternal = issuer as unknown as {
      node: {
        discoveryInfo(): Promise<{
          nodeId: string;
          directAddress: string | null;
          directAddresses: string[];
          relayUrl: string | null;
        }>;
      };
    };
    const customInternal = customReceiver as unknown as {
      resolveLocator(locator: EndpointLocator, expectedPeerId: string): Promise<{ relayUrl: string | null }>;
    };
    const disabledInternal = disabledReceiver as unknown as typeof customInternal;
    let relayUrl = 'https://outside.example/';
    issuerInternal.node.discoveryInfo = async () => ({
      nodeId: issuer.id,
      directAddress: null,
      directAddresses: [],
      relayUrl
    });

    try {
      const outsideTicket = await issuer.createTicket();
      await expect(customInternal.resolveLocator(
        { kind: 'ticket', ticket: outsideTicket },
        issuer.id
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      relayUrl = 'https://relay.example/';
      const configuredTicket = await issuer.createTicket();
      await expect(customInternal.resolveLocator(
        { kind: 'ticket', ticket: configuredTicket },
        issuer.id
      )).resolves.toMatchObject({ relayUrl: 'https://relay.example/' });

      await expect(disabledInternal.resolveLocator(
        { kind: 'ticket', ticket: configuredTicket },
        issuer.id
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    } finally {
      await Promise.all([issuer.close(), customReceiver.close(), disabledReceiver.close()]);
    }
  });

  it('applies relay callbacks only to untrusted remote candidates, not local relay configuration', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/3/relay-policy-source-separation/1');
    const localCandidates: string[] = [];
    const customCandidates: string[] = [];
    const local = await IrohEndpoint.create(alpn, {
      relay: { mode: 'default' },
      allowRelayUrl: (origin) => {
        localCandidates.push(origin);
        return true;
      }
    });
    const custom = await IrohEndpoint.create(alpn, {
      relay: { mode: 'custom', urls: ['https://RELAY.example:443'] },
      allowRelayUrl: (origin) => {
        customCandidates.push(origin);
        return true;
      }
    });
    const issuer = await IrohEndpoint.create(alpn, { relay: { mode: 'default' } });
    const issuerInternal = issuer as unknown as {
      node: {
        discoveryInfo(): Promise<{
          nodeId: string;
          directAddress: string | null;
          directAddresses: string[];
          relayUrl: string | null;
        }>;
      };
    };
    const customResolver = custom as unknown as {
      resolveLocator(locator: EndpointLocator, expectedPeerId: string): Promise<{ relayUrl: string | null }>;
    };

    try {
      // Default-network relay selection and configured custom origins are
      // trusted deployment inputs, so neither invokes the remote-candidate hook.
      await local.createTicket();
      expect(localCandidates).toEqual([]);
      expect(customCandidates).toEqual([]);

      issuerInternal.node.discoveryInfo = async () => ({
        nodeId: issuer.id,
        directAddress: null,
        directAddresses: [],
        relayUrl: 'https://relay.example/'
      });
      await expect(customResolver.resolveLocator(
        { kind: 'ticket', ticket: await issuer.createTicket() },
        issuer.id
      )).resolves.toMatchObject({ relayUrl: 'https://relay.example/' });
      expect(customCandidates).toEqual(['https://relay.example']);
    } finally {
      await Promise.all([local.close(), custom.close(), issuer.close()]);
    }
  });

  it('requires explicit egress policy for every remote signed-ticket route', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/3/ticket-route-policy/1');
    const issuer = await IrohEndpoint.create(alpn, { relay: { mode: 'default' } });
    const implicitReceiver = await IrohEndpoint.create(alpn, { relay: { mode: 'default' } });
    const explicitReceiver = await IrohEndpoint.create(alpn, {
      relay: { mode: 'default' },
      allowDirectAddress: () => true,
      allowRelayUrl: () => true
    });
    const issuerInternal = issuer as unknown as {
      node: {
        discoveryInfo(): Promise<{
          nodeId: string;
          directAddress: string | null;
          directAddresses: string[];
          relayUrl: string | null;
        }>;
      };
    };
    type Resolver = {
      resolveLocator(
        locator: EndpointLocator,
        expectedPeerId: string
      ): Promise<{ directAddresses: string[]; relayUrl: string | null }>;
    };
    const implicit = implicitReceiver as unknown as Resolver;
    const explicit = explicitReceiver as unknown as Resolver;

    try {
      issuerInternal.node.discoveryInfo = async () => ({
        nodeId: issuer.id,
        directAddress: '10.20.30.40:4433',
        directAddresses: ['10.20.30.40:4433'],
        relayUrl: null
      });
      const directTicket = await issuer.createTicket();
      await expect(implicit.resolveLocator(
        { kind: 'ticket', ticket: directTicket },
        issuer.id
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      await expect(explicit.resolveLocator(
        { kind: 'ticket', ticket: directTicket },
        issuer.id
      )).resolves.toMatchObject({ directAddresses: ['10.20.30.40:4433'], relayUrl: null });

      issuerInternal.node.discoveryInfo = async () => ({
        nodeId: issuer.id,
        directAddress: null,
        directAddresses: [],
        relayUrl: 'https://remote-ticket-relay.example/'
      });
      const relayTicket = await issuer.createTicket();
      await expect(implicit.resolveLocator(
        { kind: 'ticket', ticket: relayTicket },
        issuer.id
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      await expect(explicit.resolveLocator(
        { kind: 'ticket', ticket: relayTicket },
        issuer.id
      )).resolves.toMatchObject({ directAddresses: [], relayUrl: 'https://remote-ticket-relay.example/' });
    } finally {
      await Promise.all([issuer.close(), implicitReceiver.close(), explicitReceiver.close()]);
    }
  });

  it('fails signed-ticket direct-address policy exceptions closed', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/3/ticket-route-policy-throw/1');
    const issuer = await IrohEndpoint.create(alpn, { relay: { mode: 'disabled' } });
    const receiver = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      allowDirectAddress: () => { throw new Error('policy backend detail'); }
    });
    const resolver = receiver as unknown as {
      resolveLocator(locator: EndpointLocator, expectedPeerId: string): Promise<unknown>;
    };

    try {
      await expect(resolver.resolveLocator(
        { kind: 'ticket', ticket: await issuer.createTicket() },
        issuer.id
      )).rejects.toMatchObject({
        code: 'UNAUTHORIZED',
        message: 'Route direct address was rejected by egress policy'
      });
    } finally {
      await Promise.all([issuer.close(), receiver.close()]);
    }
  });

  it('canonicalizes custom relay origins and rejects equivalent duplicates before startup', async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/relay-origin-canonicalization/1');
    await expect(IrohEndpoint.create(alpn, {
      relay: {
        mode: 'custom',
        urls: ['https://RELAY.example.:443', 'https://relay.example/']
      }
    })).rejects.toMatchObject({ code: 'INVALID_FRAME' });
  });

  it('defaults mDNS direct hints to LAN address ranges, including scoped IPv6', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/mdns-lan-egress/1');
    const endpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { mdns: { serviceName: 'lan-egress', advertise: false } }
    });
    const broadEndpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { mdns: { serviceName: 'lan-egress', advertise: false } },
      allowDirectAddress: () => true
    });
    type MdnsDirectInternal = {
      node: { browsePeers(): AsyncIterable<{ nodeId: string; addrs: string[]; isActive: boolean }> };
      resolveLocator(locator: EndpointLocator, expectedPeerId: string): Promise<{ directAddresses: string[] }>;
    };
    const internal = endpoint as unknown as MdnsDirectInternal;
    const broadInternal = broadEndpoint as unknown as MdnsDirectInternal;
    const setAddresses = (target: MdnsDirectInternal, peerId: string, addrs: string[]): void => {
      target.node.browsePeers = () => ({
        async *[Symbol.asyncIterator]() {
          yield { nodeId: peerId, addrs, isActive: true };
        }
      });
    };

    try {
      const lanAddresses = [
        '10.0.0.1:4433',
        '172.16.0.1:4433',
        '192.168.1.1:4433',
        '169.254.2.3:4433',
        '127.0.0.1:4433',
        '[fd12:3456::1]:4433',
        '[fe80::1%en0]:4433',
        '[::1]:4433'
      ];
      setAddresses(internal, endpoint.id, lanAddresses);
      await expect(internal.resolveLocator(
        { kind: 'mdns', serviceName: 'lan-egress' }, endpoint.id
      )).resolves.toMatchObject({ directAddresses: lanAddresses });

      setAddresses(internal, endpoint.id, ['203.0.113.10:4433']);
      await expect(internal.resolveLocator(
        { kind: 'mdns', serviceName: 'lan-egress' }, endpoint.id
      )).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      setAddresses(broadInternal, broadEndpoint.id, ['203.0.113.10:4433']);
      await expect(broadInternal.resolveLocator(
        { kind: 'mdns', serviceName: 'lan-egress' }, broadEndpoint.id
      )).resolves.toMatchObject({ directAddresses: ['203.0.113.10:4433'] });
    } finally {
      await Promise.all([endpoint.close(), broadEndpoint.close()]);
    }
  });

  it('requires explicit authorization for default-relay mDNS hints and custom membership always wins', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/mdns-relay-egress/1');
    const disabledEndpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { mdns: { serviceName: 'relay-egress', advertise: false } }
    });
    const defaultEndpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'default' },
      discovery: { mdns: { serviceName: 'relay-egress', advertise: false } }
    });
    const authorizedDefaultEndpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'default' },
      discovery: { mdns: { serviceName: 'relay-egress', advertise: false } },
      allowRelayUrl: () => true
    });
    const customEndpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'custom', urls: ['https://approved.example/'] },
      discovery: { mdns: { serviceName: 'relay-egress', advertise: false } },
      allowRelayUrl: () => true
    });
    type MdnsRelayInternal = {
      node: { browsePeers(): AsyncIterable<{ nodeId: string; addrs: string[]; isActive: boolean }> };
      resolveLocator(locator: EndpointLocator, expectedPeerId: string): Promise<{ relayUrl: string | null }>;
    };
    const setRelay = (endpoint: IrohEndpoint, value: string): MdnsRelayInternal => {
      const internal = endpoint as unknown as MdnsRelayInternal;
      internal.node.browsePeers = () => ({
        async *[Symbol.asyncIterator]() {
          yield { nodeId: endpoint.id, addrs: [value], isActive: true };
        }
      });
      return internal;
    };
    const resolve = (endpoint: IrohEndpoint, internal: MdnsRelayInternal) => internal.resolveLocator(
      { kind: 'mdns', serviceName: 'relay-egress' }, endpoint.id
    );

    try {
      const disabled = setRelay(disabledEndpoint, 'https://relay.example/');
      await expect(resolve(disabledEndpoint, disabled)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      const implicitDefault = setRelay(defaultEndpoint, 'https://relay.example/');
      await expect(resolve(defaultEndpoint, implicitDefault)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      const explicitDefault = setRelay(authorizedDefaultEndpoint, 'https://relay.example/');
      await expect(resolve(authorizedDefaultEndpoint, explicitDefault))
        .resolves.toMatchObject({ relayUrl: 'https://relay.example/' });

      const outsideCustom = setRelay(customEndpoint, 'https://relay.example/');
      await expect(resolve(customEndpoint, outsideCustom)).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      const configuredCustom = setRelay(customEndpoint, 'https://approved.example/');
      await expect(resolve(customEndpoint, configuredCustom))
        .resolves.toMatchObject({ relayUrl: 'https://approved.example/' });
    } finally {
      await Promise.all([
        disabledEndpoint.close(),
        defaultEndpoint.close(),
        authorizedDefaultEndpoint.close(),
        customEndpoint.close()
      ]);
    }
  });

  it('caps aggregate mDNS route candidates before dialing', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/mdns-candidate-cap/1');
    const endpoint = await IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { mdns: { serviceName: 'candidate-cap', advertise: false } }
    });
    const internal = endpoint as unknown as {
      node: {
        browsePeers(): AsyncIterable<{
          nodeId: string;
          addrs: string[];
          isActive: boolean;
        }>;
      };
      resolveLocator(
        locator: EndpointLocator,
        expectedPeerId: string
      ): Promise<{ directAddresses: string[]; relayUrl: string | null }>;
    };
    internal.node.browsePeers = () => ({
      async *[Symbol.asyncIterator]() {
        yield {
          nodeId: endpoint.id,
          addrs: Array.from({ length: 33 }, (_, index) => `127.0.0.1:${4_000 + index}`),
          isActive: true
        };
      }
    });

    try {
      await expect(internal.resolveLocator(
        { kind: 'mdns', serviceName: 'candidate-cap' },
        endpoint.id
      )).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    } finally {
      await endpoint.close();
    }
  });

  it('creates fresh signed tickets from all current IPv4 and IPv6 route candidates', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/fresh-ticket/1');
    const endpoint = await IrohEndpoint.create(alpn, { relay: { mode: 'default' } });
    const internal = endpoint as unknown as {
      node: {
        discoveryInfo(): Promise<{
          nodeId: string;
          directAddress: string | null;
          directAddresses: string[];
          relayUrl: string | null;
        }>;
      };
    };
    let generation = 0;
    internal.node.discoveryInfo = async () => {
      generation += 1;
      return {
        nodeId: endpoint.id,
        directAddress: `192.0.2.${generation}:4433`,
        directAddresses: [`192.0.2.${generation}:4433`, `[2001:db8::${generation}]:4433`],
        relayUrl: `https://relay-${generation}.example/`
      };
    };
    try {
      const first = decodeTicketBody(await endpoint.createTicket());
      await new Promise<void>((resolve) => setTimeout(resolve, 2));
      const second = decodeTicketBody(await endpoint.createTicket());

      expect(generation).toBe(2);
      expect(first.directAddresses).toEqual(['192.0.2.1:4433', '[2001:db8::1]:4433']);
      expect(first.relayUrl).toBe('https://relay-1.example/');
      expect(second.directAddresses).toEqual(['192.0.2.2:4433', '[2001:db8::2]:4433']);
      expect(second.relayUrl).toBe('https://relay-2.example/');
      expect(second.issuedAt).toBeGreaterThan(first.issuedAt);
    } finally {
      await endpoint.close();
    }
  });

  it('requires an exact true decision from the pre-handshake peer policy', async () => {
    const connection = new AdmissionConnection();
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      preAuthorizePeer: () => 'truthy-but-invalid' as never,
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(connection.closeCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('audits installed reconnect sessions and rejects an OAuth client identity swap', async () => {
    const first = new AdmissionConnection(false);
    const duplicate = new AdmissionConnection(false);
    const swapped = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(first, duplicate, swapped);
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => events.push(event),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('session-a', 'oauth-client-a'),
      authenticatedSession('session-duplicate', 'oauth-client-a'),
      authenticatedSession('session-swapped', 'oauth-client-b')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
    };
    internals.authenticate = async () => {
      const session = sessions.shift();
      if (!session) throw new Error('No authentication result was queued');
      return session;
    };

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).resolves.toBeDefined();
      first.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);
      await expect(node.connect(connectTarget(endpoint.address.ticket))).resolves.toBeDefined();
      duplicate.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      expect(events.filter((event) => event.type === 'session.authenticated')).toMatchObject([
        { type: 'session.authenticated', sessionId: 'session-a' },
        { type: 'session.authenticated', sessionId: 'session-duplicate' }
      ]);
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(1);
      expect(swapped.closeCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('rejects connect when the authenticated audit callback synchronously closes the node', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const events: SecurityAuditEvent[] = [];
    let peerNotifications = 0;
    const closeNode: { current?: () => Promise<void> } = {};
    let reentrantClose: Promise<void> | undefined;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => {
        events.push(event);
        if (event.type === 'session.authenticated') reentrantClose = closeNode.current?.();
      },
      onPeer: () => { peerNotifications += 1; },
      endpointFactory: async () => endpoint
    });
    closeNode.current = () => node.close();
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
    };
    internals.authenticate = async () => authenticatedSession('closing-audit', 'oauth-client-a');

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(reentrantClose).toBeDefined();
      await reentrantClose;
      await Promise.resolve();
      expect(node.peersSnapshot()).toHaveLength(0);
      expect(peerNotifications).toBe(0);
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects connect when authenticated audit schedules closure before public resolution', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const events: SecurityAuditEvent[] = [];
    let peerNotifications = 0;
    const closePeer: { current?: () => Promise<void> | undefined } = {};
    let reentrantClose: Promise<void> | undefined;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => {
        events.push(event);
        if (event.type === 'session.authenticated') {
          queueMicrotask(() => { reentrantClose = closePeer.current?.(); });
        }
      },
      onPeer: () => { peerNotifications += 1; },
      endpointFactory: async () => endpoint
    });
    closePeer.current = () => node.getPeer('remote')?.close('Closed from queued authentication audit callback');
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
    };
    internals.authenticate = async () => authenticatedSession('queued-closing-audit', 'oauth-client-a');

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(reentrantClose).toBeDefined();
      await reentrantClose;
      expect(node.peersSnapshot()).toHaveLength(0);
      expect(peerNotifications).toBe(0);
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects a losing duplicate when its synchronous close callback closes the incumbent', async () => {
    const incumbentConnection = new AdmissionConnection(false, 'remote', 'client');
    const duplicate = new ReentrantCloseConnection('remote', 'server');
    const endpoint = new AdmissionEndpoint(incumbentConnection);
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => events.push(event),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('incumbent-session', 'oauth-client-a'),
      authenticatedSession('duplicate-session', 'oauth-client-a')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
    };
    internals.authenticate = async () => sessions.shift()!;

    let incumbentClose: Promise<void> | undefined;
    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      duplicate.onClose = () => {
        incumbentClose = peer.close('Closed synchronously by duplicate retirement');
      };

      await expect(internals.registerInboundConnection(duplicate)).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(duplicate.closeCalls).toBe(1);
      expect(incumbentClose).toBeDefined();
      await incumbentClose;
      expect(node.getPeer('remote')).toBeUndefined();
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('isolates rejected asynchronous security audit callbacks', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    let callbackCompleted = false;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: async () => {
        await Promise.resolve();
        callbackCompleted = true;
        throw new Error('audit sink failed');
      },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('async-audit', 'oauth-client-a');

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).resolves.toBeDefined();
      await new Promise<void>((resolve) => setTimeout(resolve, 0));
      expect(callbackCompleted).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('aborts file authorization callbacks at the node authorization deadline', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    let authorizationSignal: AbortSignal | undefined;
    let authorizationContextFrozen = false;
    let authorizationActionFrozen = false;
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: {
        ...unusedSecurity(),
        authorize: (context) => {
          authorizationSignal = context.signal;
          authorizationContextFrozen = Object.isFrozen(context);
          authorizationActionFrozen = Object.isFrozen(context.action);
          return new Promise<boolean>(() => undefined);
        }
      },
      onSecurityEvent: (event) => events.push(event),
      limits: { streamHeaderTimeoutMs: 100, shutdownTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const session = authenticatedSession('file-session', 'oauth-client-a');
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      authorize(runtime: unknown, session: AuthenticatedSession, action: { kind: 'file.pull'; capabilityId: string }): Promise<void>;
    };
    internals.authenticate = async () => session;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as { runtime: unknown }).runtime;
      await expect(internals.authorize(runtime, session, {
        kind: 'file.pull',
        capabilityId: 'capability'
      })).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(authorizationSignal?.aborted).toBe(true);
      expect(authorizationContextFrozen).toBe(true);
      expect(authorizationActionFrozen).toBe(true);
      expect(events.filter((event) => event.type === 'authorization')).toMatchObject([{
        type: 'authorization',
        allowed: false,
        reason: 'Authorization evaluation failed'
      }]);
    } finally {
      await expect(node.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
    }
  });

  it('does not let a stale reconnect overwrite a newer peer runtime', async () => {
    const originalConnection = new AdmissionConnection(false);
    const reconnectConnection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(originalConnection, reconnectConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const originalSession = authenticatedSession('original-session', 'oauth-client-a');
    const reconnectSession = authenticatedSession('reconnect-session', 'oauth-client-a');
    let authenticateCalls = 0;
    let resolveReconnectAuthentication: ((session: AuthenticatedSession) => void) | undefined;
    let markReconnectAuthenticationStarted: (() => void) | undefined;
    const reconnectAuthenticationStarted = new Promise<void>((resolve) => {
      markReconnectAuthenticationStarted = resolve;
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      peers: Map<string, unknown>;
    };
    internals.authenticate = async () => {
      authenticateCalls += 1;
      if (authenticateCalls === 1) return originalSession;
      markReconnectAuthenticationStarted?.();
      return new Promise<AuthenticatedSession>((resolve) => {
        resolveReconnectAuthentication = resolve;
      });
    };

    let runtime: { alive: boolean; connection(): Promise<QuicConnection> } | undefined;
    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const connectedRuntime = (peer as unknown as {
        runtime: { alive: boolean; connection(): Promise<QuicConnection> };
      }).runtime;
      runtime = connectedRuntime;
      disconnectRuntimeForTest(connectedRuntime);
      internals.peers.delete('remote');

      const reconnecting = connectedRuntime.connection();
      await reconnectAuthenticationStarted;
      const incumbent = Object.freeze({ identity: 'newer-runtime' });
      internals.peers.set('remote', incumbent);
      resolveReconnectAuthentication?.(reconnectSession);

      await expect(reconnecting).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(internals.peers.get('remote')).toBe(incumbent);
      expect(reconnectConnection.closeCalls).toBe(1);
    } finally {
      if (runtime) internals.peers.set('remote', runtime);
      await node.close();
    }
  });

  it('uses deterministic arbitration when a live connection appears during reconnect', async () => {
    const original = new AdmissionConnection(false, 'aaa', 'client');
    const reconnectCandidate = new ThrowingCloseConnection('aaa', 'client');
    // local > aaa, so the server-side connection is the deterministic winner.
    const inboundWinner = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original, reconnectCandidate);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const reconnectAuthentication = deferred<AuthenticatedSession>();
    let authenticateCalls = 0;
    let markReconnectStarted: (() => void) | undefined;
    const reconnectStarted = new Promise<void>((resolve) => { markReconnectStarted = resolve; });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      installConnection(
        runtime: unknown,
        connection: QuicConnection,
        identity: { readonly id: string; readonly direction: 'inbound' | 'outbound' },
        session: AuthenticatedSession
      ): void;
      peers: Map<string, unknown>;
    };
    internals.authenticate = async () => {
      authenticateCalls += 1;
      if (authenticateCalls === 1) return authenticatedSession('original-session', 'oauth-client-a');
      markReconnectStarted?.();
      return reconnectAuthentication.promise;
    };

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket, 'aaa'));
      const runtime = (peer as unknown as {
        runtime: {
          alive: boolean;
          current: QuicConnection;
          connection(): Promise<QuicConnection>;
        };
      }).runtime;
      disconnectRuntimeForTest(runtime);
      internals.peers.delete('aaa');

      const reconnecting = runtime.connection();
      await reconnectStarted;
      original.close(0n, new TextEncoder().encode('Replaced by test incumbent'));
      internals.installConnection(
        runtime,
        inboundWinner,
        Object.freeze({ id: 'aaa', direction: 'inbound' }),
        authenticatedSession('inbound-session', 'oauth-client-a')
      );
      internals.peers.set('aaa', runtime);
      const incumbent = runtime.current;

      reconnectAuthentication.resolve(authenticatedSession('reconnect-session', 'oauth-client-a'));
      await expect(reconnecting).resolves.toBe(incumbent);
      expect(runtime.current).toBe(incumbent);
      expect(peer.identity.direction).toBe('inbound');
      expect(reconnectCandidate.closeCalls).toBe(1);
      expect(inboundWinner.closeCalls).toBe(0);
      reconnectCandidate.resolveClosed();
    } finally {
      await node.close();
    }
  });

  it('rejects a reconnect loser when duplicate retirement synchronously closes the incumbent', async () => {
    const original = new AdmissionConnection(false, 'aaa', 'client');
    const reconnectCandidate = new ReentrantCloseConnection('aaa', 'client');
    // local > aaa, so the synchronously installed server-side connection wins.
    const inboundWinner = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original, reconnectCandidate);
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => events.push(event),
      endpointFactory: async () => endpoint
    });
    const reconnectAuthentication = deferred<AuthenticatedSession>();
    let authenticateCalls = 0;
    let markReconnectStarted: (() => void) | undefined;
    const reconnectStarted = new Promise<void>((resolve) => { markReconnectStarted = resolve; });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      installConnection(
        runtime: unknown,
        connection: QuicConnection,
        identity: { readonly id: string; readonly direction: 'inbound' },
        session: AuthenticatedSession
      ): unknown;
    };
    internals.authenticate = async () => {
      authenticateCalls += 1;
      if (authenticateCalls === 1) return authenticatedSession('original-session', 'oauth-client-a');
      markReconnectStarted?.();
      return reconnectAuthentication.promise;
    };

    let incumbentClose: Promise<void> | undefined;
    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket, 'aaa'));
      const runtime = (peer as unknown as {
        runtime: { connection(): Promise<QuicConnection> };
      }).runtime;
      original.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);

      const reconnecting = runtime.connection();
      await reconnectStarted;
      internals.installConnection(
        runtime,
        inboundWinner,
        Object.freeze({ id: 'aaa', direction: 'inbound' as const }),
        authenticatedSession('inbound-session', 'oauth-client-a')
      );
      reconnectCandidate.onClose = () => {
        incumbentClose = peer.close('Closed synchronously by reconnect duplicate retirement');
      };

      reconnectAuthentication.resolve(authenticatedSession('reconnect-session', 'oauth-client-a'));
      await expect(reconnecting).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(reconnectCandidate.closeCalls).toBe(1);
      expect(incumbentClose).toBeDefined();
      await incumbentClose;
      expect(node.getPeer('aaa')).toBeUndefined();
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects reconnect when authenticated audit schedules peer closure before public resolution', async () => {
    const original = new AdmissionConnection(false);
    const reconnectCandidate = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(original, reconnectCandidate);
    const events: SecurityAuditEvent[] = [];
    const closePeer: { current?: () => Promise<void> } = {};
    let reentrantClose: Promise<void> | undefined;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => {
        events.push(event);
        if (event.type === 'session.authenticated' && event.sessionId === 'queued-reconnect-session') {
          queueMicrotask(() => { reentrantClose = closePeer.current?.(); });
        }
      },
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('queued-reconnect-session', 'oauth-client-a')
    ];
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      closePeer.current = () => peer.close('Closed from queued reconnect audit callback');
      const runtime = (peer as unknown as {
        runtime: { connection(): Promise<QuicConnection> };
      }).runtime;
      original.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);

      await expect(runtime.connection()).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(reentrantClose).toBeDefined();
      await reentrantClose;
      expect(node.getPeer('remote')).toBeUndefined();
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(0);
    } finally {
      await node.close();
    }
  });

  it('rejects a reconnect whose transport peer ID changed before requesting credentials', async () => {
    const originalConnection = new AdmissionConnection(false, 'remote-a');
    const wrongPeerConnection = new AdmissionConnection(false, 'remote-b');
    const endpoint = new AdmissionEndpoint(originalConnection, wrongPeerConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    let authenticationCalls = 0;
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      peers: Map<string, unknown>;
    };
    internals.authenticate = async () => {
      authenticationCalls += 1;
      return authenticatedSession(`session-${authenticationCalls}`, 'oauth-client-a');
    };

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-a'));
      const runtime = (peer as unknown as {
        runtime: { alive: boolean; connection(): Promise<QuicConnection> };
      }).runtime;
      disconnectRuntimeForTest(runtime);
      internals.peers.delete('remote-a');

      await expect(runtime.connection()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(authenticationCalls).toBe(1);
      expect(wrongPeerConnection.closeCalls).toBe(1);
      expect(internals.peers.has('remote-b')).toBe(false);
    } finally {
      await node.close();
    }
  });

  it('retains the expected principal matcher across reconnects and rejects a changed principal', async () => {
    const originalConnection = new AdmissionConnection(false);
    const reconnectConnection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(originalConnection, reconnectConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('reconnect-session', 'oauth-client-b')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      peers: Map<string, unknown>;
    };
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as {
        runtime: { alive: boolean; connection(): Promise<QuicConnection> };
      }).runtime;
      disconnectRuntimeForTest(runtime);
      internals.peers.delete('remote');

      await expect(runtime.connection()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(endpoint.expectedPeerIds).toEqual(['remote', 'remote']);
      expect(reconnectConnection.closeCalls).toBe(1);
      expect(internals.peers.has('remote')).toBe(false);
    } finally {
      await node.close();
    }
  });

  it('requires the complete session-security contract before creating an endpoint', async () => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: {
        authenticate: () => authenticatedSession('unused', 'client').principal,
        authorize: () => true
      } as never,
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
    expect(endpointCreated).toBe(false);
  });

  it('validates file metadata schemas before creating an endpoint', async () => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      fileMetadataSchema: {
        '~standard': {
          version: 1,
          vendor: 'test',
          validate: (value: unknown) => ({ value }),
          smuggled: true
        }
      } as never,
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'INVALID_FRAME' });
    expect(endpointCreated).toBe(false);
  });

  it('snapshots the file metadata schema and preserves its validator receiver', async () => {
    const endpoint = new AdmissionEndpoint();
    const prefixes = new WeakMap<object, string>();
    const descriptor = {
      version: 1 as const,
      vendor: 'schema-vendor',
      validate(this: object, value: unknown) {
        return { value: `${prefixes.get(this)}:${String(value)}` };
      }
    };
    prefixes.set(descriptor, 'trusted');
    const schema = { '~standard': descriptor };
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      fileMetadataSchema: schema as never,
      endpointFactory: async () => endpoint
    });

    try {
      descriptor.vendor = 'mutated';
      descriptor.validate = () => ({ value: 'mutated' });
      const saved = (node as unknown as {
        options: { fileMetadataSchema: typeof schema };
      }).options.fileMetadataSchema;
      expect(saved).not.toBe(schema);
      expect(saved['~standard']).not.toBe(descriptor);
      expect(saved['~standard'].vendor).toBe('schema-vendor');
      expect(Object.isFrozen(saved)).toBe(true);
      expect(Object.isFrozen(saved['~standard'])).toBe(true);
      expect(await saved['~standard'].validate('metadata')).toEqual({ value: 'trusted:metadata' });
    } finally {
      await node.close();
    }
  });

  it('exposes cancellation to node-level request-header providers', async () => {
    let received: AbortSignal | undefined;
    const provider: NonNullable<P2PNodeOptions<typeof router>['getRequestHeaders']> = ({ signal }) => {
      received = signal;
      return { traceparent: 'test' };
    };
    const signal = new AbortController().signal;
    await provider({ peer: { id: 'remote', direction: 'outbound' }, path: 'ping', type: 'query', signal });
    expect(received).toBe(signal);
  });

  it('bounds endpoint dialing and closes a connection which resolves after the deadline', async () => {
    const pendingConnection = deferred<QuicConnection>();
    const late = new ThrowingCloseConnection();
    const endpoint = new AdmissionEndpoint(pendingConnection.promise);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { connectTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      resources: { snapshot(): { active: { handshakes: number } } };
    };

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(internals.resources.snapshot().active.handshakes).toBe(1);
      pendingConnection.resolve(late);
      await expect.poll(() => late.closeCalls).toBe(1);
      expect(internals.resources.snapshot().active.handshakes).toBe(1);
      late.resolveClosed();
      await expect.poll(() => internals.resources.snapshot().active.handshakes).toBe(0);
    } finally {
      await node.close();
    }
  });

  it('retains a failed handshake cleanup lease until physical connection closure', async () => {
    const connection = new FailingHandshakeCleanupConnection();
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { handshakeTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      resources: { snapshot(): { active: { handshakes: number; bufferedBytes: number } } };
    };

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket)))
        .rejects.toMatchObject({ code: 'TIMEOUT' });
      await expect.poll(() => ({
        reset: connection.send.resetCalls,
        stop: connection.recv.stopCalls
      })).toEqual({ reset: 1, stop: 1 });
      expect(connection.closeCalls).toBeGreaterThan(0);
      // Both terminal methods rejected, so their settlement is not proof of
      // cleanup. The pre-authentication allocation remains owned even though
      // the public timeout and the underlying handshake task have settled.
      expect(internals.resources.snapshot().active).toMatchObject({
        handshakes: 1,
        bufferedBytes: 64 * 1024
      });

      connection.resolveClosed();
      await expect.poll(() => internals.resources.snapshot().active).toMatchObject({
        handshakes: 0,
        bufferedBytes: 0
      });
    } finally {
      connection.resolveClosed();
      await node.close();
    }
  });

  it('retains rejected pre-session admission until physical connection closure', async () => {
    const connection = new ThrowingCloseConnection();
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: { snapshot(): { active: { handshakes: number } } };
    };
    internals.authenticate = async () => {
      throw new P2PError('UNAUTHORIZED', 'rejected test credential');
    };

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({
        code: 'UNAUTHORIZED',
        message: 'rejected test credential'
      });
      expect(connection.closeCalls).toBe(1);
      expect(internals.resources.snapshot().active.handshakes).toBe(1);
      connection.resolveClosed();
      await expect.poll(() => internals.resources.snapshot().active.handshakes).toBe(0);
    } finally {
      await node.close();
    }
  });

  it('retains failed reconnect admission until physical connection closure', async () => {
    const original = new AdmissionConnection(false);
    const rejectedReconnect = new AdmissionConnection(false, 'remote', 'client', false);
    const endpoint = new AdmissionEndpoint(original, rejectedReconnect);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    let authenticationCalls = 0;
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: { snapshot(): { active: { handshakes: number } } };
    };
    internals.authenticate = async () => {
      authenticationCalls += 1;
      if (authenticationCalls === 1) return authenticatedSession('original-session', 'oauth-client-a');
      throw new P2PError('UNAUTHORIZED', 'reconnect credential rejected');
    };

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as {
        runtime: { alive: boolean; connection(): Promise<QuicConnection> };
      }).runtime;
      original.resolveClosed();
      await expect.poll(() => runtime.alive).toBe(false);

      await expect(runtime.connection()).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
      expect(rejectedReconnect.closeCalls).toBe(1);
      expect(internals.resources.snapshot().active.handshakes).toBe(1);
      rejectedReconnect.resolveClosed();
      await expect.poll(() => internals.resources.snapshot().active.handshakes).toBe(0);
    } finally {
      rejectedReconnect.resolveClosed();
      await node.close();
    }
  });

  it('cancels a locator reconnect when its peer handle closes', async () => {
    const original = new AdmissionConnection(false);
    const endpoint = new CancelableReconnectEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { connectTimeoutMs: 30_000, shutdownTimeoutMs: 1_000 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as {
        runtime: { alive: boolean; connection(): Promise<QuicConnection> };
      }).runtime;
      original.resolveClosed();
      await expect.poll(() => runtime.alive).toBe(false);

      const reconnecting = runtime.connection();
      await expect.poll(() => endpoint.connectCalls).toBe(2);
      expect(endpoint.reconnectSignal?.aborted).toBe(false);

      await peer.close();
      await expect(reconnecting).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(endpoint.reconnectSignal?.aborted).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('aborts pending dialing on shutdown, cleans up late results, and never reconnects afterward', async () => {
    const pendingConnection = deferred<QuicConnection>();
    const late = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(pendingConnection.promise);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { shutdownTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });

    const connecting = node.connect(connectTarget(endpoint.address.ticket));
    const rejection = expect(connecting).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await expect.poll(() => endpoint.connectCalls).toBe(1);
    const closing = node.close();
    expect(node.close()).toBe(closing);
    await expect(closing).rejects.toMatchObject({ code: 'TIMEOUT' });
    await rejection;
    pendingConnection.resolve(late);
    await expect.poll(() => late.closeCalls).toBe(1);
    await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(endpoint.connectCalls).toBe(1);
  });

  it.each([
    ['shutdownTimeoutMs', 99],
    ['shutdownTimeoutMs', 600_001]
  ] as const)('rejects invalid %s before creating an endpoint', async (name, value) => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { [name]: value },
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(endpointCreated).toBe(false);
  });

  it('makes Peer.close terminal for that handle and removes it from the active peer set', async () => {
    const connection = new AdmissionConnection(false);
    const explicitReplacement = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection, explicitReplacement);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      runtimes: Map<string, unknown>;
      resources: { snapshot(): { active: Record<string, number>; queued: number } };
    };
    const sessions = [
      authenticatedSession('closed-peer', 'oauth-client-a'),
      authenticatedSession('explicit-replacement', 'oauth-client-a')
    ];
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket));
      expect(node.peersSnapshot()).toHaveLength(1);
      expect(Object.isFrozen(node.peersSnapshot())).toBe(true);
      expect(node.getPeer<typeof router>('remote')?.session.id).toBe('closed-peer');

      const closed = peer.close();
      await Promise.all([closed, peer.close()]);

      expect(node.peersSnapshot()).toHaveLength(0);
      expect(node.getPeer<typeof router>('remote')).toBeUndefined();
      expect(internals.runtimes.size).toBe(0);
      expect(internals.resources.snapshot()).toMatchObject({
        queued: 0,
        active: {
          handshakes: 0,
          streams: 0,
          outboundTransfers: 0,
          inboundTransfers: 0,
          bufferedBytes: 0,
          callbacks: 0
        }
      });
      expect(connection.closeCalls).toBe(1);
      await expect(peer.rpc.ping.query()).rejects.toThrow(/Peer is closed/);
      expect(endpoint.connectCalls).toBe(1);

      await node.connect(connectTarget(endpoint.address.ticket));
      expect(endpoint.connectCalls).toBe(2);
      expect(node.peersSnapshot()).toHaveLength(1);
      connection.resolveClosed();
      await Promise.resolve();
      expect(node.peersSnapshot()).toHaveLength(1);
    } finally {
      await node.close();
    }
  });

  it('keeps a peer tombstone after close throws until physical closure and blocks reconnect', async () => {
    const connection = new ThrowingCloseConnection();
    const replacement = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection, replacement);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { shutdownTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      runtimes: Map<string, unknown>;
      resources: {
        tryAcquire(owner: { peerId: string; principalId: string }, request: { callbacks: number }): {
          release(): void;
        } | undefined;
      };
    };
    const sessions = [
      authenticatedSession('closing-session', 'oauth-client-a'),
      authenticatedSession('replacement-session', 'oauth-client-a')
    ];
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const retained = internals.resources.tryAcquire(
        { peerId: 'remote', principalId: 'principal' },
        { callbacks: 1 }
      )!;
      const closing = peer.close();
      expect(peer.close()).toBe(closing);
      await expect(closing).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(internals.runtimes.has('remote')).toBe(true);
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(endpoint.connectCalls).toBe(1);

      connection.resolveClosed();
      await Promise.resolve();
      expect(internals.runtimes.has('remote')).toBe(true);
      retained.release();
      await expect.poll(() => internals.runtimes.has('remote')).toBe(false);
      await expect(node.connect(connectTarget(endpoint.address.ticket))).resolves.toBeDefined();
      expect(endpoint.connectCalls).toBe(2);
    } finally {
      await node.close();
    }
  });

  it('retains superseded physical connections when close throws until shutdown can prove closure', async () => {
    const original = new ThrowingCloseConnection('remote', 'server');
    const replacement = new AdmissionConnection(false, 'remote', 'client');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { shutdownTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      runtimes: Map<string, unknown>;
    };
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('replacement-session', 'oauth-client-a')
    ];
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      expect(peer.identity.direction).toBe('outbound');
      await internals.registerInboundConnection(replacement);
      expect(original.closeCalls).toBe(1);
      expect(peer.identity.direction).toBe('inbound');

      await expect(peer.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(internals.runtimes.has('remote')).toBe(true);

      original.resolveClosed();
      await expect.poll(() => internals.runtimes.has('remote')).toBe(false);
    } finally {
      await node.close();
    }
  });

  it('publishes the replacement epoch before a superseded-session listener closes the peer', async () => {
    const original = new AdmissionConnection(false, 'aaa', 'client');
    const replacement = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('replacement-session', 'oauth-client-a')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      runtimes: { has(peerId: string): boolean };
    };
    internals.authenticate = async () => sessions.shift()!;

    let reentrantClose: Promise<void> | undefined;
    let observedDirection: 'inbound' | 'outbound' | undefined;
    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket, 'aaa'));
      const runtime = (peer as unknown as {
        runtime: { connectionController: AbortController };
      }).runtime;
      runtime.connectionController.signal.addEventListener('abort', () => {
        observedDirection = peer.identity.direction;
        reentrantClose = peer.close('Closed synchronously from the superseded epoch');
      }, { once: true });

      await expect(internals.registerInboundConnection(replacement)).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(observedDirection).toBe('inbound');
      expect(node.getPeer('aaa')).toBeUndefined();
      expect(replacement.closeCalls).toBeGreaterThanOrEqual(1);
      await reentrantClose;
      expect(internals.runtimes.has('aaa')).toBe(false);
    } finally {
      await node.close();
    }
  });

  it('does not resurrect a replacement when superseded-session cancellation closes the node', async () => {
    const original = new AdmissionConnection(false, 'aaa', 'client');
    const replacement = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('replacement-session', 'oauth-client-a')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      runtimes: { readonly size: number };
    };
    internals.authenticate = async () => sessions.shift()!;

    let reentrantNodeClose: Promise<void> | undefined;
    const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket, 'aaa'));
    const runtime = (peer as unknown as {
      runtime: { connectionController: AbortController };
    }).runtime;
    runtime.connectionController.signal.addEventListener('abort', () => {
      reentrantNodeClose = node.close();
    }, { once: true });

    await expect(internals.registerInboundConnection(replacement)).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await reentrantNodeClose;
    expect(node.peersSnapshot()).toHaveLength(0);
    expect(node.getPeer('aaa')).toBeUndefined();
    expect(internals.runtimes.size).toBe(0);
    expect(replacement.closeCalls).toBeGreaterThanOrEqual(1);
  });

  it('keeps a synchronously installed newer epoch when an outer replacement resumes', async () => {
    const original = new AdmissionConnection(false, 'aaa', 'client');
    const outerCandidate = new AdmissionConnection(false, 'aaa', 'server');
    const newerCandidate = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('outer-session', 'oauth-client-a')
    ];
    const newerSession = authenticatedSession('newer-session', 'oauth-client-a');
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      installConnection(
        runtime: unknown,
        connection: QuicConnection,
        identity: { readonly id: string; readonly direction: 'inbound' },
        session: AuthenticatedSession
      ): unknown;
    };
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket, 'aaa'));
      const runtime = (peer as unknown as {
        runtime: { connectionController: AbortController };
      }).runtime;
      runtime.connectionController.signal.addEventListener('abort', () => {
        internals.installConnection(
          runtime,
          newerCandidate,
          Object.freeze({ id: 'aaa', direction: 'inbound' as const }),
          newerSession
        );
      }, { once: true });

      await expect(internals.registerInboundConnection(outerCandidate)).rejects.toMatchObject({ code: 'DISCONNECTED' });
      expect(node.getPeer<typeof router>('aaa')?.session.id).toBe('newer-session');
      expect(peer.session.id).toBe('newer-session');
      expect(outerCandidate.closeCalls).toBe(1);
      expect(newerCandidate.closeCalls).toBe(0);
    } finally {
      await node.close();
    }
  });

  it('does not resurrect a replacement after the superseded transport close callback closes the peer', async () => {
    const original = new ReentrantCloseConnection('aaa', 'client');
    const replacement = new AdmissionConnection(false, 'aaa', 'server');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('original-session', 'oauth-client-a'),
      authenticatedSession('replacement-session', 'oauth-client-a')
    ];
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      runtimes: { has(peerId: string): boolean };
    };
    internals.authenticate = async () => sessions.shift()!;

    let reentrantClose: Promise<void> | undefined;
    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket, 'aaa'));
      original.onClose = () => {
        reentrantClose = peer.close('Closed synchronously from the transport callback');
      };

      await expect(internals.registerInboundConnection(replacement)).rejects.toMatchObject({ code: 'DISCONNECTED' });
      await reentrantClose;
      expect(node.getPeer('aaa')).toBeUndefined();
      expect(internals.runtimes.has('aaa')).toBe(false);
      expect(replacement.closeCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('restores live membership when an inbound connection revives a disconnected outbound runtime', async () => {
    const original = new AdmissionConnection(false, 'remote', 'client');
    const inbound = new AdmissionConnection(false, 'remote', 'server');
    const endpoint = new AdmissionEndpoint(original);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
    };
    const sessions = [
      authenticatedSession('outbound-session', 'oauth-client-a'),
      authenticatedSession('inbound-session', 'oauth-client-a')
    ];
    internals.authenticate = async () => sessions.shift()!;

    try {
      const retained = await node.connect<typeof router>(connectTarget(endpoint.address.ticket));
      const runtime = (retained as unknown as {
        runtime: { connection(): Promise<QuicConnection> };
      }).runtime;
      original.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);

      await internals.registerInboundConnection(inbound);

      expect(node.peersSnapshot()).toEqual([{ id: 'remote', direction: 'inbound' }]);
      expect(node.getPeer<typeof router>('remote')?.session.id).toBe('inbound-session');
      await expect(runtime.connection()).resolves.toMatchObject({ remoteId: 'remote', side: 'server' });
      expect(endpoint.connectCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('starts endpoint teardown immediately and node close waits underlying peer settlement', async () => {
    const connection = new AdmissionConnection(false, 'remote', 'client', false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { shutdownTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('closing-session', 'oauth-client-a');

    const peer = await node.connect(connectTarget(endpoint.address.ticket));
    await expect(peer.close()).rejects.toMatchObject({ code: 'TIMEOUT' });
    const closing = node.close();
    expect(endpoint.closeCalls).toBe(1);
    await expect(closing).rejects.toMatchObject({ code: 'TIMEOUT' });
    connection.resolveClosed();
  });

  it('observes a synchronous endpoint close failure without skipping other shutdown work', async () => {
    const endpoint = new ThrowingCloseEndpoint();
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const unhandled: unknown[] = [];
    const onUnhandled = (cause: unknown): void => { unhandled.push(cause); };
    process.on('unhandledRejection', onUnhandled);
    try {
      const closing = node.close();
      expect(endpoint.closeCalls).toBe(1);
      await expect(closing).rejects.toMatchObject({ code: 'INTERNAL' });
      expect(node.close()).toBe(closing);
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
    } finally {
      process.removeListener('unhandledRejection', onUnhandled);
    }
  });

  it('sanitizes and UTF-8 bounds public Peer.close reasons before local and transport use', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('closed-peer', 'oauth-client-a');

    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as {
        runtime: { connectionController: AbortController };
      }).runtime;
      const unsafeReason = `\n\u001b\u0085\u202e${'\ud83d\udca5'.repeat(10_000)}not transmitted`;
      const expected = `????${'\ud83d\udca5'.repeat(63)}`;

      peer.close(unsafeReason);

      expect(connection.closeRequests).toHaveLength(1);
      expect(connection.closeRequests[0]?.code).toBe(0n);
      const transmitted = new TextDecoder('utf-8', { fatal: true }).decode(connection.closeRequests[0]?.reason);
      expect(transmitted).toBe(expected);
      expect(Buffer.byteLength(transmitted, 'utf8')).toBe(256);
      expect((runtime.connectionController.signal.reason as Error).message).toBe(expected);
    } finally {
      await node.close();
    }
  });

  it('uses one exact abortable file context per physical authenticated connection', async () => {
    const original = new AdmissionConnection(false, 'remote', 'server');
    const replacement = new AdmissionConnection(false, 'remote', 'client');
    const endpoint = new AdmissionEndpoint(original, replacement);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('session-original', 'oauth-client-a'),
      authenticatedSession('session-replacement', 'oauth-client-a')
    ];
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => sessions.shift()!;

    try {
      const firstPeer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (firstPeer as unknown as {
        runtime: { currentFiles: { signal: AbortSignal }; fileConnection(): Promise<unknown> };
      }).runtime;
      const firstContext = await runtime.fileConnection() as { signal: AbortSignal };
      expect(Object.isFrozen(firstContext)).toBe(true);
      expect(firstContext.signal.aborted).toBe(false);

      original.resolveClosed();
      await expect.poll(() => firstContext.signal.aborted).toBe(true);
      // A file operation itself must be able to trigger reconnection and see
      // the managed connection, without a preceding node.connect() call.
      const secondContext = await runtime.fileConnection() as { signal: AbortSignal };
      expect(secondContext).not.toBe(firstContext);
      expect(firstContext.signal.aborted).toBe(true);
      expect(secondContext.signal.aborted).toBe(false);

      await node.close();
      expect(secondContext.signal.aborted).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('reports quiescent peer transfer diagnostics without exposing mutable manager state', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('diagnostic-session', 'oauth-client-a');

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const diagnostics = await peer.diagnostics();
      expect(diagnostics).toMatchObject({
        sessionId: 'diagnostic-session',
        connection: { sentBytes: 0, receivedBytes: 0, lostPackets: 0 },
        files: {
          activeTransfers: 0,
          queuedTransfers: 0,
          incomingSessions: 0,
          reservedSessions: 0,
          activeLanes: 0,
          activeOperations: 0,
          ambiguousOperations: 0,
          operationRecords: 0
        },
        resources: { queued: 0, active: { streams: 0, bufferedBytes: 0 } },
        shares: { activeShares: 0, operationRecords: 0, activeReservations: 0, closed: false },
        tasks: { peer: expect.any(Number), node: expect.any(Number) }
      });
      expect(Object.isFrozen(diagnostics)).toBe(true);
      expect(Object.isFrozen(diagnostics.files)).toBe(true);
      expect(Object.isFrozen(diagnostics.resources)).toBe(true);
      expect(Object.isFrozen(diagnostics.shares)).toBe(true);
      expect(Object.isFrozen(diagnostics.tasks)).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('binds safe peer file shares to the current endpoint and complete principal', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      shares: ShareRegistry;
    };
    internals.authenticate = async () => authenticatedSession('share-session', 'oauth-client-a');
    const source = Object.freeze({
      name: 'bound.bin',
      size: 1,
      readChunk: async () => Uint8Array.of(1)
    });

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const handle = peer.files.share(source, { maxDownloads: 1 });
      expect(Object.isFrozen(handle)).toBe(true);
      expect(() => peer.files.share(source, { allowedPeerIds: ['attacker'] } as never))
        .toThrow(/unknown field/);
      const request = {
        peerId: 'remote',
        principalId: 'principal',
        subject: 'subject',
        issuer: 'https://identity.example',
        clientId: 'oauth-client-a',
        tenantId: 'tenant',
        fingerprint: 'chunk-plan-v3',
        operationId: 'operation-1'
      };
      expect(() => internals.shares.reserve(handle.token, { ...request, peerId: 'attacker' }))
        .toThrowError(P2PError);
      expect(() => internals.shares.reserve(handle.token, { ...request, tenantId: 'other' }))
        .toThrowError(P2PError);
      const reservation = internals.shares.reserve(handle.token, request);
      expect(reservation.source).toBe(source);
      reservation.complete();
      expect(() => internals.shares.reserve(handle.token, { ...request, operationId: 'operation-2' }))
        .toThrowError(P2PError);
    } finally {
      await node.close();
    }
  });

  it('aborts the exact file context on connection closure and session expiry', async () => {
    const closedConnection = new AdmissionConnection(false, 'remote-closed');
    const expiringConnection = new ThrowingCloseConnection('remote-expiring');
    const endpoint = new AdmissionEndpoint(closedConnection, expiringConnection);
    let inspectExpiryVisibility = (): { readonly peerCount: number; readonly hasPeer: boolean } => ({
      peerCount: -1,
      hasPeer: true
    });
    let expiryVisibility: { readonly peerCount: number; readonly hasPeer: boolean } | undefined;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onSecurityEvent: (event) => {
        if (event.type === 'session.expired' && event.peerId === 'remote-expiring') {
          expiryVisibility = inspectExpiryVisibility();
        }
      },
      endpointFactory: async () => endpoint
    });
    inspectExpiryVisibility = () => ({
      peerCount: node.peersSnapshot().length,
      hasPeer: node.getPeer('remote-expiring') !== undefined
    });
    const sessions = [
      authenticatedSession('session-closed', 'oauth-client-a'),
      // Leave enough time for admission finalization before exercising expiry.
      authenticatedSession('session-expiring', 'oauth-client-a', 250)
    ];
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => sessions.shift()!;

    try {
      const closedPeer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-closed'));
      const closedSignal = ((closedPeer as unknown as { runtime: { currentFiles: { signal: AbortSignal } } }).runtime)
        .currentFiles.signal;
      closedConnection.resolveClosed();
      await expect.poll(() => closedSignal.aborted).toBe(true);

      const expiringPeer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-expiring'));
      const expiringSignal = ((expiringPeer as unknown as { runtime: { currentFiles: { signal: AbortSignal } } }).runtime)
        .currentFiles.signal;
      await expect.poll(() => expiringSignal.aborted, { timeout: 1_000 }).toBe(true);
      expect(expiringConnection.closeCalls).toBeGreaterThan(0);
      // Session expiry is immediately absent from the public live-peer API,
      // even when the transport close throws and physical closure has not yet
      // settled.
      expect(node.peersSnapshot()).toHaveLength(0);
      expect(node.getPeer<typeof router>('remote-expiring')).toBeUndefined();
      expect(expiryVisibility).toEqual({ peerCount: 0, hasPeer: false });
      expiringConnection.resolveClosed();
    } finally {
      await node.close();
    }
  });

  it('enforces peer capacity and passes the configured inbound chunk ceiling to file transfers', async () => {
    const first = new AdmissionConnection(false, 'remote-a');
    const rejected = new AdmissionConnection(false, 'remote-b');
    const endpoint = new AdmissionEndpoint(first, rejected);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: {
        maxPeers: 1,
        fileChunkSize: 64 * 1024,
        maxFileChunkSize: 128 * 1024,
        maxGlobalFileTransfers: 1
      },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-a'));
      const transferLimits = ((peer as unknown as {
        runtime: { transfers: { options: { limits: { maxChunkSize: number } } } };
      }).runtime).transfers.options.limits;
      expect(transferLimits.maxChunkSize).toBe(128 * 1024);
      await expect(node.connect(connectTarget(endpoint.address.ticket, 'remote-b'))).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
      expect(node.peersSnapshot()).toHaveLength(1);
      expect(endpoint.connectCalls).toBe(1);
      expect(rejected.closeCalls).toBe(0);
    } finally {
      await node.close();
    }
  });

  it('reserves maxPeers capacity across concurrent authentication and disconnected runtimes', async () => {
    const retainedConnection = new AdmissionConnection(false, 'retained', 'client');
    const candidateB = new AdmissionConnection(false, 'candidate-b', 'server');
    const candidateC = new AdmissionConnection(false, 'candidate-c', 'server');
    const endpoint = new AdmissionEndpoint(retainedConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { maxPeers: 2 },
      endpointFactory: async () => endpoint
    });
    const candidateAuthentication = deferred<AuthenticatedSession>();
    const authenticationStarted = deferred<void>();
    let authenticationCalls = 0;
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      registerInboundConnection(connection: QuicConnection): Promise<unknown>;
      runtimes: { readonly size: number; readonly occupied: number; has(peerId: string): boolean };
    };
    internals.authenticate = async () => {
      authenticationCalls += 1;
      if (authenticationCalls === 1) return authenticatedSession('retained-session', 'oauth-client-a');
      if (authenticationCalls === 2) {
        authenticationStarted.resolve();
        return candidateAuthentication.promise;
      }
      throw new Error('Capacity rejection must happen before authenticating candidate C');
    };

    try {
      await node.connect(connectTarget(endpoint.address.ticket, 'retained'));
      retainedConnection.resolveClosed();
      await expect.poll(() => node.peersSnapshot()).toHaveLength(0);
      expect(internals.runtimes.size).toBe(1);

      const admittingB = internals.registerInboundConnection(candidateB);
      await authenticationStarted.promise;
      expect(internals.runtimes.occupied).toBe(2);

      await expect(internals.registerInboundConnection(candidateC)).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
      expect(authenticationCalls).toBe(2);
      expect(candidateC.closeCalls).toBe(1);
      expect(internals.runtimes.occupied).toBe(2);

      candidateAuthentication.resolve(authenticatedSession('candidate-b-session', 'oauth-client-a'));
      await admittingB;
      expect(internals.runtimes.size).toBe(2);
      expect(internals.runtimes.has('retained')).toBe(true);
      expect(internals.runtimes.has('candidate-b')).toBe(true);
    } finally {
      candidateAuthentication.resolve(authenticatedSession('candidate-b-session', 'oauth-client-a'));
      await node.close();
    }
  });

  it('rejects a default file chunk size above the inbound ceiling', async () => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { fileChunkSize: 128 * 1024, maxFileChunkSize: 64 * 1024 },
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(endpointCreated).toBe(false);
  });

  it('rejects a zero file-size ceiling before creating an endpoint', async () => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { maxFileSize: 0 },
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(endpointCreated).toBe(false);
  });

  it.each([
    { maxInboundStreams: 1 },
    { maxInboundStreams: 2 },
    { maxInboundStreams: 3 },
    { maxInboundStreams: 4 },
    { maxGlobalInboundStreams: 1 },
    { maxGlobalInboundStreams: 2 },
    { maxGlobalInboundStreams: 3 },
    { maxGlobalInboundStreams: 4 },
    { maxPrincipalInboundStreams: 1 },
    { maxPrincipalInboundStreams: 2 },
    { maxPrincipalInboundStreams: 3 },
    { maxPrincipalInboundStreams: 4 },
    { maxPeerBufferedBytes: DEFAULT_MINIMUM_FILE_BUFFER - 1 },
    { maxPrincipalBufferedBytes: DEFAULT_MINIMUM_FILE_BUFFER - 1 },
    { maxBufferedBytes: DEFAULT_MINIMUM_FILE_BUFFER - 1 }
  ])('rejects quotas which cannot reserve bidirectional file-lane progress: %j', async (limits) => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits,
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(endpointCreated).toBe(false);
  });

  it.each([
    ['maxControlFrameItems', 0],
    ['maxControlFrameItems', 1_000_001],
    ['maxControlFrameDepth', 0],
    ['maxControlFrameDepth', 257]
  ] as const)('rejects invalid %s before creating an endpoint', async (name, value) => {
    let endpointCreated = false;
    await expect(createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { [name]: value },
      endpointFactory: async () => {
        endpointCreated = true;
        return new AdmissionEndpoint();
      }
    })).rejects.toMatchObject({ code: 'RESOURCE_LIMIT' });
    expect(endpointCreated).toBe(false);
  });

  it('audits thrown authorization failures without leaking callback messages', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const events: SecurityAuditEvent[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: {
        ...unusedSecurity(),
        authorize: () => { throw new Error('secret policy backend detail'); }
      },
      onSecurityEvent: (event) => events.push(event),
      endpointFactory: async () => endpoint
    });
    const session = authenticatedSession('session', 'oauth-client-a');
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      authorize(runtime: unknown, session: AuthenticatedSession, action: { kind: 'file.pull'; capabilityId: string }): Promise<void>;
    };
    internals.authenticate = async () => session;

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const runtime = (peer as unknown as { runtime: unknown }).runtime;
      await expect(internals.authorize(runtime, session, { kind: 'file.pull', capabilityId: 'capability' }))
        .rejects.toThrow('secret policy backend detail');
      expect(events.filter((event) => event.type === 'authorization')).toMatchObject([{
        type: 'authorization',
        allowed: false,
        reason: 'Authorization evaluation failed'
      }]);
      expect(JSON.stringify(events)).not.toContain('secret policy backend detail');
    } finally {
      await node.close();
    }
  });

  it('reports safely cleaned file-control failures through the node error hook', async () => {
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const errors: P2PError[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      onError: (error) => errors.push(error),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      await node.connect(connectTarget(endpoint.address.ticket));

      const malformed = duplexPair();
      await writeStreamKind(malformed.right.send, 255 as StreamKind);
      connection.queueBi(malformed.left);
      await expect.poll(() => errors.some(
        (error) => error.code === 'INVALID_FRAME' && error.message.includes('Unknown stream kind')
      )).toBe(true);

      // A safely terminated pre-admission classifier must not kill the
      // per-connection accept loop. The next correctly classified stream is
      // dispatched and reports its own independent frame error.
      const stream = duplexPair();
      await writeStreamKind(stream.right.send, StreamKind.TransferControl);
      await writeFrame(stream.right.send, 99, {});
      connection.queueBi(stream.left);
      await expect.poll(() => errors.filter((error) => error.code === 'INVALID_FRAME')).toHaveLength(2);
    } finally {
      await node.close();
    }
  });

  it('keeps inbound file-control admission reachable when general RPC capacity is saturated', async () => {
    const controlBytes = 64 * 1024;
    const fileDataBytes = 2 * controlBytes;
    const minimumBuffers = 3 * controlBytes + 2 * fileDataBytes;
    const connection = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(connection);
    const errors: P2PError[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: {
        maxControlFrameBytes: controlBytes,
        fileChunkSize: controlBytes,
        maxFileChunkSize: controlBytes,
        maxInboundStreams: 5,
        maxGlobalInboundStreams: 5,
        maxPrincipalInboundStreams: 5,
        maxFileTransfers: 1,
        maxGlobalFileTransfers: 1,
        maxPrincipalFileTransfers: 1,
        maxBufferedBytes: minimumBuffers,
        maxPeerBufferedBytes: minimumBuffers,
        maxPrincipalBufferedBytes: minimumBuffers
      },
      onError: (error) => errors.push(error),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: {
        tryAcquire(
          owner: { peerId: string; principalId: string },
          request: { streams: number; bufferedBytes: number }
        ): { release(): void } | undefined;
      };
    };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    let general: { release(): void } | undefined;
    try {
      await node.connect(connectTarget(endpoint.address.ticket));
      general = internals.resources.tryAcquire(
        { peerId: 'remote', principalId: 'principal' },
        { streams: 1, bufferedBytes: controlBytes }
      );
      expect(general).toBeDefined();

      const overloadedRpc = duplexPair();
      await writeStreamKind(overloadedRpc.right.send, StreamKind.Rpc);
      connection.queueBi(overloadedRpc.left);
      await expect.poll(() => errors.some(
        (error) => error.message === 'Inbound RPC capacity is unavailable'
      )).toBe(true);

      const stream = duplexPair();
      await writeStreamKind(stream.right.send, StreamKind.TransferControl);
      await writeFrame(stream.right.send, 99, {});
      connection.queueBi(stream.left);

      await expect.poll(() => errors.some((error) => error.code === 'INVALID_FRAME')).toBe(true);
    } finally {
      general?.release();
      await node.close();
    }
  });

  it('retains unadmitted bidirectional stream ownership until physical closure', async () => {
    const connection = new ThrowingCloseConnection();
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { streamHeaderTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: { snapshot(): { active: { streams: number; bufferedBytes: number }; peers: number; principals: number } };
    };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      await node.connect(connectTarget(endpoint.address.ticket));
      const stream = new RejectingCleanupPipe();
      await writeStreamKind(stream, 255 as StreamKind);
      connection.queueBi({ send: stream, recv: stream });

      await expect.poll(() => connection.closeCalls).toBe(1);
      // The one-byte classifier is deliberately outside quota admission, so a
      // malformed stream cannot consume a directional progress reserve. The
      // physical connection task, rather than a scheduler lease, owns it.
      expect(internals.resources.snapshot()).toMatchObject({
        active: { streams: 0, bufferedBytes: 0 },
        peers: 0,
        principals: 0
      });

      let closed = false;
      const closing = node.close().then(() => { closed = true; });
      await Promise.resolve();
      expect(closed).toBe(false);
      connection.resolveClosed();
      await closing;
      expect(closed).toBe(true);
    } finally {
      connection.resolveClosed();
      await node.close();
    }
  });

  it('retains an inbound unidirectional stream lease when stop stalls until physical closure', async () => {
    const connection = new AdmissionConnection(false, 'remote', 'client', false);
    const endpoint = new AdmissionEndpoint(connection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { streamHeaderTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: { snapshot(): { active: { streams: number; bufferedBytes: number }; peers: number; principals: number } };
    };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      await node.connect(connectTarget(endpoint.address.ticket));
      const stream = new StalledStopPipe();
      await writeStreamKind(stream, StreamKind.Rpc);
      connection.queueUni(stream);

      await expect.poll(() => connection.closeCalls, { timeout: 1_000 }).toBe(1);
      expect(internals.resources.snapshot()).toMatchObject({
        active: { streams: 1, bufferedBytes: 4 * 1024 * 1024 + 64 * 1024 },
        peers: 1,
        principals: 1
      });

      connection.resolveClosed();
      await expect.poll(() => internals.resources.snapshot()).toMatchObject({
        active: { streams: 0, bufferedBytes: 0 },
        peers: 0,
        principals: 0
      });
    } finally {
      await node.close();
    }
  });

  it('retains committed inbound file-control admission until physical closure after cleanup failure', async () => {
    const connection = new AdmissionConnection(false, 'remote', 'client', false);
    const endpoint = new AdmissionEndpoint(connection);
    let finalizes = 0;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: { ...unusedSecurity(), authorize: () => true },
      onIncomingFile: () => ({
        accept: {
          prepare: async () => new Set<number>(),
          writeChunk: async () => undefined,
          finalize: async (_manifest, context) => {
            finalizes += 1;
            context.markCommitted();
          },
          abort: async () => undefined
        }
      }),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as {
      authenticate(): Promise<AuthenticatedSession>;
      resources: { snapshot(): { active: { streams: number; bufferedBytes: number }; peers: number; principals: number } };
    };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      const peer = await node.connect(connectTarget(endpoint.address.ticket));
      const sessionSignal = (peer as unknown as {
        runtime: { currentFiles: { signal: AbortSignal } };
      }).runtime.currentFiles.signal;
      const localToRemote = new CleanupRejectingPipe();
      const remoteToLocal = new CleanupRejectingPipe();
      const local = { send: localToRemote, recv: remoteToLocal };
      const remote = { send: remoteToLocal, recv: localToRemote };
      await writeStreamKind(remote.send, StreamKind.TransferControl);
      await writeFrame(remote.send, TransferFrameKind.Offer, {
        transferId: 'committed-control-ownership',
        name: 'empty.bin',
        size: 0,
        digest: '0'.repeat(64),
        chunkSize: 1024 * 1024,
        chunkCount: 0
      });
      connection.queueBi(local);

      const acceptance = await readFrame<Record<string, unknown>>(remote.recv);
      expect(acceptance).toMatchObject({ kind: TransferFrameKind.Accept });
      await writeFrame(remote.send, TransferFrameKind.Complete, {
        transferId: 'committed-control-ownership',
        attemptId: acceptance.value.attemptId
      });
      const terminal = await readFrame(remote.recv);
      expect(terminal.kind).toBe(TransferFrameKind.Complete);
      // Omit the receipt after publication, then make both local terminal
      // operations reject. The transfer result remains success, but its native
      // stream lease must remain visible until closed() fulfills.
      await remote.send.finish();

      await expect.poll(() => finalizes).toBe(1);
      await expect.poll(() => connection.closeCalls).toBeGreaterThanOrEqual(1);
      expect(sessionSignal.aborted).toBe(true);
      expect(internals.resources.snapshot()).toMatchObject({
        active: { streams: 1, bufferedBytes: 1024 * 1024 },
        peers: 1,
        principals: 1
      });

      connection.resolveClosed();
      await expect.poll(() => internals.resources.snapshot()).toMatchObject({
        active: { streams: 0, bufferedBytes: 0 },
        peers: 0,
        principals: 0
      });
    } finally {
      connection.resolveClosed();
      await node.close();
    }
  });

  it('backpressures file controls at the global admission limit', async () => {
    const firstConnection = new AdmissionConnection(false, 'remote-a');
    const secondConnection = new AdmissionConnection(false, 'remote-b');
    const endpoint = new AdmissionEndpoint(firstConnection, secondConnection);
    const errors: P2PError[] = [];
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { maxGlobalFileTransfers: 1 },
      onError: (error) => errors.push(error),
      endpointFactory: async () => endpoint
    });
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => authenticatedSession('session', 'oauth-client-a');

    try {
      await node.connect(connectTarget(endpoint.address.ticket, 'remote-a'));
      const secondPeer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-b'));

      const stalled = duplexPair();
      await writeStreamKind(stalled.right.send, StreamKind.TransferControl);
      firstConnection.queueBi(stalled.left);
      await (stalled.left.recv as AsyncPipe).waitingForBytes;

      const rejected = duplexPair();
      await writeStreamKind(rejected.right.send, StreamKind.TransferControl);
      secondConnection.queueBi(rejected.left);
      await expect.poll(async () => (await secondPeer.diagnostics()).resources.queued).toBe(1);
      expect(errors).toEqual([]);
    } finally {
      await node.close();
    }
  });

  it('enforces one file-transfer quota across endpoint keys for the same principal', async () => {
    const firstConnection = new AdmissionConnection(false, 'remote-a');
    const secondConnection = new AdmissionConnection(false, 'remote-b');
    const endpoint = new AdmissionEndpoint(firstConnection, secondConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { maxGlobalFileTransfers: 2, maxPrincipalFileTransfers: 1 },
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('session-a', 'oauth-client-a'),
      authenticatedSession('session-b', 'oauth-client-a')
    ];
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    internals.authenticate = async () => sessions.shift()!;

    try {
      await node.connect(connectTarget(endpoint.address.ticket, 'remote-a'));
      const secondPeer = await node.connect(connectTarget(endpoint.address.ticket, 'remote-b'));
      const first = duplexPair();
      await writeStreamKind(first.right.send, StreamKind.TransferControl);
      firstConnection.queueBi(first.left);
      await (first.left.recv as AsyncPipe).waitingForBytes;

      const second = duplexPair();
      await writeStreamKind(second.right.send, StreamKind.TransferControl);
      secondConnection.queueBi(second.left);
      await expect.poll(async () => (await secondPeer.diagnostics()).resources.queued).toBe(1);
      expect((await secondPeer.diagnostics()).resources.active.inboundTransfers).toBe(1);
    } finally {
      await node.close();
    }
  });
});

function unusedSecurity(): P2PNodeOptions<typeof router>['security'] {
  return {
    getCredential: () => {
      throw new Error('Admission should run before credentials are requested');
    },
    authenticate: () => {
      throw new Error('Admission should run before authentication');
    },
    authorize: () => false
  };
}

function authenticatedSession(id: string, clientId: string, ttlMs = 60_000): AuthenticatedSession {
  const expiresAt = Date.now() + ttlMs;
  return Object.freeze({
    id,
    establishedAt: Date.now(),
    expiresAt,
    principal: Object.freeze({
      id: 'principal',
      subject: 'subject',
      issuer: 'https://identity.example',
      clientId,
      tenantId: 'tenant',
      expiresAt,
      scopes: new Set(['p2prpc:connect']),
      claims: Object.freeze({})
    })
  });
}

function sharedSecretSession(id: string, peerId: string): AuthenticatedSession {
  const expiresAt = Date.now() + 60_000;
  return Object.freeze({
    id,
    establishedAt: Date.now(),
    expiresAt,
    principal: Object.freeze({
      id: peerId,
      subject: peerId,
      expiresAt,
      scopes: new Set(['p2prpc:*']),
      claims: Object.freeze({ authentication: 'shared-secret' })
    })
  });
}

function connectTarget(ticket: string, expectedPeerId = 'remote'): ConnectOptions {
  return {
    locator: { kind: 'ticket', ticket },
    expectedPeerId,
    expectedPrincipal: {
      subject: 'subject',
      issuer: 'https://identity.example',
      clientId: 'oauth-client-a',
      tenantId: 'tenant'
    }
  };
}

function decodeTicketBody(ticket: string): {
  readonly directAddresses: string[];
  readonly relayUrl: string | null;
  readonly issuedAt: number;
} {
  const [, body] = ticket.split('.');
  if (!body) throw new Error('Ticket body is missing');
  return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')) as {
    directAddresses: string[];
    relayUrl: string | null;
    issuedAt: number;
  };
}

class LocatorEndpoint implements QuicEndpoint {
  readonly id = 'local';
  readonly address = { id: this.id, ticket: 'locator-ticket' };
  readonly locators: EndpointLocator[] = [];
  readonly expectedPeerIds: string[] = [];
  readonly signals: Array<AbortSignal | undefined> = [];
  legacyConnectCalls = 0;

  constructor(private readonly connection: QuicConnection) {}

  async connect(): Promise<QuicConnection> {
    this.legacyConnectCalls += 1;
    throw new Error('Legacy ticket dialing must not be used');
  }

  async connectLocator(
    locator: EndpointLocator,
    _alpn: Uint8Array,
    expectedPeerId: string,
    signal?: AbortSignal
  ): Promise<QuicConnection> {
    this.locators.push(locator);
    this.expectedPeerIds.push(expectedPeerId);
    this.signals.push(signal);
    return this.connection;
  }

  async accept(): Promise<null> {
    return null;
  }

  async close(): Promise<void> {}
}

class InboundEndpoint implements QuicEndpoint {
  readonly id = 'local';
  readonly address = { id: this.id, ticket: 'inbound-ticket' };
  acceptCalls = 0;
  private readonly queued: QuicConnection[] = [];
  private waiter: ((connection: QuicConnection | null) => void) | undefined;
  private closed = false;

  async connect(): Promise<QuicConnection> {
    throw new Error('Inbound test endpoint cannot dial');
  }

  accept(): Promise<QuicConnection | null> {
    this.acceptCalls += 1;
    const connection = this.queued.shift();
    if (connection) return Promise.resolve(connection);
    if (this.closed) return Promise.resolve(null);
    return new Promise<QuicConnection | null>((resolve) => { this.waiter = resolve; });
  }

  queue(connection: QuicConnection): void {
    const waiter = this.waiter;
    if (waiter) {
      this.waiter = undefined;
      waiter(connection);
    } else {
      this.queued.push(connection);
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    this.waiter?.(null);
    this.waiter = undefined;
  }
}

class CancelableReconnectEndpoint implements QuicEndpoint {
  readonly id = 'local';
  readonly address = { id: this.id, ticket: 'reconnect-ticket' };
  connectCalls = 0;
  reconnectSignal: AbortSignal | undefined;

  constructor(private readonly initial: QuicConnection) {}

  async connect(): Promise<QuicConnection> {
    throw new Error('Locator dialing is required');
  }

  connectLocator(
    _locator: EndpointLocator,
    _alpn: Uint8Array,
    _expectedPeerId: string,
    signal?: AbortSignal
  ): Promise<QuicConnection> {
    this.connectCalls += 1;
    if (this.connectCalls === 1) return Promise.resolve(this.initial);
    this.reconnectSignal = signal;
    return new Promise<QuicConnection>((_resolve, reject) => {
      const onAbort = (): void => reject(
        signal?.reason ?? new P2PError('CANCELLED', 'Reconnect cancelled')
      );
      if (signal?.aborted) onAbort();
      else signal?.addEventListener('abort', onAbort, { once: true });
    });
  }

  async accept(): Promise<null> { return null; }
  async close(): Promise<void> {}
}

class AdmissionEndpoint implements QuicEndpoint {
  readonly id = 'local';
  readonly address = { id: this.id, ticket: 'admission-ticket' };
  connectCalls = 0;
  closeCalls = 0;
  readonly expectedPeerIds: string[] = [];
  private readonly connections: Array<QuicConnection | Promise<QuicConnection>>;

  constructor(...connections: Array<QuicConnection | Promise<QuicConnection>>) {
    this.connections = connections;
  }

  async connect(_ticket: string, _alpn: Uint8Array, expectedPeerId: string): Promise<QuicConnection> {
    this.connectCalls += 1;
    this.expectedPeerIds.push(expectedPeerId);
    const connection = this.connections.shift();
    if (!connection) throw new Error('No connection was queued');
    return await connection;
  }

  async accept(): Promise<null> {
    return null;
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
  }
}

class ThrowingCloseEndpoint extends AdmissionEndpoint {
  override close(): Promise<void> {
    this.closeCalls += 1;
    throw new Error('synchronous endpoint close failure');
  }
}

class AdmissionConnection implements QuicConnection {
  closeCalls = 0;
  readonly closeRequests: Array<{ readonly code: bigint; readonly reason: Uint8Array }> = [];
  private readonly incomingBi: QuicBiStream[] = [];
  private readonly biWaiters: Array<(stream: QuicBiStream) => void> = [];
  private readonly incomingUni: QuicRecvStream[] = [];
  private readonly uniWaiters: Array<(stream: QuicRecvStream) => void> = [];
  private readonly closedState = deferred<string>();

  constructor(
    private readonly rejectConfiguration = true,
    readonly remoteId = 'remote',
    readonly side: 'client' | 'server' = 'client',
    private readonly confirmLocalClose = true
  ) {}

  async openBi(): Promise<QuicBiStream> {
    return pending();
  }

  async acceptBi(): Promise<QuicBiStream> {
    const queued = this.incomingBi.shift();
    if (queued) return queued;
    return new Promise<QuicBiStream>((resolve) => this.biWaiters.push(resolve));
  }

  async openUni(): Promise<QuicSendStream> {
    return pending();
  }

  async acceptUni(): Promise<QuicRecvStream> {
    const queued = this.incomingUni.shift();
    if (queued) return queued;
    return new Promise<QuicRecvStream>((resolve) => this.uniWaiters.push(resolve));
  }

  async closed(): Promise<string> {
    return this.closedState.promise;
  }

  close(code: bigint, reason: Uint8Array): void {
    this.closeCalls += 1;
    this.closeRequests.push({ code, reason: Uint8Array.from(reason) });
    if (this.confirmLocalClose) this.closedState.resolve('locally closed');
  }

  async stats(): Promise<ConnectionStats> {
    return { rttMs: null, sentBytes: 0, receivedBytes: 0, lostPackets: 0 };
  }

  configure(): void {
    if (this.rejectConfiguration) throw new Error('Admission should run before the connection is configured');
  }

  queueBi(stream: QuicBiStream): void {
    const waiter = this.biWaiters.shift();
    if (waiter) waiter(stream);
    else this.incomingBi.push(stream);
  }

  queueUni(stream: QuicRecvStream): void {
    const waiter = this.uniWaiters.shift();
    if (waiter) waiter(stream);
    else this.incomingUni.push(stream);
  }

  resolveClosed(reason = 'closed'): void {
    this.closedState.resolve(reason);
  }
}

class FailingHandshakeCleanupConnection extends AdmissionConnection {
  readonly send = new TerminalRejectingCleanupPipe();
  readonly recv = new TerminalRejectingCleanupPipe();

  constructor() {
    super(false, 'remote', 'client', false);
  }

  override async openBi(): Promise<QuicBiStream> {
    return { send: this.send, recv: this.recv };
  }
}

class ThrowingCloseConnection extends AdmissionConnection {
  constructor(remoteId = 'remote', side: 'client' | 'server' = 'client') {
    super(false, remoteId, side, false);
  }

  override close(code: bigint, reason: Uint8Array): void {
    this.closeCalls += 1;
    this.closeRequests.push({ code, reason: Uint8Array.from(reason) });
    throw new Error('synchronous transport close failure');
  }
}

class ReentrantCloseConnection extends AdmissionConnection {
  onClose: (() => void) | undefined;

  constructor(remoteId: string, side: 'client' | 'server') {
    super(false, remoteId, side);
  }

  override close(code: bigint, reason: Uint8Array): void {
    super.close(code, reason);
    this.onClose?.();
  }
}

function duplexPair(): { left: QuicBiStream; right: QuicBiStream } {
  const leftToRight = new AsyncPipe();
  const rightToLeft = new AsyncPipe();
  return {
    left: { send: leftToRight, recv: rightToLeft },
    right: { send: rightToLeft, recv: leftToRight }
  };
}

class AsyncPipe implements QuicSendStream, QuicRecvStream {
  readonly waitingForBytes: Promise<void>;
  private readonly bytes: number[] = [];
  private readonly waiters: Array<() => void> = [];
  private ended = false;
  private signalWaitingForBytes!: () => void;

  constructor() {
    this.waitingForBytes = new Promise<void>((resolve) => { this.signalWaitingForBytes = resolve; });
  }

  async writeAll(data: Uint8Array): Promise<void> {
    this.bytes.push(...data);
    for (const waiter of this.waiters.splice(0)) waiter();
  }

  async readExact(size: number): Promise<Uint8Array> {
    while (this.bytes.length < size) {
      if (this.ended) throw new Error('EOF');
      this.signalWaitingForBytes();
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    return Uint8Array.from(this.bytes.splice(0, size));
  }

  async finish(): Promise<void> {
    this.ended = true;
    for (const waiter of this.waiters.splice(0)) waiter();
  }

  async expectEnd(): Promise<void> {
    while (!this.ended && this.bytes.length === 0) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
    }
    if (!this.ended || this.bytes.length !== 0) throw new Error('Expected clean EOF');
  }

  async reset(): Promise<void> {
    await this.finish();
  }

  async stop(): Promise<void> {
    await this.finish();
  }

  async setPriority(): Promise<void> {}
}

class RejectingCleanupPipe extends AsyncPipe {
  override async reset(): Promise<void> {
    throw new Error('reset failed');
  }

  override async stop(): Promise<void> {
    throw new Error('stop failed');
  }
}

class CleanupRejectingPipe extends AsyncPipe {
  override async reset(): Promise<void> {
    await super.reset();
    throw new Error('reset rejected after cleanup');
  }

  override async stop(): Promise<void> {
    await super.stop();
    throw new Error('stop rejected after cleanup');
  }
}

class TerminalRejectingCleanupPipe extends AsyncPipe {
  resetCalls = 0;
  stopCalls = 0;

  override async reset(): Promise<void> {
    this.resetCalls += 1;
    await super.reset();
    throw new Error('reset rejected after terminal cleanup');
  }

  override async stop(): Promise<void> {
    this.stopCalls += 1;
    await super.stop();
    throw new Error('stop rejected after terminal cleanup');
  }
}

class StalledStopPipe extends AsyncPipe {
  override stop(): Promise<void> {
    return pending();
  }
}

function pending<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

function deferred<T>(): { readonly promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function disconnectRuntimeForTest(value: unknown): void {
  const runtime = value as {
    lifecycle: {
      readonly state: string;
      readonly epoch: unknown;
      readonly outboundTarget?: unknown;
    };
  };
  const lifecycle = runtime.lifecycle;
  if (lifecycle.state !== 'live' || lifecycle.outboundTarget === undefined) {
    throw new Error('Test runtime is not a reconnectable live epoch');
  }
  runtime.lifecycle = Object.freeze({
    state: 'disconnected',
    epoch: lifecycle.epoch,
    outboundTarget: lifecycle.outboundTarget
  });
}
