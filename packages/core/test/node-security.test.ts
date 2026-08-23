import { initTRPC } from '@trpc/server';
import { describe, expect, it } from 'vitest';
import {
  createP2PNode,
  P2PError,
  type AuthenticatedSession,
  type ConnectOptions,
  type P2PNodeOptions,
  type SecurityAuditEvent
} from '../src/index.js';
import { StreamKind, writeFrame, writeStreamKind } from '../src/protocol.js';
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

describe('node security boundaries', () => {
  it('passes a signal to peer admission and aborts it at the handshake deadline', async () => {
    const connection = new AdmissionConnection();
    const endpoint = new AdmissionEndpoint(connection);
    let admissionSignal: AbortSignal | undefined;
    let admissionPeerFrozen = false;
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      preAuthorizePeer: (peer, signal) => {
        admissionPeerFrozen = Object.isFrozen(peer);
        admissionSignal = signal;
        return new Promise<boolean>(() => undefined);
      },
      limits: { handshakeTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'TIMEOUT' });
      expect(admissionSignal).toBeDefined();
      expect(admissionSignal?.aborted).toBe(true);
      expect(admissionPeerFrozen).toBe(true);
      expect(connection.closeCalls).toBe(1);
    } finally {
      await node.close();
    }
  });

  it('keeps existing one-argument peer admission callbacks source compatible', () => {
    const admission: NonNullable<P2PNodeOptions<typeof router>['preAuthorizePeer']> = () => true;
    expect(admission({ id: 'remote', direction: 'inbound' }, new AbortController().signal)).toBe(true);
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
      ticket: endpoint.address.ticket,
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
        locator: { kind: 'dns' }
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
      { relayUrls: ['https://relay.example'], allowRelayUrl: () => undefined }
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

  it('fails DNS discovery closed when resolved routes cannot be checked by application egress policy', { timeout: 30_000 }, async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/dns-policy/1');
    await expect(IrohEndpoint.create(alpn, {
      relay: { mode: 'disabled' },
      discovery: { dns: true },
      allowDirectAddress: () => true
    })).rejects.toMatchObject({ code: 'UNAUTHORIZED' });
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

  it('canonicalizes custom relay origins and rejects equivalent duplicates before startup', async () => {
    const alpn = new TextEncoder().encode('p2prpc/2/relay-origin-canonicalization/1');
    await expect(IrohEndpoint.create(alpn, {
      relay: {
        mode: 'custom',
        urls: ['https://RELAY.example:443', 'https://relay.example/']
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

  it('audits only installed sessions and rejects an OAuth client identity swap', async () => {
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
      await expect(node.connect(connectTarget(endpoint.address.ticket))).resolves.toBeDefined();
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'UNAUTHORIZED' });

      expect(events.filter((event) => event.type === 'session.authenticated')).toMatchObject([
        { type: 'session.authenticated', sessionId: 'session-a' }
      ]);
      expect(events.filter((event) => event.type === 'session.rejected')).toHaveLength(1);
      expect(duplicate.closeCalls).toBe(1);
      expect(swapped.closeCalls).toBe(1);
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
      limits: { streamHeaderTimeoutMs: 100 },
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
      await node.close();
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
      connectedRuntime.alive = false;
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
      runtime.alive = false;
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
      runtime.alive = false;
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
    const late = new AdmissionConnection(false);
    const endpoint = new AdmissionEndpoint(pendingConnection.promise);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      limits: { connectTimeoutMs: 100 },
      endpointFactory: async () => endpoint
    });

    try {
      await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'TIMEOUT' });
      pendingConnection.resolve(late);
      await expect.poll(() => late.closeCalls).toBe(1);
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
      endpointFactory: async () => endpoint
    });

    const connecting = node.connect(connectTarget(endpoint.address.ticket));
    const rejection = expect(connecting).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await expect.poll(() => endpoint.connectCalls).toBe(1);
    await node.close();
    await rejection;
    pendingConnection.resolve(late);
    await expect.poll(() => late.closeCalls).toBe(1);
    await expect(node.connect(connectTarget(endpoint.address.ticket))).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(endpoint.connectCalls).toBe(1);
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
    const internals = node as unknown as { authenticate(): Promise<AuthenticatedSession> };
    const sessions = [
      authenticatedSession('closed-peer', 'oauth-client-a'),
      authenticatedSession('explicit-replacement', 'oauth-client-a')
    ];
    internals.authenticate = async () => sessions.shift()!;

    try {
      const peer = await node.connect<typeof router>(connectTarget(endpoint.address.ticket));
      expect(node.peersSnapshot()).toHaveLength(1);

      peer.close();
      peer.close();

      expect(node.peersSnapshot()).toHaveLength(0);
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

      await node.connect(connectTarget(endpoint.address.ticket));
      const secondContext = await runtime.fileConnection() as { signal: AbortSignal };
      expect(secondContext).not.toBe(firstContext);
      expect(firstContext.signal.aborted).toBe(true);
      expect(secondContext.signal.aborted).toBe(false);
      expect(original.closeCalls).toBe(1);

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
          activeLanes: 0
        }
      });
      expect(Object.isFrozen(diagnostics)).toBe(true);
      expect(Object.isFrozen(diagnostics.files)).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('aborts the exact file context on connection closure and session expiry', async () => {
    const closedConnection = new AdmissionConnection(false, 'remote-closed');
    const expiringConnection = new AdmissionConnection(false, 'remote-expiring');
    const endpoint = new AdmissionEndpoint(closedConnection, expiringConnection);
    const node = await createP2PNode({
      router,
      protocol: { applicationId: 'node-security-test', contractVersion: '1' },
      createContext: () => ({}),
      security: unusedSecurity(),
      endpointFactory: async () => endpoint
    });
    const sessions = [
      authenticatedSession('session-closed', 'oauth-client-a'),
      authenticatedSession('session-expiring', 'oauth-client-a', 30)
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
      expect(rejected.closeCalls).toBe(1);
    } finally {
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
      const stream = duplexPair();
      await writeStreamKind(stream.right.send, StreamKind.TransferControl);
      await writeFrame(stream.right.send, 99, {});
      connection.queueBi(stream.left);
      await expect.poll(() => errors.some((error) => error.code === 'INVALID_FRAME')).toBe(true);
    } finally {
      await node.close();
    }
  });

  it('enforces a separate global admission limit for active file controls', async () => {
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
      await node.connect(connectTarget(endpoint.address.ticket, 'remote-b'));

      const stalled = duplexPair();
      await writeStreamKind(stalled.right.send, StreamKind.TransferControl);
      firstConnection.queueBi(stalled.left);
      await (stalled.left.recv as AsyncPipe).waitingForBytes;

      const rejected = duplexPair();
      await writeStreamKind(rejected.right.send, StreamKind.TransferControl);
      secondConnection.queueBi(rejected.left);
      await expect.poll(() => errors.some((error) => (
        error.code === 'RESOURCE_LIMIT' && error.message.includes('Global inbound file transfer')
      ))).toBe(true);
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
    ticket,
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

class AdmissionEndpoint implements QuicEndpoint {
  readonly id = 'local';
  readonly address = { id: this.id, ticket: 'admission-ticket' };
  connectCalls = 0;
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

  async close(): Promise<void> {}
}

class AdmissionConnection implements QuicConnection {
  closeCalls = 0;
  readonly closeRequests: Array<{ readonly code: bigint; readonly reason: Uint8Array }> = [];
  private readonly incomingBi: QuicBiStream[] = [];
  private readonly biWaiters: Array<(stream: QuicBiStream) => void> = [];
  private readonly closedState = deferred<string>();

  constructor(
    private readonly rejectConfiguration = true,
    readonly remoteId = 'remote',
    readonly side: 'client' | 'server' = 'client'
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
    return pending();
  }

  async closed(): Promise<string> {
    return this.closedState.promise;
  }

  close(code: bigint, reason: Uint8Array): void {
    this.closeCalls += 1;
    this.closeRequests.push({ code, reason: Uint8Array.from(reason) });
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

  resolveClosed(reason = 'closed'): void {
    this.closedState.resolve(reason);
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

function pending<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

function deferred<T>(): { readonly promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
