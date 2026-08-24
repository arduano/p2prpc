import { initTRPC } from '@trpc/server';
import type { KeyObject } from 'node:crypto';
import { expectTypeOf, it } from 'vitest';
import type {
  ConnectOptions,
  OidcIssuerConfiguration,
  OidcStaticJwk,
  P2PNode,
  Peer,
  PeerContext,
  PrincipalMatcher
} from '../src/index.js';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({ value: t.procedure.query(() => ({ ok: true as const })) });
type TypedPeer = Peer<typeof router>;

it('exposes the inferred tRPC proxy on peers', () => {
  void router;
  expectTypeOf<TypedPeer['rpc']['value']['query']>().toBeFunction();
  expectTypeOf<Awaited<ReturnType<TypedPeer['rpc']['value']['query']>>>().toEqualTypeOf<{ ok: true }>();
});

it('requires a typed expected target for outbound connections', () => {
  type ConnectArgument = Parameters<P2PNode<typeof router>['connect']>[0];
  expectTypeOf<ConnectArgument>().toEqualTypeOf<ConnectOptions>();
  expectTypeOf<ConnectArgument['expectedPrincipal']>().toEqualTypeOf<PrincipalMatcher>();
});

const completePrincipal: PrincipalMatcher = {
  subject: 'subject',
  issuer: null,
  clientId: null,
  tenantId: null
};

// @ts-expect-error A peer ID and principal cannot select a route by themselves.
const missingLocator: ConnectOptions = { expectedPeerId: 'peer', expectedPrincipal: completePrincipal };
// @ts-expect-error Discovery cannot supply the independently trusted endpoint expectation.
const missingEndpoint: ConnectOptions = { locator: { kind: 'dns' }, expectedPrincipal: completePrincipal };
// @ts-expect-error Discovery cannot supply the independently trusted principal expectation.
const missingPrincipal: ConnectOptions = { locator: { kind: 'dns' }, expectedPeerId: 'peer' };
// @ts-expect-error Legacy and current locator forms are mutually exclusive.
const ambiguousLocator: ConnectOptions = { locator: { kind: 'dns' }, ticket: 'legacy-ticket', expectedPeerId: 'peer', expectedPrincipal: completePrincipal };
void [missingLocator, missingEndpoint, missingPrincipal, ambiguousLocator];

const oidcBase = {
  issuer: 'https://identity.example',
  audience: 'urn:example:p2prpc',
  algorithms: ['RS256'] as const
};
// @ts-expect-error An issuer must select exactly one library-controlled trust root.
const oidcMissingTrustRoot: OidcIssuerConfiguration = oidcBase;
// @ts-expect-error Trust-root variants are mutually exclusive.
const oidcAmbiguousTrustRoot: OidcIssuerConfiguration = {
  ...oidcBase,
  jwksUri: 'https://identity.example/jwks.json',
  verificationKey: {} as KeyObject
};
const oidcEmptyAlgorithms: OidcIssuerConfiguration = {
  ...oidcBase,
  // @ts-expect-error The algorithm allow-list must be non-empty and restricted to supported algorithms.
  algorithms: [],
  jwksUri: 'https://identity.example/jwks.json'
};
const oidcPrivateJwk: OidcStaticJwk = {
  kty: 'RSA',
  alg: 'RS256',
  n: 'public-modulus',
  e: 'AQAB',
  // @ts-expect-error Private JWK members are excluded from the production API.
  d: 'private-exponent'
};
const oidcWrongCurve: OidcStaticJwk = {
  kty: 'EC',
  alg: 'ES384',
  // @ts-expect-error Static EC key algorithm and curve must agree by construction.
  crv: 'P-256',
  x: 'x',
  y: 'y'
};
void [oidcMissingTrustRoot, oidcAmbiguousTrustRoot, oidcEmptyAlgorithms, oidcPrivateJwk, oidcWrongCurve];
