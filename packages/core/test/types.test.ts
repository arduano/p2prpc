import { initTRPC } from '@trpc/server';
import { expectTypeOf, it } from 'vitest';
import type { ConnectOptions, P2PNode, Peer, PeerContext, PrincipalMatcher } from '../src/index.js';

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
