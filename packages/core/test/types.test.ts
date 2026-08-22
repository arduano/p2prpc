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
