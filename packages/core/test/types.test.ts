import { initTRPC } from '@trpc/server';
import { expectTypeOf, it } from 'vitest';
import type { Peer, PeerContext } from '../src/index.js';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({ value: t.procedure.query(() => ({ ok: true as const })) });
type TypedPeer = Peer<typeof router>;

it('exposes the inferred tRPC proxy on peers', () => {
  void router;
  expectTypeOf<TypedPeer['rpc']['value']['query']>().toBeFunction();
  expectTypeOf<Awaited<ReturnType<TypedPeer['rpc']['value']['query']>>>().toEqualTypeOf<{ ok: true }>();
});
