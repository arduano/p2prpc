# p2prpc

[![CI](https://github.com/arduano/p2prpc/actions/workflows/ci.yml/badge.svg)](https://github.com/arduano/p2prpc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/arduano/p2prpc/actions/workflows/codeql.yml/badge.svg)](https://github.com/arduano/p2prpc/actions/workflows/codeql.yml)
[![Docs](https://github.com/arduano/p2prpc/actions/workflows/pages.yml/badge.svg)](https://arduano.github.io/p2prpc/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Type-safe peer-to-peer tRPC, subscriptions, and secure parallel file transfer over one Iroh QUIC connection.

p2prpc separates route discovery, Iroh endpoint identity, application identity, authorization, RPC metadata, and file capabilities. Knowing a node ID or signed ticket is never enough to dispatch work: both peers must finish the bounded mutual session handshake, establish an expiring principal, and authorize each operation. The current QUIC application protocol/ALPN is v4; its credential handshake format remains v3.

```text
authenticated Iroh QUIC connection
├── one bidirectional stream per RPC
├── one bidirectional control stream per file operation
└── bounded unidirectional file-data lanes
```

The [architecture and security wiki](https://arduano.github.io/p2prpc/) is the concise audit model. Start with [System Model](./docs/wiki/Home.md), [Lifecycles](./docs/wiki/Lifecycles.md), and the [Audit Guide](./docs/wiki/Audit-Guide.md).

> [!IMPORTANT]
> This is a pre-1.0 release candidate and has not been published to npm. Publishing remains blocked until the exact candidate passes the external discovery/relay, mixed-load, and 10,000-file lifecycle gates in [Production Validation](./docs/wiki/Production-Validation.md).

## Requirements

- Node.js 20.3+ in an ES module application
- TypeScript and tRPC 11
- A supported `@momics/iroh-http-node` native target
- matching application ID and contract version on both peers
- peer-bound shared-secret or OIDC security on every production node

CommonJS, browsers, and React Native are outside this release.

After the first registry release:

```bash
npm install @p2prpc/core @trpc/client@11.18.0 @trpc/server@11.18.0
```

## Secure RPC MVP

The shared-secret helper requires at least 32 bytes of separately provisioned random material and an explicit authorization policy. It proves workload-group membership; it does not identify individual users or tenants.

```ts
import { initTRPC, TRPCError } from '@trpc/server';
import { z } from 'zod';
import {
  createP2PNode,
  createSharedSecretSecurity,
  p2pRpcContext,
  type PeerContext
} from '@p2prpc/core';

const t = initTRPC.context<PeerContext>().create();
const tenantProcedure = t.procedure.use(({ ctx, next }) => {
  // Headers are untrusted assertions; the principal is verified.
  if (ctx.p2p.request.headers['x-tenant-id'] !== 'tenant-a') {
    throw new TRPCError({ code: 'FORBIDDEN' });
  }
  return next();
});

const appRouter = t.router({
  hello: tenantProcedure
    .input(z.object({ name: z.string().max(100) }))
    .query(({ input, ctx }) => ({
      greeting: `Hello ${input.name}`,
      principal: ctx.p2p.auth.principal.id,
      endpoint: ctx.p2p.peer.id
    }))
});
export type AppRouter = typeof appRouter;

// Load these exact values from trusted deployment/bootstrap configuration.
const approvedDirectRoutes = new Set(['203.0.113.10:4433']);
const approvedRelayOrigins = new Set(['https://relay.example']);
const node = await createP2PNode({
  router: appRouter,
  protocol: { applicationId: 'com.example.service', contractVersion: '1' },
  security: createSharedSecretSecurity(process.env.P2PRPC_SHARED_SECRET!, {
    authorize: ({ action }) => action.kind === 'rpc'
  }),
  iroh: {
    allowDirectAddress: (candidate) => approvedDirectRoutes.has(candidate),
    allowRelayUrl: (origin) => approvedRelayOrigins.has(origin)
  },
  createContext: (ctx) => ctx
});

const peer = await node.connect<AppRouter>({
  locator: { kind: 'ticket', ticket: remoteTicket },
  expectedPeerId: remoteEndpointId,
  expectedPrincipal: {
    id: remoteEndpointId,
    subject: remoteEndpointId,
    issuer: null,
    clientId: null,
    tenantId: null
  }
});

const reply = await peer.rpc.hello.query(
  { name: 'Ada' },
  { context: p2pRpcContext({ 'x-tenant-id': 'tenant-a', traceparent }) }
);
```

`connect()` always requires a locator plus independently trusted endpoint and principal expectations. Targets are exact-key validated, copied, frozen, and retained unchanged for reconnection. Discovery never supplies trust.

Header names are lowercased and the map is immutable. Count, name, value, and aggregate byte limits are enforced; credential/proxy/`p2prpc-*` names and unsafe Unicode/control characters are rejected. Use metadata for tracing, locale, idempotency keys, or a requested tenant—not identity. Verified identity is `ctx.p2p.auth.principal`.

Calls are never transparently retried. Cancellation or disconnect after dispatch yields `OUTCOME_UNKNOWN`; non-idempotent procedures need durable application idempotency.

## OIDC/OAuth without HTTP

p2prpc is an OAuth resource server. Your application obtains and refreshes access tokens through its normal flow; p2prpc mutually presents and verifies them inside the encrypted QUIC handshake.

```ts
import {
  createOidcSessionSecurity,
  irohPeerIdJwkThumbprint
} from '@p2prpc/core';

const security = createOidcSessionSecurity({
  issuers: [{
    issuer: 'https://identity.example.com',
    audience: 'urn:example:p2prpc:production',
    algorithms: ['RS256', 'ES256'],
    jwksUri: 'https://identity.example.com/.well-known/jwks.json'
  }],
  getAccessToken: async ({ localPeerId, remotePeerId }) =>
    tokenManager.getAccessToken({
      audience: 'urn:example:p2prpc:production',
      destinationPeerId: remotePeerId,
      // cnf.jkt binds the token to this presenting node, not its destination.
      confirmationJkt: await irohPeerIdJwkThumbprint(localPeerId)
    }),
  authorize: ({ principal, action }) =>
    principal.tenantId === 'tenant-a' &&
    (action.kind !== 'rpc' || !action.path.startsWith('admin.'))
});
```

OAuth remains useful without HTTP: it provides issuer-managed short lifetimes, audience and scope separation, client/tenant identity, signature-key rotation, and centralized grants—properties a plain API key does not inherently provide. HTTP redirects, token acquisition, and refresh tokens are out of scope.

Transport binding is not assumed. A token must contain `cnf.jkt` matching the presenting node's authenticated Iroh key, or—only when `cnf` is absent—an explicitly configured authoritative directory must bind the verified principal to that key. `irohPeerIdJwkThumbprint(localPeerId)` produces the canonical binding value; `remotePeerId` is only a destination hint for application-owned token selection. A malformed or mismatched present `cnf` always fails. Verification also requires configured issuer/audience/algorithms/JWKS, `iat`, `exp`, access-token `typ`, maximum age, and `p2prpc:connect`. Operations require `p2prpc:rpc`, exact `p2prpc:rpc:<path>`, `p2prpc:file:push`, or `p2prpc:file:pull`; `p2prpc:*` satisfies all library scopes.

Static JWKs require an explicit compatible allow-listed `alg`. Fetched JWKs may omit `alg` for provider compatibility, but any present value must be compatible and allow-listed; every fetched key requires a bounded unique `kid`. Remote JWKS uses HTTPS only, a 5-second fetch timeout, a 30-second success/failure refresh cooldown, and a 10-minute cache lifetime. Removing a key therefore does not invalidate an already authenticated session, and a cached key may remain usable until refresh; use short token/session lifetimes or online policy for urgent revocation.

See [Security Model](./docs/wiki/Security-Model.md) for the exact transcript and policy model.

## File push

File bytes bypass tRPC serialization and use a control stream plus bounded data lanes. The receiver makes a discriminated decision and chooses a trusted destination path; a remote filename is never treated as a path.

```ts
const receiver = await createP2PNode({
  // router, protocol, security, createContext...
  onIncomingFile: async (offer) => {
    if (offer.principal.tenantId !== 'tenant-a') {
      return { reject: 'tenant policy' };
    }
    return { accept: fileDestination('/srv/quarantine/incoming.bin') };
  }
});

const transfer = await peer.files.sendFile(await fileSource('/srv/export/video.mp4'));
for await (const progress of transfer.progress()) console.log(progress);
await transfer.result;
```

`fileSource()` retains one no-follow, identity-checked descriptor from hashing through transmission. `fileDestination()` uses bounded binary resume state, per-chunk and complete BLAKE3 verification, no-follow staging/lock files, and atomic durable publication.

Wire v4 closes every file delivery with a receiver-generated 256-bit receipt challenge after publication. A valid receiver completion makes sender success permanent. For a push, the echoed receipt also lets the receiver demote its hard acknowledgement-ambiguous record to a bounded replay tombstone. The node-lifetime ledger survives physical connection replacement and same-process runtime revival, but not process restart. Hard records have per-peer, canonical-principal, and node-wide caps and are never capacity-evicted; tombstones have separate evictable caps. This preserves reconciliation for a lost acknowledgement without making normal acknowledged push throughput wait for a 15-minute TTL.

## Typed capability pull

Issue a share from the session-bound file facade inside an authorized tRPC procedure. The root API automatically binds the 256-bit capability to the request's endpoint and complete current principal; callers cannot substitute arbitrary bindings or create bearer shares.

```ts
const filesRouter = t.router({
  requestDownload: tenantProcedure
    .input(z.object({ documentId: z.string().uuid() }))
    .query(async ({ input, ctx }) => {
      const path = await documents.authorizedPath(ctx.p2p.auth.principal, input.documentId);
      return ctx.p2p.files.share(await fileSource(path), {
        expiresAt: Math.min(Date.now() + 60_000, ctx.p2p.auth.expiresAt),
        maxDownloads: 1
      });
    })
});

const handle = await peer.rpc.files.requestDownload.query({ documentId });
const transfer = await peer.files.download(
  handle,
  fileDestination('/srv/downloads/report.pdf'),
  // Normally omit this for a random ID. Persist and reuse it only when the
  // same logical capability redemption must survive reconnect/retry.
  { operationId: durableDownloadOperationId }
);
await transfer.result;
```

Only a domain-separated token hash is stored. Logical operations have bounded records, expiry/download budgets, revocation, principal/endpoint/fingerprint binding, and fixed reconnect leases. A lost final acknowledgement cannot authorize a different operation or silently justify an unsafe retry.

Pushes use `SendFileOptions.transferId`, which is part of the manifest and may be reused only for the exact same push manifest. Pulls instead use `DownloadFileOptions.operationId`, which identifies one capability redemption; `download()` does not accept a push `transferId`.

Optional file metadata requires a Standard Schema v1 runtime schema on the node; metadata without one is rejected.

## Discovery and relays

Supported locator forms are:

```ts
{ kind: 'ticket', ticket }
{ kind: 'dns' }
{ kind: 'mdns', serviceName: 'corp-p2prpc' }
```

Node Iroh options select default, custom, or disabled relay policy and separately enable DNS/PKARR or mDNS. A remote signed ticket containing direct candidates requires `allowDirectAddress`; a remote default-relay hint requires `allowRelayUrl`. Custom relay membership is already an explicit allowlist. The callback receives only canonical untrusted remote candidates—not local default selection or configured custom origins—and callback exceptions deny before dial.

With pinned Iroh wrapper 0.6.0:

- DNS plus custom relay or candidate filtering is rejected because resolved routes cannot be inspected before dial.
- relay-disabled mode keeps UDP networking enabled while removing relay use. A version-locked compatibility seam corrects the wrapper's accidental loopback-only normalization, restores its module export synchronously, and fails closed on dependency drift.
- relay-less signed tickets and mDNS work only where peers have mutually reachable direct addresses; they do not provide relay/NAT traversal.
- mDNS defaults to private/link-local/loopback direct candidates and requires explicit policy for default-network relay hints.
- Omitting signed-ticket policy does not mean “allow all”; any corresponding remote route hint is rejected.

See [Production Validation](./docs/wiki/Production-Validation.md) for the exact topology matrix.

## API trust boundary

- `@p2prpc/core` — production node/peer APIs and branded peer-bound security factories.
- `@p2prpc/core/advanced` — custom authenticators/transports, raw link/registry components; explicitly expands the deployment TCB.
- `@p2prpc/core/testing` — endpoint injection and `dangerouslyAllowInsecureSessions()`; never use in production.

## Development

```bash
npm ci --strict-allow-scripts
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run build
npm run check:docs
npm run docs:build
```

The repository is MIT licensed. Third-party native packaging notes are in [THIRD_PARTY_NOTICES.md](./packages/core/THIRD_PARTY_NOTICES.md), and vulnerabilities should follow [SECURITY.md](./SECURITY.md).
