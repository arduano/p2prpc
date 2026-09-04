# @arduano/p2prpc-core

Type-safe peer-to-peer tRPC and secure parallel file transfer over one authenticated Iroh QUIC connection.

> Pre-1.0 package: a release tag publishes to GitHub Packages only after the
> exact `main` commit passes public CI. Publication alone is not a claim that
> the optional external production-validation suite has run.

GitHub Packages requires an authenticated npm client, including for public
packages. See the repository [installation and authentication
instructions](https://github.com/arduano/p2prpc#install-from-github-packages) before running
`npm install @arduano/p2prpc-core`.

## What it guarantees

- A node ID, address, locator, or signed ticket never grants application work.
- Every connection negotiates p2prpc wire/ALPN v4 and completes the six-message v3 credential handshake before RPC/file dispatch.
- Outbound callers independently pin both the Iroh endpoint ID and exact application principal.
- Per-operation authorization, immutable tRPC metadata, and global/peer/principal quotas are mandatory.
- RPCs use independent bidirectional streams; file data uses a control stream plus bounded parallel lanes.
- Built-in `fileSource()` remains stable from hashing through send; built-in `fileDestination()` fully verifies, atomically publishes, and marks the irreversible boundary before cleanup.
- Safe share handles are automatically bound to the current endpoint and complete principal.
- Failures after RPC dispatch or storage commit boundaries are explicit `OUTCOME_UNKNOWN`, never implicit retries.

## Minimal setup

```ts
import { initTRPC } from '@trpc/server';
import {
  createP2PNode,
  createSharedSecretSecurity,
  type PeerContext
} from '@arduano/p2prpc-core';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({
  ping: t.procedure.query(({ ctx }) => ({
    pong: true,
    principal: ctx.p2p.auth.principal.id
  }))
});

// Populate from trusted deployment/bootstrap configuration.
const approvedDirectRoutes = new Set(['203.0.113.10:4433']);
const approvedRelayOrigins = new Set(['https://relay.example']);
const node = await createP2PNode({
  router,
  protocol: { applicationId: 'com.example.app', contractVersion: '1' },
  security: createSharedSecretSecurity(process.env.P2PRPC_SECRET!, {
    authorize: () => true // narrow this in production
  }),
  iroh: {
    allowDirectAddress: (candidate) => approvedDirectRoutes.has(candidate),
    allowRelayUrl: (origin) => approvedRelayOrigins.has(origin)
  },
  createContext: (ctx) => ctx
});
```

Production root creation accepts only peer-bound security returned by `createSharedSecretSecurity` or `createOidcSessionSecurity`. Custom security/transports live under `@arduano/p2prpc-core/advanced`; injected endpoints and the deliberately insecure helper live under `@arduano/p2prpc-core/testing`. Structural custom file sources and destinations are accepted by root file APIs and become trusted application code: they must independently meet the documented stability, integrity, publication, cancellation, and cleanup contracts.

## Connect

```ts
const peer = await node.connect<typeof router>({
  locator: { kind: 'ticket', ticket }, // or dns / mdns
  expectedPeerId,
  expectedPrincipal: {
    subject: expectedPeerId,
    issuer: null,
    clientId: null,
    tenantId: null
  }
});

await peer.rpc.ping.query();
```

Locators provide reachability only. Expectations must come from a trusted bootstrap channel and are copied for reconnect. Signed-ticket direct routes and default-relay hints are rejected before dial unless the matching explicit Iroh egress callback allows them; custom relay configuration is an allowlist by construction.

## Files

```ts
// In a tRPC procedure, bound to that exact authenticated request:
const handle = ctx.p2p.files.share(await fileSource(serviceOwnedPath), {
  expiresAt: Date.now() + 60_000,
  maxDownloads: 1
});

// On the requesting peer:
const transfer = await peer.files.download(handle, fileDestination(localPath), {
  // Optional stable capability-redemption ID; reuse only for this operation.
  operationId
});
for await (const event of transfer.progress()) observe(event);
await transfer.result;
```

File bytes never use tRPC serialization. Optional manifest metadata requires a Standard Schema v1 schema in node configuration. A push has a manifest-level `SendFileOptions.transferId`; a pull has a distinct `DownloadFileOptions.operationId` for reconnect/retry reconciliation. Wire v4 uses a fresh receiver completion challenge and sender receipt before closing the control halves; acknowledged pushes leave only a bounded replay tombstone instead of occupying hard reconciliation capacity. The node-lifetime receiver ledger survives physical reconnection and same-process runtime revival, but not process restart. Its hard and tombstone state has independent per-peer, canonical-principal, and node-wide bounds; hard state rejects rather than evicts, while tombstones are evictable.

## Security model

The OIDC helper verifies configured issuer, audience, algorithms, HTTPS JWKS/static JWKS/single static public key, token type, `iat`/`exp`/maximum age, connection/operation scopes, and exact token-to-Iroh-key binding through `cnf.jkt` or an authoritative directory fallback only when `cnf` is absent. Its algorithm allow-list supports `RS256/384/512`, `PS256/384/512`, `ES256/384/512`, and Ed25519 `EdDSA`. It requires `p2prpc:connect`, then `p2prpc:rpc`, exact `p2prpc:rpc:<path>`, `p2prpc:file:push`, or `p2prpc:file:pull`; `p2prpc:*` is the library wildcard. Arbitrary JOSE key-resolver callbacks are rejected because they observe unverified token headers. Static and fetched key sets are limited to 64 keys/256 KiB and public importable material. Static JWKs require explicit compatible `alg`; fetched JWKs may omit it, but a present value must be compatible/allow-listed and every fetched key needs a bounded unique `kid`. Remote JWKS uses HTTPS only, a 5-second timeout, 30-second success/failure cooldown, and 10-minute cache. The shared-secret helper requires 32+ bytes and explicit authorization.

```ts
import {
  createOidcSessionSecurity,
  irohPeerIdJwkThumbprint
} from '@arduano/p2prpc-core';

const security = createOidcSessionSecurity({
  issuers: [{
    issuer: 'https://identity.example.com',
    audience: 'urn:example:p2prpc:production',
    algorithms: ['RS256'],
    jwksUri: 'https://identity.example.com/.well-known/jwks.json'
  }],
  getAccessToken: async ({ localPeerId, remotePeerId }) =>
    tokenManager.getAccessToken({
      destinationPeerId: remotePeerId,
      // The presenter, not the destination, is the cnf.jkt proof key.
      confirmationJkt: await irohPeerIdJwkThumbprint(localPeerId)
    })
});
```

Existing sessions are not reverified when JWKS changes. Cached removed keys can remain usable until refresh, and authenticated sessions remain valid until their own expiry; select token/session TTLs accordingly.

RPC headers are bounded, normalized, immutable caller assertions available at `ctx.p2p.request.headers`; they are not identity. Verified identity is `ctx.p2p.auth.principal`.

Full documentation and production constraints: <https://arduano.github.io/p2prpc/>.

MIT licensed. Report vulnerabilities through the repository security policy, not a public issue.
