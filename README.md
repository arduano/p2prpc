# p2prpc

[![CI](https://github.com/arduano/p2prpc/actions/workflows/ci.yml/badge.svg)](https://github.com/arduano/p2prpc/actions/workflows/ci.yml)
[![CodeQL](https://github.com/arduano/p2prpc/actions/workflows/codeql.yml/badge.svg)](https://github.com/arduano/p2prpc/actions/workflows/codeql.yml)
[![Docs](https://github.com/arduano/p2prpc/actions/workflows/pages.yml/badge.svg)](https://arduano.github.io/p2prpc/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.3-339933?logo=node.js&logoColor=white)](./packages/core/package.json)

Type-safe peer-to-peer RPC, subscriptions, and parallel resumable file transfer over one Iroh QUIC connection, with mandatory application authentication.

`@p2prpc/core` combines tRPC's router/type system with Iroh's encrypted Ed25519 transport identity. Every physical connection completes a bounded, mutual application handshake before any RPC or file stream is dispatched. RPC calls use independent bidirectional streams; files use a control stream plus bounded parallel data lanes, so interactive traffic can progress alongside bulk transfer.

Read the [published architecture wiki](https://arduano.github.io/p2prpc/) for the concise system model, or browse its [Markdown source](./docs/wiki/Home.md) in the repository.

> [!NOTE]
> p2prpc is pre-1.0. The `@p2prpc/core` package metadata is release-ready, but the package has not yet been published to npm. The install command below applies after the first registry release; contributors can use the workspace directly with `npm ci`.

## Requirements

- Node.js 20.3 or newer and an ES module application; CommonJS `require()` is not supported
- An `@momics/iroh-http-node` native target: glibc 2.34+ Linux x64/arm64, macOS x64/arm64, or Windows x64
- Matching application ID and contract version
- A `SessionSecurity` implementation on every node

Browser and React Native runtimes need separate transports and are not part of this release.

## Install

```bash
npm install @p2prpc/core @trpc/client @trpc/server
```

## Typed RPC and request metadata

The smallest secure setup uses a separately provisioned 256-bit application secret. OAuth/OIDC is described below.

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
  // Headers are bounded but caller-controlled. The principal is verified.
  // A group secret grants membership in this example's single tenant.
  if (ctx.request.headers['x-tenant-id'] !== 'tenant-a') {
    throw new TRPCError({ code: 'FORBIDDEN' });
  }
  return next();
});

const appRouter = t.router({
  hello: tenantProcedure
    .input(z.object({ name: z.string() }))
    .query(({ input, ctx }) => ({
      greeting: `Hello ${input.name}`,
      subject: ctx.auth.principal.subject,
      peerId: ctx.peer.id
    }))
});
export type AppRouter = typeof appRouter;

const node = await createP2PNode({
  router: appRouter,
  protocol: { applicationId: 'my-app', contractVersion: '1' },
  security: createSharedSecretSecurity(process.env.P2PRPC_SHARED_SECRET!),
  createContext: (requestContext) => requestContext
});

// Obtain the locator and expected identity through a trusted bootstrap channel.
// The ticket is not itself an authorization secret or target-selection policy.
const peer = await node.connect<AppRouter>({
  ticket: remoteTicket,
  expectedPeerId: remotePeerId,
  expectedPrincipal: {
    id: remotePeerId,
    subject: remotePeerId,
    issuer: null,
    clientId: null,
    tenantId: null
  }
});
const result = await peer.rpc.hello.query(
  { name: 'Ada' },
  { context: p2pRpcContext({ 'x-tenant-id': 'tenant-a', traceparent }) }
);
```

Header names are normalized to lowercase and the resulting record is frozen. The default limits are 64 fields, 64 bytes per name, 8 KiB per value, and 16 KiB total. C0/C1 controls, Unicode bidirectional/zero-width formatting controls, and duplicates are rejected. The reserved namespace includes `authorization`, `cookie`, `set-cookie`, `connection`, `forwarded`, `host`, `origin`, `proxy-*`, `x-forwarded-*`, `x-real-ip`, `p2prpc-*`, and `x-p2prpc-*`. Bearer credentials are sent only inside the encrypted handshake, never copied into request headers.

Metadata is still asserted by the caller. It is appropriate for trace IDs, locale, requested tenant, and similar routing hints, but it must not be treated as identity or proof of membership. tRPC middleware should compare it with `ctx.auth.principal` or other verified policy data. `getRequestHeaders` can supply per-peer defaults; per-call values supplied with `p2pRpcContext()` override those defaults after both sets are validated.

The library-owned `PeerContext` view passed into `createContext` is frozen, as are its authenticated session, principal, request, headers, and connection facade. If `createContext` returns a different application context, preserve that separation between verified identity and caller assertions rather than copying either into mutable or user-controlled fields.

Outbound `connect()` always requires the locator plus a separately trusted endpoint ID and exact application-principal matcher. `subject`, `issuer`, `clientId`, and `tenantId` are provider-neutral canonical identity fields; use `null` to require an optional field to be absent. `id` is an optional additional check of the authenticator's stable principal ID. Shared-secret principals use the endpoint ID for both `id` and `subject` and have no issuer, client, or tenant, as shown above. OIDC callers should instead provide the expected issuer/subject/client/tenant tuple. The target is validated and snapshotted before dialing, retained for reconnects, and cannot be weakened by later object mutation.

Node configuration is snapshotted at construction. In particular, the security methods and their original receiver are captured, and Iroh key and relay lists are defensively copied; mutating the original options object later cannot widen authorization. Application callback closures and any services they reference remain application-owned and must apply their own concurrency and lifecycle controls.

Each RPC opens its own stream. Calls are not automatically retried after disconnection because mutations may not be idempotent.

For a non-idempotent mutation, require a bounded `idempotency-key` metadata value and atomically store the result or operation state under the verified principal tuple, verified tenant, procedure path, and key. Return the recorded result for a duplicate. The key is replay-control input supplied by the caller, not identity or authorization evidence, and in-memory deduplication is insufficient when processes can restart.

`peer.close()` is terminal for that local `Peer` handle: it removes the runtime, aborts active RPC/file signals, and disables automatic reconnect. Reconnecting from that side requires an explicit `node.connect()` and returns a new handle; the remote endpoint can independently establish a later inbound runtime. Physical connection replacement, session expiry, and node shutdown likewise abort the signal exposed to tRPC procedures and middleware.

The default client I/O timeout is 30 seconds per stream operation, including each subscription response read. There is no protocol heartbeat frame, so a subscription which may otherwise be silent must yield an application heartbeat/data item within the idle window. Applications using `irohLink` directly may instead select a larger bounded `ioTimeoutMs`; the built-in `Peer` client currently uses the 30-second default.

## OAuth/OIDC deployment

The OIDC helper treats p2prpc as an OAuth resource server. Your application obtains and refreshes short-lived access tokens; p2prpc does not handle browser login, device flow, or refresh tokens.

```ts
import { createOidcSessionSecurity } from '@p2prpc/core';

const security = createOidcSessionSecurity({
  issuers: [{
    issuer: 'https://id.example.com',
    audience: 'urn:example:p2prpc',
    algorithms: ['RS256', 'ES256'],
    jwksUri: 'https://id.example.com/.well-known/jwks.json'
  }],
  getAccessToken: ({ remotePeerId }) => tokenManager.accessTokenFor(remotePeerId)
});
```

The required `expectedPeerId` is compared with the signed ticket before the native dial and with the connected transport identity before `getAccessToken` is called. The initiator must still present its access token before it can authenticate the remote *application* principal. `expectedPrincipal` is therefore checked immediately after mutual authentication and before the peer is installed or returned, but it cannot prevent disclosure to the already approved endpoint key. Obtain the ticket, expected peer ID, and expected principal through a trusted bootstrap channel; mint short-lived peer/audience-specific tokens; and use `preAuthorizePeer` for an organization-wide endpoint-key allow-list or inbound admission policy:

```ts
const approvedPeerIds = new Set(configuredPeerIds);

const node = await createP2PNode({
  // ...router, protocol, security, and createContext...
  preAuthorizePeer: ({ id }) => approvedPeerIds.has(id)
});
```

`preAuthorizePeer` runs before either side exchanges application credentials. For outbound connections it is cumulative with the required per-call expected peer; for inbound connections it remains the available endpoint-key admission gate. It is not a substitute for expected-principal matching, `SessionSecurity` authentication, or per-operation authorization.

Locator dialing uses only the ticket's signed direct/relay candidates; implicit native DNS and mDNS route discovery is disabled. For restricted egress, configure `iroh.allowDirectAddress` and explicit `iroh.relayUrls` with `iroh.allowRelayUrl`. A relay allow-policy cannot be combined with unknown default relays, because the policy must run before native networking begins.

With OIDC, compare the requested tenant to the verified claim instead: `ctx.request.headers['x-tenant-id'] === ctx.auth.principal.tenantId`. The header selects a tenant; it never proves membership in one.

Verification is strict: configured issuer, audience, algorithm allow-list, signature/JWKS, `iat`, `exp`, access-token `typ` (`at+jwt` by default), and the `p2prpc:connect` scope. Token age is limited to one hour by default; `maxTokenAge` can tighten that limit and cannot exceed 24 hours. By default, the token must contain an RFC 7800-style `cnf.jkt` equal to the JWK thumbprint of the remote Iroh Ed25519 key. This turns the transport's proof of key possession into token proof of possession without pretending the non-HTTP protocol is RFC 9449 DPoP.

Assign a distinct OAuth audience and connection scope to each application, environment, and trust domain. Reusing a broad audience and `p2prpc:connect` grant across unrelated services creates a confused-deputy path even when signatures and peer binding are valid.

Verified `client_id` or `azp` is retained as `principal.clientId`; if both claims are present they must agree. `principal.id` is a non-readable stable identifier of the form `oidc:<base64url SHA-256>`, derived with domain separation from the JSON tuple `[issuer, subject, clientId ?? null]`. Code should use the separately retained `issuer`, `subject`, and `clientId` fields when it needs those values.

If an issuer cannot mint `cnf`-bound tokens, configure `bindPrincipalToPeer` to consult an enterprise directory mapping the verified issuer/subject/client to allowed Iroh keys. This fallback runs only when no usable `cnf.jkt` is present; a non-empty mismatched thumbprint always fails. `peerBinding: 'optional'` or `'disabled'` is an explicit weaker bearer-token mode.

Default authorization scopes are:

- `p2prpc:connect`
- `p2prpc:rpc` or `p2prpc:rpc:<router.path>`
- `p2prpc:file:push`
- `p2prpc:file:pull`
- `p2prpc:*` for an administrative service identity

Pass `authorize` to the OIDC helper for tenant, role, path, mutation, metadata, or file-specific policy. It runs only after the mandatory connection and operation scope checks pass, so it may narrow access but cannot grant an operation for which the token lacks scope. JWT revocation is bounded by token/session lifetime; use short tokens or a custom introspection-backed `SessionSecurity` where immediate revocation is required.

`onSecurityEvent` emits credential-free structured records for installed/rejected/expired sessions and core RPC/file authorization decisions. Once policy evaluation starts, an exception or timeout produces a denied event with a generic reason; a stale-session rejection before evaluation starts does not. Audit callbacks are best-effort, in-process, and deliberately cannot backpressure or alter protocol state. Monitor callback/sink health and forward records to a durable external audit system.

The hashed OIDC principal ID is a breaking identity migration from earlier readable/delimiter-based IDs. Migrate ACLs, database keys, audit correlation, and cached grants keyed by the previous ID before upgrading. The underlying verified issuer, subject, and client ID do not change.

## Files

File bytes never pass through tRPC serialization. A tRPC procedure normally returns a short-lived capability handle; the client then opens the separate transfer protocol on the same authenticated session.

Push only after the receiver authorizes the session scope and selects a destination:

```ts
const receiver = await createP2PNode({
  router: appRouter,
  protocol: { applicationId: 'my-app', contractVersion: '1' },
  security,
  createContext: (context) => context,
  onIncomingFile(offer) {
    // principal/sessionId are trusted; signal follows this authenticated attempt.
    // The name is untrusted display text and never a destination path.
    if (offer.principal.tenantId !== 'tenant-a') return offer.reject();
    offer.accept(fileDestination('/quarantine/incoming.bin'));
  }
});

const transfer = await peer.files.sendFile(await fileSource('/data/video.mp4'));
transfer.onProgress(console.log);
await transfer.result;
```

Pull capabilities are peer-bound by default, stop accepting new or reconnecting operations after five minutes, permit one logical operation, and are stored only as domain-separated SHA-256 token hashes. The normal flow issues one from an already-authorized tRPC procedure and binds it to both the calling endpoint and its complete verified principal:

```ts
// On the receiver. Authorize an application document ID, then resolve it inside
// a trusted, service-owned source root; never accept a caller-supplied path.
const filesRouter = t.router({
  requestDownload: tenantProcedure
    .input(z.object({ documentId: z.string().uuid() }))
    .query(async ({ input, ctx }) => {
      const path = await documentStore.authorizedPath(ctx.auth.principal, input.documentId);
      return node.files.share(await fileSource(path), {
        allowedPeerIds: [ctx.peer.id],
        allowedPrincipals: [ctx.auth.principal],
        expiresAt: Math.min(Date.now() + 60_000, ctx.auth.expiresAt),
        maxDownloads: 1
      });
    })
});
// Mount this as `files` in the node's application router.
const appRouter = t.router({ files: filesRouter });

// On the caller. The handle is typed like any other tRPC result.
const handle = await peer.rpc.files.requestDownload.query({ documentId });
const transfer = await peer.files.download(
  handle,
  fileDestination('/downloads/archive.tar')
);
await transfer.result;
```

The secret capability travels in the authorized RPC response and then in transfer control setup. File contents do not: raw chunks are striped across separate QUIC data streams, so unrelated RPCs and subscriptions continue in parallel. Session credentials are used only by the mutual handshake and are never copied into RPC headers, capability records, or file lanes.

Setting `allowBearer: true` permits omission of the endpoint-ID restriction; it does not erase an explicitly supplied `allowedPeerIds` list or bypass session authentication, file-pull authorization, expiry, or download limits. Add `allowedPrincipals: [ctx.auth.principal]` to keep an exact issuer/subject/client/tenant restriction even when endpoint mobility requires a bearer capability. A capability is secondary file authorization, not session authentication.

Treat the handle token as a secret even when it is peer-bound: return it only from an authorized tRPC procedure, do not place it in RPC metadata, and redact it from logs and telemetry.

`maxDownloads` counts distinct logical operation IDs, not packet delivery attempts. Calling `node.files.revoke(handle)` removes the capability and immediately aborts its active reservations. Passive expiry rejects a later reservation/reconnect but is not an independent timer that kills active work at the exact expiry millisecond; use explicit revocation or a session/policy deadline for a hard cutoff. A disconnected operation can resume only with the same peer ID, complete canonical principal identity (ID, issuer, subject, OAuth client, and tenant), operation ID, and negotiated chunk-size/lane fingerprint, within a fixed 30-second lease and at most five reconnects by default. Every reconnect repeats session authentication and file authorization. Endpoint-key rotation requires a new explicit `node.connect()` and newly issued capabilities. `allowedPrincipals` is the preferred identity restriction; `allowedSubjects` compares only the raw verified `subject` and is safe as a global check only for a single issuer or an issuer-aware surrounding policy.

Files are split into bounded BLAKE3-checked chunks and striped over independently authenticated connection streams. The built-in `fileDestination()` also hashes the complete partial file against the manifest immediately before atomic publication. Manifests, names, metadata, missing ranges, lane counts, chunk counts, file sizes, active sessions, and queues are bounded before allocation. Validated manifests are frozen and metadata is exposed through detached snapshots; reconnects require metadata as well as every content field to remain equal. Control and data lanes are tied to the exact authenticated connection context and use receiver-issued attempt IDs and random lane tokens, so a replacement session, stale stream, or duplicate stream cannot attach by transfer ID alone. Session expiry, connection replacement, node shutdown, and active capability revocation abort affected work; a bounded reconnect creates a fresh authenticated and authorized attempt.

`fileSource()` rejects symlinks and detects inode/size/time changes around every read. Opens also compare the path and opened-file identities, preserving the leaf-symlink defense on platforms without `O_NOFOLLOW`. These checks establish file stability, not entitlement: applications must map an authorized opaque object ID to a path inside a trusted, service-owned source root. Never pass a remote RPC value directly to `fileSource()`, and do not rely on leaf checks when an untrusted local user controls a source parent directory. `fileDestination()` uses no-follow/exclusive private partial files, a destination lock, bounded verified resume state, full-file verification, and atomic no-replace publication when `overwrite` is false. Its default maximum chunk size is 4 MiB; when a node deliberately raises `maxFileChunkSize`, pass the same value as `fileDestination(path, { maxChunkSize })`. Resume state matches the digest, size, and chunk size and every saved chunk is re-hashed before reuse. It is content-bound rather than peer/principal/capability-bound, so authorization remains an independent requirement.

Custom `FileSource` and `FileDestination` implementations are trusted storage adapters. A custom source must return stable bytes for the lifetime of a manifest. A custom destination's `finalize()` must independently verify the complete staged content against `manifest.digest` immediately before publishing it; per-chunk transport checks alone do not replace that final check. It must also honor the abort/commit contract documented by the TypeScript interface. Prefer the built-in filesystem adapters unless another storage backend can provide equivalent guarantees.

Destination parent directories must be trusted and service-owned: leaf no-follow checks cannot protect against an attacker who can replace a parent path component. The exclusive `.p2prpc.lock` is removed during normal cleanup, but stale locks are not broken automatically. After a crash, an operator may remove one only after proving that no writer still owns the destination. Remote filenames are untrusted display text and are never interpreted as local paths.

## Security model

| Layer | Establishes | Does not establish |
|---|---|---|
| Signed locator ticket | Self-authenticated endpoint-key attestation over routes, protocol hint, and issue/expiry times | Enterprise ownership, confidentiality, or permission |
| Iroh QUIC identity | Encrypted channel and possession of the endpoint Ed25519 key | Application user/workload authorization |
| Session handshake | Mutual short-lived principal, exact app contract, nonces, session ID, expiry | Per-operation permission |
| Authorization policy | RPC path/type and file push/pull permission | Trust in caller metadata or file names |
| File capability | A bounded grant for one shared source | Authentication of an otherwise unknown peer |

The first accepted bidirectional stream must be session authentication, and RPC/file dispatch loops do not start before it completes. The handshake is bounded to 64 KiB and ten seconds, mutually checks the exact `p2prpc/2/<application>/<contract>` identity, derives a unique session ID from both peer IDs and 256-bit nonces, and closes at the shorter credential/session expiry. Every reconnect fetches fresh credentials and repeats authentication. A connection cannot replace another session with a different canonical principal ID, issuer, subject, OAuth client, or tenant.

Remote RPC responses omit stacks, tRPC formatter/custom data, and internal-error messages. Non-internal messages deliberately authored by application procedures are sanitized (including C0/C1 and Unicode bidirectional/zero-width formatting controls) and capped at 8 KiB before being sent; they must not contain secrets. The client performs the same sanitization and cap on an authenticated peer's error message.

The library includes `dangerouslyAllowInsecureSessions()` only for tests and isolated benchmarks. It is deliberately explicit; omitting `security` fails node creation.

See [SECURITY.md](./SECURITY.md) for the threat model, enterprise controls, residual risks, and audit notes.

## Development

```bash
npm ci
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run build
npm run test:minimum-runtime
npm run docs:build
npm audit --audit-level=low
```

Run the example with the same separately exchanged secret in two terminals:

```bash
P2PRPC_SHARED_SECRET='replace-with-at-least-32-random-bytes' npm start -w @p2prpc/cli-example -- serve ./downloads
P2PRPC_SHARED_SECRET='replace-with-at-least-32-random-bytes' npm start -w @p2prpc/cli-example -- connect '<expected-peer-id>' '<ticket>' ./large-file.bin
```

`npm run benchmark` runs 1,000 RPCs while transferring a 256 MiB file.

## Wire layout

| QUIC stream | Direction | Purpose |
|---|---:|---|
| Session authentication | bidirectional | Mandatory mutual credential handshake before application streams |
| RPC | bidirectional | One query, mutation, or subscription with bounded metadata |
| Transfer control | bidirectional | Authorization, offers, acceptance, missing ranges, completion |
| Transfer data | unidirectional | Attempt-bound indexed chunks across bounded parallel lanes |

Control envelopes use length-bounded MessagePack frames with configurable pre-decode item-count and nesting limits (`maxControlFrameItems` and `maxControlFrameDepth`). Only plain-data MessagePack is accepted: map keys must be unique UTF-8 strings, `__proto__` is rejected, and extension values are not part of the wire contract. tRPC values use SuperJSON inside that envelope. File bodies are raw bytes. `@momics/iroh-http-node` 0.6 does not expose custom native QUIC ALPN, stream priorities, configured stream-count limits, or configured receive-window limits through this adapter. Native flow control remains in charge; JavaScript admission limits, deadlines, and cleanup are defense in depth. A timed-out native stream open cannot be aborted directly, although a stream which resolves late is cleaned up. These limitations are tracked in the security notes.

## Community and license

See [CONTRIBUTING.md](./CONTRIBUTING.md) before proposing a change, use [SUPPORT.md](./SUPPORT.md) to choose the right public or private channel, and follow the [Code of Conduct](./CODE_OF_CONDUCT.md). p2prpc is available under the [MIT License](./LICENSE); runtime dependency licensing and the current Iroh packaging caveat are recorded in the [third-party notices](./packages/core/THIRD_PARTY_NOTICES.md).
