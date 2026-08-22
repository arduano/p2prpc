# File transfers

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Audit guide](Audit-Guide.md)

## Control plane versus data plane

tRPC is the recommended typed application authorization and capability-issuance plane: it answers questions such as “may this principal download document 42?” and returns a typed `SharedFileHandle`.

The file protocol has its own QUIC control stream: it presents that handle, obtains operation authorization, and negotiates the attempt. It then stripes raw chunks across independent data streams. Neither file control messages nor bytes are serialized through tRPC, so unrelated RPC/subscription streams can continue concurrently.

```text
tRPC: requestDownload({ documentId }) ──> SharedFileHandle
                                                │
file control: Pull(handle, options) ─────────────┘
file lanes:   chunk 0, 4, 8 ...
              chunk 1, 5, 9 ...       in parallel
              chunk 2, 6, 10 ...
              chunk 3, 7, 11 ...
```

## Capability pull

1. An authorized tRPC procedure maps an opaque application object ID to a service-owned `FileSource`.
2. It creates a short-lived capability bound to `ctx.peer.id` and preferably `ctx.auth.principal`.
3. The caller receives the typed handle and calls `peer.files.download(handle, destination)`.
4. The source peer authorizes `file.pull` using the capability hash, then atomically reserves the matching capability operation.
5. The source creates/offers a manifest. The destination reports already verified chunks and creates fresh attempt credentials.
6. Missing bytes move over bounded lanes. The destination verifies, publishes, and acknowledges completion.

Capability tokens are 256-bit opaque secrets; the registry stores only a domain-separated SHA-256 hash. By default a share must name allowed endpoint IDs, expires after five minutes, and permits one logical download. `allowBearer: true` deliberately permits omitting endpoint binding; it never removes session or file authorization. Principal binding is recommended but must be configured explicitly.

Use `allowedPrincipals` for principal binding. `allowedSubjects` is deprecated because a subject is only unique within its issuer.

Recommended policy binds both dimensions:

```ts
node.files.share(source, {
  allowedPeerIds: [ctx.peer.id],
  allowedPrincipals: [ctx.auth.principal],
  expiresAt: Math.min(Date.now() + 60_000, ctx.auth.expiresAt),
  maxDownloads: 1
});
```

Do not log the handle or place it in RPC metadata.

## Push

`peer.files.sendFile(source)` sends a manifest on a control stream. The receiver validates it, authorizes `file.push`, and invokes `onIncomingFile` with the verified principal/session and an abort signal. The handler must choose a local destination from server policy. The remote filename is display data and is never a path.

Push has no capability because the receiver makes the admission and destination decision directly. Session and per-operation authorization are still mandatory.

## Attempt and lane binding

The receiver returns:

- `transferId`: stable logical content-transfer identifier; not secret.
- `attemptId`: fresh per-attempt identifier.
- `laneToken`: fresh 256-bit secret shared only on the authenticated control stream.
- missing chunk ranges and maximum lane count.

Every data lane must match the exact in-memory authenticated connection context, all three identifiers, an unused lane number, and the announced chunk budget. A stale stream from a replaced connection cannot attach even if it knows a transfer ID or old lane token.

A lane is not independently OIDC-authenticated. It inherits the exact physical connection that completed mutual application authentication, then proves attempt membership with the receiver-issued lane token and identifiers.

## Integrity and publication

The source first reads the full file to create a BLAKE3 manifest, then reads chunks for transfer. Each chunk carries its own BLAKE3 digest. The receiver checks chunk geometry and digest before writing; the built-in destination re-reads the complete staged file and compares the manifest digest immediately before atomic publication.

The sender reports success only after the receiver has finalized and acknowledged the same attempt. Digests prove transfer consistency, not authorship, authorization, content type, or malware safety.

## Built-in filesystem adapters

`fileSource()` rejects leaf symlinks and detects inode, size, and timestamp changes around reads. The application must still resolve an authorized object ID inside a service-owned source root; never pass a remote path directly.

`fileDestination()` uses:

- a private exclusive `.p2prpc.part` staging file;
- bounded `.p2prpc.state.json` verified resume state;
- an exclusive `.p2prpc.lock` with no automatic stale-lock breaking;
- no-follow and identity checks;
- full-file digest verification;
- staged-file sync by default, best-effort parent-directory sync where supported, and atomic publication.

Parent directories must be service-owned. Leaf checks cannot defeat a local attacker who can replace a parent path component.

Custom `FileSource` and `FileDestination` objects are trusted storage adapters. They must cooperate with abort, keep source bytes stable, independently verify final staged content, and publish atomically.

## Resume, retry, expiry, and revocation

- Transport disconnects retry with backoff up to five times; other failures are terminal.
- Pull retry keeps one operation ID and must match the original endpoint, full principal binding, and chunk/lane fingerprint.
- The reconnect lease is fixed when disconnection first occurs and is 30 seconds by default.
- Capability expiry prevents new or reconnecting reservations; it is not an exact timer for already active work.
- `node.files.revoke(handle)` removes the capability and immediately aborts active reservations.
- Filesystem resume state, including for push, matches whole-file digest, size, and chunk size, then re-hashes every recorded chunk. It is not bound to name, metadata, transfer ID, peer, principal, session, or capability. Every new attempt still requires session authentication, operation authorization, and receiver admission; pull reconnect adds its peer, principal, capability-operation, and fingerprint constraints separately.
