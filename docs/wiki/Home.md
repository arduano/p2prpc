# p2prpc architecture wiki

This wiki is the shortest complete model of p2prpc for architecture and security reviewers. It describes protocol v2 as implemented in `@p2prpc/core`.

## System in one sentence

p2prpc runs typed tRPC calls and a separate resumable file protocol over one mutually authenticated Iroh QUIC connection, using independent streams so RPC and bulk data can progress concurrently.

```text
application router / typed tRPC client
                 │
              P2PNode
                 │  mandatory mutual application session
      ┌──────────┼────────────────────┐
      │          │                    │
  RPC stream  file control stream  file data lanes
   (bi, one      (bi, one per       (uni, bounded N
   per call)      attempt)           per attempt)
      └──────────┴────────────────────┘
                 │
          encrypted Iroh QUIC
```

File capability handles may be returned by tRPC, but file bytes never enter tRPC or SuperJSON.

## Non-negotiable invariants

1. A ticket or address alone cannot select an outbound target: callers must independently supply the exact expected Iroh peer ID and application-principal tuple, and all three are bound before the peer is exposed.
2. No RPC or file stream is dispatched until both endpoints complete the application handshake.
3. Every RPC, file push, and file pull is authorized again before dispatch or capability lookup.
4. `ctx.auth.principal` is verified identity; `ctx.request.headers`, RPC input, filenames, manifests, metadata, and file content are caller-controlled.
5. File data lanes are valid only for one authenticated physical connection and one receiver-created transfer attempt.

These are production invariants. The explicitly named `dangerouslyAllowInsecureSessions()` test/development escape hatch intentionally provides no real application authentication and must be prohibited in deployed configurations.

## The eight concepts

| Concept | Meaning |
|---|---|
| Locator ticket | Signed, expiring route description. Bootstrap data, not a bearer grant; it may expose route topology and should come through a trusted channel. |
| Outbound target | A snapshotted locator plus independently trusted expected endpoint ID and exact principal matcher; all are rechecked on reconnect. |
| Endpoint ID | Iroh Ed25519 public-key identity proved by the encrypted transport. |
| Principal | Verified application identity derived from OAuth/OIDC or another `SessionSecurity`. |
| Session | Short-lived binding of both endpoint IDs, fresh nonces, protocol contract, and principals to one physical connection. |
| RPC metadata | Bounded, normalized headers-like caller assertions exposed to tRPC middleware. |
| File capability | Opaque secret granting bounded access to one local `FileSource`; it is secondary to session and operation authorization. |
| Transfer attempt | One control exchange plus bounded parallel data lanes, tied to the exact connection and fresh lane credentials. |

## Read this wiki

- [Architecture](Architecture.md): components, boundaries, and stream layout.
- [Data model](Data-Model.md): identities, objects, ownership, and data classification.
- [Lifecycles](Lifecycles.md): node, session, reconnect, RPC, and cancellation state changes.
- [Security model](Security-Model.md): threat model, OAuth/OIDC compromise, and authorization layers.
- [File transfers](File-Transfers.md): capability pull, push, lanes, integrity, resume, and publication.
- [Audit guide](Audit-Guide.md): source map, control evidence, deployment checklist, and non-guarantees.

The repository [security policy](../../SECURITY.md) is the detailed threat model and residual-risk register. Source and tests remain authoritative if documentation and behavior ever diverge.

## Scope

This release targets TypeScript on Node.js and p2prpc protocol v2 over Iroh. It is not HTTP, does not implement browser login or OAuth token acquisition, and does not make tRPC types into an authorization boundary. Applications still own business policy, input schemas, storage authorization, quotas, idempotency, audit retention, and content scanning.
