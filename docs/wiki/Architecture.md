# Architecture

[Home](Home.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md) · [Audit guide](Audit-Guide.md)

## Component model

```text
┌──────────────────────── application boundary ────────────────────────┐
│ tRPC router + middleware             typed remote tRPC proxy          │
│ storage authorization                FileSource / FileDestination     │
│ business policy                      audit and quota services         │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
┌──────────────────────── p2prpc core ─────────────────────────────────┐
│ P2PNode                                                              │
│ ├─ outbound target: locator + expected endpoint + principal          │
│ ├─ peer runtimes: connection + authenticated session                 │
│ ├─ RPC link/server: framing, metadata, dispatch, cancellation        │
│ ├─ transfer managers: control, lanes, retries, integrity             │
│ ├─ share registry: hashed capabilities and operation state           │
│ └─ SessionSecurity: credentials, authentication, authorization       │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
┌────────────────────── transport and network ────────────────────────┐
│ signed locator + independent target expectations                    │
│        → Iroh endpoint → encrypted multiplexed QUIC                 │
└─────────────────────────────────────────────────────────────────────┘
```

`P2PNode` is symmetrical: every node can accept connections, initiate connections, expose a router, invoke a remote router, and send or receive files. “Client” and “server” describe one QUIC connection or stream, not a permanent node role.

## Stream layout

| Stream | Direction | Multiplicity | Purpose |
|---|---|---:|---|
| Session authentication | Bidirectional | Exactly one before activation | Mutual credentials, challenges, session agreement. |
| RPC | Bidirectional | One per query, mutation, or subscription | Request metadata/input, results, error, completion, cancellation. |
| Transfer control | Bidirectional | One per transfer attempt | Authorization setup, manifest, resume ranges, attempt credentials, completion. |
| Transfer data | Unidirectional | Bounded parallel lanes | Indexed chunks and per-chunk digests. |

Streams share QUIC encryption, congestion control, and connection flow control but avoid stream-level head-of-line blocking. The current native adapter does not expose effective stream priorities, so `setPriority()` is only an architectural hint.

## Protocol layers

| Layer | Establishes | Deliberately does not establish |
|---|---|---|
| Signed ticket | Self-authenticated attestation by the named endpoint key over its ID, routes, protocol hint, and issue/expiry times | Enterprise ownership, confidentiality, or permission |
| Outbound target expectations | Exact endpoint and application-principal tuple the caller intended, sourced independently of the locator | Proof that the endpoint or principal is authentic; later transport and handshake checks provide that proof |
| Iroh transport | Confidential channel and possession of the endpoint Ed25519 key | OAuth identity or business authorization |
| Application handshake | Mutual principals, transcript-bound session ID, contract match, and session expiry | Permission for an individual operation |
| Operation policy | RPC path/type or file push/pull permission | Trust in inputs, metadata, paths, names, or content |
| File capability | A bounded grant to one local source | Authentication of an unknown endpoint or principal |

## Type safety and runtime trust

tRPC supplies compile-time procedure paths and input/output inference. At runtime:

- `connect<RemoteRouter>({ ticket, expectedPeerId, expectedPrincipal })` enforces the target fields at runtime, but the `RemoteRouter` generic itself remains a caller-side TypeScript assertion; it does not negotiate or verify the remote router schema.
- `contractVersion` is an application-managed compatibility label, not schema negotiation. Peers only compare the configured string.
- MessagePack envelopes are size-, item-, and depth-bounded before decode.
- RPC values use SuperJSON inside the validated envelope.
- Application input parsers such as Zod remain responsible for RPC input validation.
- TypeScript types disappear on the wire and never prove identity or authorization.

## Protocol identity

Nodes must match `p2prpc/2/<applicationId>/<contractVersion>`. The value is carried in the signed ticket and checked again in the authenticated transcript. This is application-contract isolation even though the current Iroh adapter does not expose a custom native QUIC ALPN.

## Important ownership boundaries

- p2prpc owns framing, session continuity, bounded metadata, core authorization calls, capability enforcement, transfer integrity, and cleanup ordering.
- tRPC owns router dispatch and input/output typing.
- Iroh owns transport encryption and endpoint-key possession.
- The application owns identity issuance, policy semantics, storage path selection, local adapter safety, rate limits, durable audit, idempotency, and content trust.
