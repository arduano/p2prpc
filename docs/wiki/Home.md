# System model

p2prpc is a TypeScript library for typed tRPC calls and parallel file transfer over one authenticated Iroh QUIC connection. This wiki describes wire protocol v4 and is intentionally written for architecture and security review. The application credential handshake and on-disk resume state remain format v3; those version numbers are independent.

## Five-minute model

An Iroh endpoint has an Ed25519 **endpoint ID**. A locator—signed ticket, DNS/PKARR, or mDNS—only helps reach that endpoint. It never grants application access.

Before accepting an RPC or file stream, both endpoints complete a six-message application handshake:

```text
ClientHello       ->
                  <- ServerChallenge
ClientCredential  ->
                  <- ServerCredential
ClientFinished    ->
                  <- ServerFinished
```

The transcript commits protocol identity, roles, both endpoint IDs, both fresh 256-bit nonces, timestamps, both credentials, both grant expiries, and the derived session ID. The result is an immutable, expiring **authenticated session** containing a canonical application **principal**.

Every operation then passes explicit authorization. RPC metadata is available to tRPC middleware at `ctx.p2p.request.headers`, but remains an untrusted caller assertion. Identity comes only from `ctx.p2p.auth.principal`.

RPC and files do not share a serializer:

```text
authenticated QUIC connection
├── bidirectional stream per RPC
├── bidirectional control stream per file operation
└── bounded unidirectional file-data lanes
```

tRPC carries typed control values and capability handles. File bytes stay outside tRPC and use chunked, resumable streams with backpressure.

## Trust boundaries

| Value | Security meaning |
|---|---|
| Locator or discovered route | Untrusted reachability hint |
| Iroh endpoint ID | Transport proof of key possession; not application authorization |
| Expected endpoint and principal | Out-of-band trust asserted by the dialer |
| Session principal | Verified application identity |
| RPC headers | Bounded, normalized, immutable, but untrusted metadata |
| File manifest/name/metadata | Untrusted until exact validation; name is never a path |
| Share handle | Short-lived secondary capability, bound to an authenticated endpoint and full principal by the safe API |

## Production API boundary

The package root exposes peer-bound OIDC and shared-secret factories, `createP2PNode`, typed peers, RPC metadata helpers, and safe file APIs. It does not expose anonymous sessions, custom credential implementations, raw transports, or a directly constructible transfer.

- `@p2prpc/core/advanced` is an explicit trust boundary for custom security, transports, raw links, and registries.
- `@p2prpc/core/testing` contains the intentionally insecure session helper and injected-endpoint node factory.

Root `createP2PNode` rejects an unbranded custom security object at runtime as well as at the TypeScript boundary.

## OAuth in a non-HTTP protocol

p2prpc acts as an OAuth resource server. The application obtains and refreshes access tokens; the library presents and verifies them during the QUIC handshake. HTTP redirects, authorization-code exchange, and refresh tokens are deliberately out of scope.

OAuth still adds material value: issuer-managed short lifetimes, signed audience/scope grants, key rotation through configured JWKS, tenant/client identity, and centralized policy. A plain API key cannot provide those properties by itself. OAuth does not secure discovery or magically bind a bearer token to QUIC, so p2prpc additionally requires either exact `cnf.jkt` binding to the presenting Iroh key or an authoritative principal-to-peer directory decision. Token acquisition should compute the presenter binding with `irohPeerIdJwkThumbprint(localPeerId)`; `remotePeerId` is only the destination selector.

Verification accepts explicitly allow-listed RSA (`RS*`/`PS*`), NIST EC (`ES*`), or Ed25519 (`EdDSA`) algorithms. Static JWKs require explicit compatible `alg`; fetched keys may omit it but all need unique bounded `kid`. The exact scopes are `p2prpc:connect`, `p2prpc:rpc`, `p2prpc:rpc:<exact-path>`, `p2prpc:file:push`, `p2prpc:file:pull`, and the library wildcard `p2prpc:*`. See [Security Model](Security-Model.md) for key and JWKS lifecycle bounds.

## Availability boundary

Global, per-endpoint, and per-principal quotas bound handshakes, streams, direction-separated file transfers, buffers, callbacks, and queues. Each scope independently reserves an outbound file control, inbound file control, outbound data lane, and inbound data lane; general work and the other three classes cannot consume that class's last slot. Configuration therefore admits at least five streams: one general/RPC stream plus those four file progress paths. File progress is conflated per observer. Each resource has one owner and exact-once release; scheduler shutdown rejects queued/new work without erasing active ownership.

The pinned Iroh wrapper supports default, custom, and disabled relay policies plus signed tickets, DNS/PKARR, and mDNS with the restrictions in [Production Validation](Production-Validation.md). Signed-ticket direct/default-relay routes require explicit egress policy before dial; custom relays use configured membership. Relay-disabled retains direct LAN networking through a fail-closed exact-version compatibility seam. DNS plus custom filtering is rejected because resolved DNS routes are not exposed for inspection.

## Responsibility split

p2prpc owns authentication framing, endpoint/principal binding, operation authorization hooks, bounded metadata, lifecycle accounting, transfer integrity, and atomic local file publication. Applications still own token acquisition, bootstrap trust, business authorization, tRPC input schemas, durable mutation idempotency, storage ACLs, malware scanning, audit retention, and operational monitoring.
