# Security policy

## Reporting

Do not open a public issue with secrets or exploit details. Use [GitHub private vulnerability reporting](https://github.com/arduano/p2prpc/security/advisories/new) and include affected commit/version, impact, reproduction, and any proposed mitigation. Rotate credentials, capability tokens, or endpoint keys included in a report.

Before the first registry release, only `main` is supported. After releases begin, the current minor line and `main` are intended to receive fixes.

## Security target

p2prpc treats the network, locators, DNS/PKARR and mDNS results, remote endpoint, request metadata/input, file manifest/metadata/content, and capability presenter as hostile.

An Iroh endpoint ID proves possession of a transport key. A signed ticket proves which endpoint signed route hints. Neither authorizes application work. The current QUIC application protocol/ALPN is v4; the credential-handshake format remains v3. p2prpc dispatches RPC or file streams only after:

1. the connected endpoint matches an independently trusted expectation for outbound calls;
2. optional endpoint-key admission succeeds;
3. both peers complete the exact six-message protocol-v3 application handshake;
4. the authenticated principal matches the expected principal for outbound calls;
5. the current session and operation pass explicit authorization.

The concise, audit-oriented model is in the [security wiki](./docs/wiki/Security-Model.md) and [audit guide](./docs/wiki/Audit-Guide.md).

## Implemented controls

### Identity and authorization

- Production root creation accepts only branded peer-bound OIDC or shared-secret factories; no anonymous default exists.
- The v3 transcript commits protocol, roles, both endpoint IDs, fresh 256-bit nonces, timestamps, credentials, grant expiries, transcript hashes, and session ID.
- Unknown handshake fields, wrong roles/IDs/protocol, stale timestamps, excessive credentials, transcript mismatch, trailing bytes, and incomplete finish fail closed.
- The responder withholds its credential until the initiator authenticates.
- Physical reconnect repeats endpoint admission, authentication, exact principal comparison, and operation authorization. A runtime cannot swap canonical principal; a same-principal inbound connection may revive a retained disconnected outbound runtime.
- Every RPC path/type, file push, and capability pull receives a current-session authorization decision.
- Connection replacement, expiry, peer close, and node close abort session-bound signals.

### OIDC/OAuth

- Exact configured issuer and audience, an explicit allow-list drawn from `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, and Ed25519 `EdDSA`, a configured HTTPS JWKS/static JWKS/single static public key, signature, `iat`, `exp`, access-token `typ`, maximum age, and bounded clock tolerance. The production OIDC factory rejects HTTP JWKS endpoints and arbitrary JOSE key-resolver callbacks.
- Required `p2prpc:connect`; operations require `p2prpc:rpc`, exact `p2prpc:rpc:<path>`, `p2prpc:file:push`, or `p2prpc:file:pull`, while `p2prpc:*` satisfies every library scope. Custom policy can narrow but cannot restore a missing scope.
- Canonical immutable issuer/subject/client/tenant principal and deeply bounded claims/scopes.
- Exact `cnf.jkt` binding to the authenticated remote Iroh Ed25519 key, or an authoritative directory callback only when `cnf` is absent. Malformed/mismatched present `cnf` never falls back.
- Token-controlled `jku` and `x5u` are ignored; only p2prpc constructs local or remote JWKS resolvers. Static and fetched JWKS are capped at 64 keys/256 KiB and accept only importable public material compatible with the issuer allow-list. Static JWKs require explicit `alg`; fetched JWKs may omit it, but a present `alg` must be compatible/allow-listed and every fetched key requires a bounded unique `kid`. Mutable JWKs and descriptor-safe configuration are snapshotted at construction.
- Remote JWKS fetches reject redirects, have a 5-second timeout, 30-second success/failure cooldown, and 10-minute cache lifetime. A removed key can remain accepted until cache refresh, and established sessions are not reverified; revocation latency is therefore bounded by cache, token, and session lifetimes unless deployment policy adds an online decision.

p2prpc is a resource server, not an authorization server: applications own browser/workload login, token acquisition/refresh, and storage. OAuth remains valuable without HTTP because audience, scopes, short grants, identity, and key rotation are transport-independent.

### RPC and metadata

- Request frames and remote error shapes use exact schemas; response IDs/paths/codes must be internally consistent.
- Header names/values/count/aggregate bytes are bounded, normalized, frozen, and stripped of credential/proxy/library-reserved names and unsafe display controls.
- `ctx.p2p` separates verified identity from untrusted caller headers and cannot be replaced by application context.
- MessagePack is byte/item/depth bounded and accepts one project-canonical encoding: duplicate/prototype keys, overlong varints, alternate numeric/container encodings, extensions, accessors, symbols, and exotic prototypes are rejected. RPC SuperJSON uses a private built-in-only, acyclic codec; global custom transformers, classes, symbols, aliases, and cycles are not wire types. Outbound values are preflighted before serialization; inbound annotation paths are canonical, non-overlapping, target-checked, and allocation-bounded before value construction.
- Internal tRPC errors, stacks, formatter extensions, and unsanitized peer text are not exposed.
- RPC is never transparently retried; after dispatch uncertainty is `OUTCOME_UNKNOWN`.

### Files and capabilities

- Root `ctx.p2p.files.share()` and `peer.files.share()` automatically bind a capability to the current endpoint and complete principal; arbitrary/bearer policy is advanced-only. A captured request facade rejects after its exact session is replaced or expires.
- Capability and logical-operation IDs are random; registries store domain-separated hashes and bounded indexed records.
- Expiry, logical-download count, atomic reservation, active revocation, reconnect lease/attempt limit, endpoint/principal/fingerprint matching, and completion reconciliation are enforced.
- File control/data lanes are bound to the exact authenticated connection, attempt, and receiver-issued lane secret.
- Pull retry authority is private to the exact current attempt and is granted only after typed current-transport loss, stream drain, and prepared-source closure. Callback-visible errors, stale abort reasons, plain `DISCONNECTED` errors, and untyped connection aborts cannot authorize reconnect.
- File wire v4 commits use a fresh receiver receipt challenge. The sender keeps its send half open, echoes that token only after seeing durable success, and then sends FIN; a pre-sent or mismatched receipt cannot retire correctness-critical push state.
- Active and acknowledgement-ambiguous push records occupy a hard store bounded independently per peer, per canonical principal across endpoint keys, and node-wide; capacity exhaustion rejects admission and never evicts correctness-critical state. Acknowledged/rejected outcomes occupy a separate replay-tombstone store with evictable bounds at the same three scopes. Acknowledged throughput therefore does not exhaust hard reconciliation capacity or create an unbounded node-wide peer map.
- Sources use no-follow identity checks and retain one prepared descriptor across hashing and send.
- Destinations use no-follow private staging/lock/resume files, bounded binary v3 resume state, chunk and complete BLAKE3 verification, and atomic durable publication.
- Remote names are display values only. Applications choose trusted destination paths.
- Optional metadata is rejected without a configured Standard Schema v1 validator; plain data is accessor/prototype checked and copied before packing, and validated output is snapshotted. Binary metadata is defensively copied again on every public manifest access.

### Availability and lifecycle

- Global, endpoint, and principal quotas cover handshakes, streams, direction-separated file transfers, library-controlled buffers, callbacks, and fair bounded queues.
- Each quota scope independently reserves outbound/inbound file-control and outbound/inbound file-data progress. Stream limits admit those four classes plus one general/RPC stream; buffer limits admit three control frames plus both data buffers.
- Requests too large for any applicable ceiling reject immediately rather than queue forever.
- Handshakes also use global/per-peer token buckets.
- Streams, prepared sources, destinations, reservations, callbacks, and tasks have explicit owners and exact terminal cleanup. Timeout does not erase ownership of an underlying promise that is still running.
- Shutdown is bounded by `shutdownTimeoutMs`; a non-cooperative owner makes `close()` reject with `TIMEOUT` while accounting remains active and transport teardown still proceeds.
- Slow file progress consumers are independently conflated and cannot backpressure a transfer.
- File receive timeouts measure lack of progress rather than total duration; lane/chunk/64 KiB segment/write/FIN progress refreshes the watchdog while each stalled operation remains bounded.
- Failed native stream cleanup quarantines/closes the physical connection.
- Initial install, replacement, duplicate arbitration, runtime revival, and reconnect share one final admission-success gate after synchronous callbacks. Public promise continuations recheck it after their last `await`, and queued `onPeer` delivery is conditional on the exact selection remaining current. A peer is returned only while its node, registry slot, live-map entry, epoch, and session remain current; callback-triggered closure rejects acquisition instead of returning a stale handle.
- Receiver reconciliation expiry uses a deadline index and removes only due records, rather than scanning all retained peer/principal state on each operation. Node close first rejects new ledger admission; it clears retained state only after all ledger-owning work settles, even when the public close deadline expires first.

## Deployment requirements

- Store persistent Iroh secret keys in a managed keystore; bootstrap endpoint and exact principal expectations through an authenticated channel independent of discovery.
- Use distinct OAuth audiences/scopes per application, environment, and trust domain. Prefer short access-token/session lifetimes; use introspection/directory policy when urgent revocation is required.
- Keep peer proof-of-possession binding mandatory. Never use ID or refresh tokens as access tokens.
- Treat request headers as assertions. Compare a requested tenant with verified principal claims or authoritative policy.
- Use durable, atomic application idempotency for mutations, keyed by verified principal/tenant, procedure, and a bounded caller key.
- Resolve authorized object IDs inside service-owned source roots. Never pass an untrusted path to `fileSource()` or derive a destination from `manifest.name`.
- Quarantine received files and apply malware, DLP, type, retention, and storage authorization policy. BLAKE3 proves consistency, not safety.
- Treat capability tokens as secrets; never put them in headers, logs, traces, or durable audit records.
- Export `onSecurityEvent` to a monitored durable sink. The in-process callback is intentionally best effort.
- Bound application procedures, schemas, databases, custom callbacks, disk use, and tenant workloads above library limits. Cooperate promptly with supplied `AbortSignal`s.
- Review any import from `@arduano/p2prpc-core/advanced` as part of the trusted computing base. Never deploy `@arduano/p2prpc-core/testing`.

## Discovery and native boundary

- Custom relays are canonical HTTPS origins and remote hints must remain in the configured set. Egress callback exceptions deny.
- Signed-ticket direct candidates require `allowDirectAddress`; default-relay ticket hints require `allowRelayUrl`. Omission rejects rather than allows remote pre-authentication egress. These hooks inspect canonical untrusted remote candidates, not local default-relay selection or configured custom origins.
- With pinned `@momics/iroh-http-node` 0.6.0, DNS-resolved routes cannot be inspected before dial, so DNS plus custom relay or candidate filters is rejected.
- Relay-disabled mode removes relay use without disabling UDP networking. This requires an exact-version compatibility seam for node 0.6.0/shared 0.6.1; it targets only the endpoint's exact options object, restores the original export before yielding, and refuses an unexpected version, module graph, descriptor, or call path.
- Relay-less ticket/mDNS routes require direct reachability and explicit deployment validation; they cannot traverse NATs that require a relay.
- mDNS defaults to private/link-local/loopback direct candidates and requires explicit policy for default-network relay hints.
- Native flow control and some QUIC settings are wrapper-managed; the adapter cannot promise cancellation of an already-started native stream open. Late streams are cleaned when delivered and native handle return-to-baseline is a release gate.
- The exact-pinned Iroh packages require narrow relay-normalization and writer-cleanup compatibility seams. Dependency provenance, platform targets, licenses, SBOM, and native lifecycle evidence are part of release review.
- Production tRPC client/server versions are exact-pinned to the pair exercised by the wire, type-resolution, and package gates.

## Residual risks

- During outbound mutual bootstrap, a credential is disclosed to the independently approved endpoint key before the remote application principal can be verified. Narrow peer-bound tokens, expected endpoint provisioning, audience separation, and `preAuthorizePeer` reduce this exposure.
- JWT revocation is bounded by token/session lifetime unless deployments add introspection or authoritative online policy.
- JavaScript cancellation cannot kill arbitrary application code or undo a committed mutation. A callback that ignores abort can delay structured shutdown and retain admission ownership.
- RPC delivery is not exactly once. `OUTCOME_UNKNOWN` requires durable reconciliation/idempotency.
- The node-scoped receiver ledger survives physical connection replacement and same-process runtime revival. Its push reconciliation and acknowledged/rejected replay tombstones remain process-local and time/bound limited: process loss, TTL expiry, or tombstone eviction ends that protection, so durable application state remains authoritative.
- A custom file destination is trusted to perform complete verification immediately before atomic commit; prefer the built-in destination.
- Leaf no-follow checks cannot protect a parent directory controlled by a hostile local user.
- Security/audit callbacks can lose events on sink or process failure.
- Iroh/native implementations remain a dependency trust boundary and must pass the exact-commit external topology and native-handle gates.

## Release status

Public CI and package gates establish a releasable pre-1.0 artifact, not formal production approval. The stronger qualification additionally exercises ticket/default, ticket/custom, ticket/disabled, DNS/default, mDNS/default, mDNS/custom, and mDNS/disabled two-host cases; a 100-peer mixed workload; and 5,000 pushes plus 5,000 pulls over one authenticated physical connection with stream/task/share/reconciliation/memory/native-handle return-to-baseline. No qualifying external evidence is claimed until those artifacts exist. See [Production Validation](./docs/wiki/Production-Validation.md).
