# Audit guide

This is the shortest useful review order for p2prpc wire/ALPN v4. The credential-handshake and file resume formats independently remain v3.

## 1. Establish the deployed boundary

Record the exact package tarball/hash, Node/npm/native targets, Iroh wrapper version, application protocol identity, enabled locators, relay configuration, limits, and whether `/advanced` or `/testing` is present in the production graph. Any custom security, transport, source, destination, schema, or policy callback joins the trusted computing base.

Verify production imports only from the root unless an exception is documented. Root node creation must use a branded peer-bound security factory. Confirm the immutable packed artifact—not a rebuild—is what the publish job and deployment consume.

## 2. Trace trust establishment

For one outbound connection, identify the trusted source of:

- locator;
- expected Iroh endpoint ID;
- expected issuer/subject/client/tenant;
- token audience/scope and peer binding.

Confirm discovery never supplies the expectations. Trace endpoint comparison and `preAuthorizePeer` before credential disclosure, then all six exact v3 frames, transcript construction, expiry cap, expected-principal comparison, and runtime installation. Repeat from the inbound side, where no outbound expectation exists. Verify a same-principal inbound connection can revive a retained disconnected outbound runtime, while a different principal fails and a purely inbound runtime remains non-reconnectable.

Trace initial install, replacement, retained incumbent, duplicate arbitration, and reconnect into the same final admission-success gate. After every synchronous security event, abort listener, expiry action, and transport-close callback, require the node open, runtime slot and live-map entry still owned, exact epoch current, and session unexpired. Verify public promise continuations recheck after their last `await` and queued `onPeer` delivery rechecks its exact captured selection. Deterministically close the node from `session.authenticated`, queue closure before public resolution, close the incumbent while retiring a duplicate, and repeat during outbound reconnect; each acquisition must reject `DISCONNECTED`, return or notify no stale peer, and emit no false authentication rejection.

Code anchors: `transport/iroh.ts`, `security/handshake.ts`, `security/oidc.ts`, `security/shared-secret.ts`, `node.ts`.

## 3. Trace one RPC

Follow stream admission, kind parsing, exact frame validation, header normalization, operation authorization, frozen `ctx.p2p`, tRPC runtime input parsing, procedure execution, validated response/error framing, cancellation, and both-half cleanup.

Check that middleware treats headers as assertions and identity as `ctx.p2p.auth.principal`. Verify mutations use durable idempotency and callers handle `OUTCOME_UNKNOWN`. Ensure long procedures/subscriptions cooperate with `AbortSignal`; there is no hidden response heartbeat timeout.

Code anchors: `runtime/managed-connection.ts`, `rpc/headers.ts`, `rpc/server.ts`, `rpc/link.ts`, `protocol.ts`.

## 4. Trace push and pull files

For push, trace one prepared source descriptor from stat checks through hash/send/close, then exact offer validation, metadata schema, authorization, destination choice, lane ownership, complete digest, and atomic publication. Verify a custom destination checks its finalize signal immediately before publication and calls `markCommitted()` immediately afterward, before fallible cleanup; returning without the signal must fail closed. At the terminal exchange, verify sender `Complete` leaves its half open; receiver publication precedes `Complete` with a fresh 256-bit challenge; sender echoes that exact token in `Receipt` before FIN; receiver validates receipt and FIN before its FIN. A pre-sent receipt must not work. No path after publication may abort/reject the destination or change receiver success, and no path after the sender validates receiver completion may return uncertainty or retry.

For receiver push reconciliation, distinguish hard `active`/acknowledgement-ambiguous `committed` records from evictable `acknowledged`/`rejected` replay tombstones. Verify the ledger is node-scoped across physical replacement and same-process runtime revival, with stable operation-handle identity, principal/manifest fingerprint checks, and authorization on every offer. Independently saturate per-peer, canonical-principal-across-endpoint, and node-wide hard quotas; admission must reject without evicting active/ambiguous state. Saturate the three tombstone quotas and verify oldest-applicable eviction without consuming hard capacity. Confirm deadline-indexed expiry does work proportional to due entries rather than retained peers, and that shutdown stops admission before clearing only after ledger-owning work settles. Treat TTL, tombstone eviction, and process loss—not ordinary physical reconnect—as ends of replay protection; confirm the application handles crash-boundary `OUTCOME_UNKNOWN`.

For pull, start at root `ctx.p2p.files.share()`. Verify exact-session invalidation, automatic current-endpoint/full-principal binding, hashed token/operation indexes, expiry/download budget, atomic reservation, reconnect matching, revocation, process-local completion reconciliation, and bounded cleanup. Confirm retry authority is a private result of the exact current attempt, after current streams drain and the prepared source closes—not an error class, error code, or callback-visible abort reason. Replay attempt 1's abort reason and transport error during healthy attempt 2, and bare-abort the connection signal during preparation: all must settle the current stream, consume the capability terminally, and avoid redial. A genuine current typed transport loss must remain retryable only after drain and source closure. Confirm `DownloadFileOptions.operationId` is the stable capability-redemption ID and that push-only `transferId` is not accepted. Treat remote names and metadata as untrusted.

Code anchors: `files/fs.ts`, `files/validation.ts`, `files/share.ts`, `files/manager.ts`, `files/transfer.ts`.

## 5. Prove bounded ownership

For every asynchronous start, answer:

1. What global, peer, and principal admission was acquired first?
2. Which object owns the promise, stream half, buffer, descriptor, reservation, or callback?
3. What abort signal reaches it?
4. Which success, failure, timeout, cancellation, late-result, and shutdown paths terminate it?
5. Is release exact-once, and does a timed-out underlying promise remain accounted until settlement?

For outbound BI and UNI opens, test four distinct boundaries: pre-abort performs no native call or admission; cancellation of a never-settling native open rejects promptly and requests physical close; its lease stays visible until fulfilled closure; and a late stream is terminally reset/stopped before the lease disappears. A rejected `closed()` promise must never release the lease.

Inspect requests larger than each per-principal ceiling: they must reject immediately rather than queue forever. Verify fair queues are bounded and active scheduler leases remain visible until their actual logical owners settle.

At global, peer, and principal scopes, saturate general capacity and prove all four file classes remain admissible independently: outbound control, inbound control, outbound data, and inbound data. Trace inbound bidirectional classification: one sequential per-connection loop may read only the one-byte kind before admission; the header deadline bounds that structural slot; the stream must then enter its real class with immediate admission or be load-shed. Prove a queued general request cannot hide an available directional reserve, an overloaded RPC cannot head-of-line block a later file control, and failed classifier cleanup quarantines the connection. Configuration must reject fewer than five stream slots or less than three maximum control frames plus two `max(control frame, maximum chunk + 64 KiB)` data buffers. For a transfer lasting longer than `streamIdleTimeoutMs`, verify sub-timeout lane/chunk/segment/write/FIN progress refreshes the receiver watchdog while a truly stalled operation times out.

Code anchors: `runtime/resources.ts`, `runtime/task-group.ts`, `runtime/managed-connection.ts`, accept loops in `node.ts`.

## 6. Review OAuth policy

Require exact issuers/audiences, the documented RSA/EC/Ed25519 algorithm-key pairs, a configured HTTPS JWKS/static JWKS/single static public key, token `typ`, `iat`/`exp`/max age, connection and exact RPC/file scopes, and tenant/client rules. Confirm arbitrary JOSE key-resolver callbacks and all HTTP JWKS are rejected before unverified `jku`/`x5u` can influence selection. Verify configuration and mutable JWKs are snapshotted; fetched/static sets are bounded to 64 importable public keys/256 KiB; static JWKs require explicit compatible `alg`; fetched keys may omit `alg`, but any present value is compatible/allow-listed and every fetched key has a bounded unique `kid`. Confirm exact `cnf.jkt` binding to the presenter's `localPeerId` thumbprint or an authoritative directory callback only when `cnf` is absent. A malformed/mismatched present `cnf` must never fall back.

Review token acquisition/storage separately; it is application-owned. Verify remote JWKS rejects redirects and uses the fixed 5-second timeout, 30-second success/failure cooldown, and 10-minute cache. Establish removed/new-key and established-session revocation latency from that cache, token/session TTL, and any introspection/directory mechanism.

## 7. Review discovery and egress

Validate signed-ticket expiry/signature/protocol and confirm every remote direct candidate or default-relay origin requires an explicit egress decision before dial. Check canonical HTTPS origins, custom-relay membership, mDNS label/address bounds, and absent/false/throwing callback behavior. DNS plus custom filtering remains unsupported. For relay-less claims, inspect the exact-version normalization seam and require two-host evidence showing non-loopback direct paths, no relay, and both ticket and mDNS discovery.

## Deferred hypotheses, not release findings

The 2026-08-24 follow-up closed the reproduced stale retry-provenance and admission false-success cases above. The scoped review did not establish production failures for forcibly bounding a non-cooperative custom prepared-source `close()` without erasing ownership, compile-time shared-attempt/runtime-claim disposal, replacing the sender commit boolean, the internal runtime-slot `undefined` sentinel, or broader slot-model permutations. These remain optional hardening prompts, not confirmed defects or reasons to expand this pass.

## Release decision checklist

- No unresolved medium-or-higher local architecture/security findings.
- Unit, native integration, type, lint, docs, package, dependency, and workflow gates pass on the exact commit.
- Packed public API contains no testing/internal leaks and ATTW/publint/install/tree-shake checks pass.
- External ticket/default, ticket/custom, ticket/disabled, DNS/default, mDNS/default, mDNS/custom, and mDNS/disabled topology cases pass.
- Mixed workload, 100-peer, and 10,000-file single-physical-connection gates meet error/fairness/memory/native-baseline criteria. The file gate is exactly 5,000 pushes and 5,000 capability pulls and requires zero active/ambiguous operations, bounded tombstones, and task/share/resource/stream return to baseline.
- The external lab run is tied to the exact source commit; the immutable publish manifest ties that commit and run ID to the one validated tarball.
- SBOM, registry signatures, tarball digest, and post-publish registry bytes match; verified provenance names this repository, publish workflow, commit, run, and tarball SHA-512.
- `main`, the `npm` environment, trusted-publisher identity, and dedicated/ephemeral self-hosted lab runners have independently reviewed protections.

A green local suite creates a release candidate. It does not substitute for the external relay/discovery/native lifecycle evidence. A same-host, loopback, mocked, reduced, reconnecting, or diagnostics-incomplete run cannot qualify the 10,000-file or two-host topology claims; this repository does not claim those artifacts before they exist for the exact candidate.
