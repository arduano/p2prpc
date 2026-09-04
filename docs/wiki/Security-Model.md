# Security model

## Security claim

Possessing an address, signed ticket, endpoint ID, or open QUIC connection is insufficient to dispatch RPCs or file operations. Work is accepted only after mutual application authentication creates a current session and explicit policy authorizes the individual action.

```text
locator resolution (reachability only)
  -> connected Iroh endpoint equals independently expected endpoint
  -> optional endpoint-key admission
  -> mutual v3 credential handshake
  -> exact expected-principal match (outbound)
  -> current, unexpired session
  -> operation scope + configured authorize policy
  -> tRPC middleware/procedure or file capability/destination policy
```

The QUIC application protocol and ALPN are v4. The six-message credential handshake embedded in it remains handshake format v3.

Inbound peers do not have an outbound expected-target record, so endpoint admission, credential authentication, and operation authorization are their trust boundaries.

Every initial installation, replacement, retained-runtime revival, duplicate decision, and reconnect passes one final admission-success gate after synchronous security, abort, expiry, and transport-close callouts. Public promise continuations recheck it after their last `await`, and queued `onPeer` delivery rechecks its captured selection. It returns or notifies a peer only if the node is still open, the runtime is still registry-owned and publicly live, the selected epoch is current, and the session is unexpired. Callback re-entry can terminate admission but cannot expose an already closed peer.

Locator authenticity is not egress authorization. Before any ticket-based dial, every advertised direct address requires an explicit `allowDirectAddress` decision and every remote default-network relay origin requires `allowRelayUrl`; omission rejects the candidate. Configured custom relays are an explicit canonical-origin allowlist. The callbacks see canonical untrusted remote candidates, never local default selection or configured custom origins. This prevents even a valid expected endpoint key from turning its signed reachability hints into unrestricted pre-authentication UDP or HTTPS egress.

## Transcript and replay resistance

The v3 handshake commits both endpoint IDs, both fresh 256-bit nonces, both timestamps, protocol identity, initiator/responder roles, credentials, grant expiries, transcript hashes, and the session ID. Credentials from one peer, role, protocol, or challenge cannot be transplanted into another transcript. Exact-key validation prevents older-version field smuggling.

Handshake frames are bounded to 64 KiB and have deadlines. The responder withholds its credential until the initiator authenticates. A failed handshake closes the physical connection; unauthenticated streams are never dispatched.

## OIDC/OAuth helper

The helper is an OAuth **resource server**, not an authorization server or HTTP emulation. Applications acquire tokens through their normal browser, workload-identity, client-credentials, device, or refresh flow and provide a short-lived access token to p2prpc.

Verification requires:

- a configured issuer and audience;
- an explicit signature-algorithm allow-list;
- a configured HTTPS JWKS URI, static JWKS, or single static public verification key (token `jku`/`x5u` is ignored, arbitrary resolver callbacks are rejected, and remote JWKS is HTTPS-only);
- `exp`, `iat`, maximum token age, clock tolerance, and accepted access-token `typ`;
- `p2prpc:connect` and operation-specific scopes;
- bounded, deeply immutable claims/scopes/principal fields;
- peer proof-of-possession binding.

Each verifier requires exact `cnf.jkt` equality with the authenticated remote Iroh Ed25519 JWK thumbprint. The presenter obtains that value with `irohPeerIdJwkThumbprint(localPeerId)`; its `remotePeerId` is not the proof key. If `cnf` is absent, an explicitly configured authoritative directory callback may bind the already verified principal to that endpoint key. A present malformed or mismatched `cnf` always fails and never falls back.

OIDC configuration is snapshotted through enumerable data properties, so later mutation cannot replace a trust root. Static and fetched JWKS are limited to 64 importable public keys and 256 KiB. Static JWKs require an explicit compatible allow-listed `alg`. Fetched JWKs may omit `alg` for provider compatibility, but any present value must be compatible/allow-listed; every fetched key and remote token requires a bounded `kid`, unique within the set.

| JWT algorithms | Required public key |
|---|---|
| `RS256/384/512` | RSA PKCS#1 v1.5, 2048–8192 bits |
| `PS256/384/512` | RSA-PSS, 2048–8192 bits, compatible hash/MGF/salt restrictions |
| `ES256`, `ES384`, `ES512` | P-256, P-384, P-521 respectively |
| `EdDSA` | Ed25519 |

Remote JWKS rejects redirects and has a 5-second fetch timeout. A successful set is cached for 10 minutes; unknown-key refresh and failed-fetch retry are held to a 30-second cooldown, and non-200 bodies are cancelled. A removed key can remain usable until a successful refresh. Existing sessions are not reverified when keys change and remain valid until their own expiry, so urgent revocation needs short token/session TTLs or an authoritative online policy.

OAuth adds centralized issuance/revocation policy, short grants, audience separation, scopes, tenant/client identity, issuer key rotation, and auditable identity. Those benefits are transport-independent and are not N/A without HTTP. Compared with an API key, OAuth substantially narrows and identifies authority. It does **not** authenticate discovery, acquire tokens, guarantee immediate JWT revocation, or bind bearer tokens to QUIC without the extra `cnf`/directory rule.

Use distinct audiences and grants per application/environment/trust domain. Prefer short token/session TTLs; use introspection or directory policy when immediate revocation is a requirement.

## Shared-secret helper

Shared-secret mode proves membership with HMAC-SHA-256 over the full role-specific transcript. It requires at least 32 bytes of securely generated material and an explicit `authorize` callback; omitted authorization is impossible and callback failure denies. The secret does not distinguish holders, users, or tenants, so it is appropriate for a tightly provisioned workload group, not general enterprise user identity.

The insecure helper exists only in `@arduano/p2prpc-core/testing`.

## Authorization

OIDC first enforces mandatory scopes, then lets custom policy narrow the result. The callback cannot restore a missing scope. RPC policy receives exact path, procedure type, and immutable headers; file policy receives push manifest or pull capability ID. Reasons crossing audit/public boundaries are display-sanitized and bounded.

| Scope | Authority |
|---|---|
| `p2prpc:connect` | Establish a session; required by default |
| `p2prpc:rpc` | Any RPC |
| `p2prpc:rpc:<exact-path>` | One exact RPC path |
| `p2prpc:file:push` | Push a file |
| `p2prpc:file:pull` | Redeem a pull capability |
| `p2prpc:*` | All library scopes, including connect |

Authorization does not receive parsed tRPC input. Input-aware business authorization belongs in middleware/procedure after runtime validation. Non-idempotent mutations need durable application idempotency; p2prpc deliberately performs no transparent RPC retry.

## Request metadata

Headers are a non-HTTP metadata map designed to feel familiar to tRPC middleware. Names are lowercase; names, values, count, and aggregate bytes are bounded; duplicate, control/bidi/zero-width, proxy, credential, and `p2prpc-*` names are rejected. The final map and surrounding request context are immutable.

Headers are suitable for tracing, locale, idempotency keys, and a requested tenant. They are never identity. Compare a requested tenant with the verified `ctx.p2p.auth.principal.tenantId`; do not trust a header merely because the QUIC peer is authenticated.

## File capabilities

Root `ctx.p2p.files.share()` derives both allowed endpoint and complete canonical principal from the exact request session; captured facades reject after session replacement or expiry. `peer.files.share()` applies the same derivation to the peer's current session. Callers can choose only expiry and logical-download count. Bearer capabilities and arbitrary binding lists remain an advanced API choice.

Tokens contain 256 random bits and only domain-separated hashes are stored. Reservation checks are constant-key lookups and bind token, endpoint, full principal, operation ID, transfer fingerprint, expiry, and download budget. Revocation aborts active reservations. Reconnects reauthenticate and reauthorize.

Capability-pull retry authority is private to one connection attempt. Callback signals expose only ordinary sanitized errors; replaying a prior abort reason, throwing a lookalike `DISCONNECTED` error, or receiving an untyped connection abort cannot authorize reconnect. A current typed transport loss becomes retryable only after that same attempt proves stream drain and prepared-source closure; uncertainty consumes the reservation terminally.

Push completion uses a receiver-generated 256-bit receipt challenge after durable destination publication. Until the sender validates that completion, it may report `OUTCOME_UNKNOWN`; afterward success is permanent even if receipt/FIN cleanup fails. A valid echoed receipt moves the outcome from the hard acknowledgement-ambiguous store to a bounded replay tombstone. The receiver ledger is node-scoped, so it survives physical connection replacement and same-process runtime revival. Hard state has non-evictable peer, canonical-principal, and node-wide quotas; recent acknowledged/rejected tombstones have separate evictable quotas at those scopes. Expiry is deadline-indexed, and shutdown closes admission before clearing evidence only after owned work settles. The ledger is not process-durable, so applications still need durable reconciliation across crash or replay-window expiry.

## Denial-of-service controls

All frames, text, collections, claims, metadata, manifests, files, chunks, lanes, peers, handshakes, queues, buffers, callbacks, and transfers have limits. Admission is global, per endpoint, and per principal. Each scope reserves outbound/inbound file controls and outbound/inbound data lanes independently, leaving one general/RPC slot; no class may consume another class's last progress path. The corresponding minimum buffer model is three control frames plus both maximum data buffers. Handshakes also use bounded global/peer token buckets. Unknown fields and malformed shapes fail before application callbacks.

The file receiver enforces an idle-progress deadline rather than a total-duration deadline. Lane admission, chunk headers, each 64 KiB body segment, successful destination writes, lane FIN, and terminal progress refresh it; individual stalled operations still time out. This permits healthy long transfers without allowing silent sessions to live forever.

These controls bound library-owned work; applications must bound their own schema parsing, databases, callback internals, and response generation.

## Audit and secrets

`onSecurityEvent` emits credential-free session and authorization records. Delivery is best effort and grants no authority, so forward it to a monitored durable sink. An event callback may synchronously close the peer or node; the final admission gate observes that terminal state before any peer is returned. Tokens, shared secrets, credentials, capability plaintext, file contents, and unsanitized peer errors are not included.

Custom authenticators/transports imported from `/advanced`, token providers, directory binders, application policy, destinations, and storage are part of the deployment trusted computing base.
