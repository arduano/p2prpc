# Security policy and threat model

## Security target

p2prpc assumes the network, locator tickets, request metadata, remote endpoints, RPC inputs, file manifests, and file contents may be hostile. It relies on Iroh/QUIC for transport confidentiality and possession of an endpoint key, and adds mandatory application authentication and authorization before dispatch. Knowledge of an address, ticket, or peer ID is never intended to authorize RPC or file work.

Reviewers can use the concise [architecture and security wiki](./docs/wiki/Home.md) before this detailed control and residual-risk register.

## Supported versions

Before 1.0, security fixes are maintained on `main` and the latest released minor line only. Older snapshots and unsupported dependency combinations may not receive fixes.

| Version | Supported |
|---|:---:|
| `main` | Yes |
| Latest released `0.x` line | Yes |
| Older versions | No |

The intended enterprise deployment uses short-lived OAuth access tokens with exact issuer/audience validation and proof-of-possession binding to managed Iroh endpoint keys. A provisioned HMAC secret is suitable for smaller workload-to-workload deployments. Human identity, workload identity, device identity, and authorization policy should remain distinct in audit records.

## Controls implemented

- Fail-closed required `SessionSecurity`; no anonymous default.
- Mutual protocol-v2 handshake with fresh 256-bit nonces, transcript-derived session ID, bounded credential/frame size, deadline, exact contract identity, mutual credential verification, and expiry closure.
- Authentication repeated on every physical reconnect; principal swapping on one endpoint runtime is rejected.
- Connection replacement, expiry, explicit peer close, and node shutdown abort active RPC and file-operation signals; a closed peer handle cannot reconnect itself.
- OAuth JWT verification through `jose`: exact configured issuer/audience, HTTPS JWKS, algorithm allow-list, time claims, access-token type, scopes, a one-hour default/24-hour maximum token age, and default `cnf.jkt` binding to the Iroh Ed25519 identity.
- Canonical, collision-resistant OIDC principal IDs derived from the verified issuer/subject/client tuple; conflicting `client_id` and `azp` claims are rejected.
- Per-operation authorization for every RPC path/type, incoming file push, and capability pull.
- Normalized, immutable, bounded request metadata separated from a frozen trusted session principal/claims and frozen library-owned `PeerContext` view. Credential, forwarding, HTTP authority/origin, and library-owned names are reserved; security-relevant display text rejects or sanitizes C0/C1 and Unicode bidirectional/zero-width formatting controls.
- Domain-separated Ed25519-signed, expiring, size-bounded locator tickets with strict peer-key, timestamp-ordering, socket-address, relay-URL, and canonical-encoding validation. Tickets are never authorization capabilities.
- Required outbound target binding: every `connect()` supplies a separately trusted expected endpoint ID and exact canonical principal matcher. Ticket/connection identity mismatch and endpoint admission fail before credentials are requested; principal mismatch fails before a peer runtime is installed or returned. The frozen target is retained across reconnects.
- Bounded unauthenticated handshakes, application stream handlers, control-frame bytes/items/nesting, RPC paths/headers, file manifests, chunks, lanes, active transfers, and transfer queues. MessagePack is preflighted before decoding and rejects extensions, invalid UTF-8 map keys, duplicate keys, and `__proto__`.
- Peer-bound, expiring, one-operation file capabilities by default; only domain-separated token hashes are stored. Capability failures are deliberately non-oracular.
- Exact authenticated-connection binding for file control/data lanes, receiver-issued transfer attempt and lane secrets, duplicate-session rejection, and strict chunk-size validation before allocation. The built-in filesystem destination performs full-file BLAKE3 verification before publication.
- Capability operations bound across bounded reconnects to peer ID, the complete canonical principal tuple (ID, issuer, subject, OAuth client, and tenant), operation ID, and negotiated chunk-size/lane fingerprint. Active revocation aborts reservations.
- No-follow/stability-checked file sources and exclusive private, locked, verified, atomically published destinations.
- Remote RPC error shapes strip stacks, custom data, and internal-error messages.

The security regression suite includes a native raw-Iroh peer which has the target ID and direct routes but cannot invoke a tRPC mutation without the application handshake.

## Operational requirements

- Persist Iroh secret keys in a secrets manager or managed device keystore. Ephemeral endpoint identities make peer binding and audit correlation unstable.
- Bootstrap tickets, expected peer IDs, and expected canonical principal tuples through a trusted directory, device-management channel, or equivalent authenticated mechanism. Signed tickets prove which endpoint key authored their routing data; they do not say that the endpoint belongs to an approved application principal. For optional principal fields, a `null` matcher value explicitly requires absence.
- Use access tokens intended for this service, preferably `typ: at+jwt`, with short expiry. Never present ID or refresh tokens. Mint a narrow token for the expected peer/audience in `getAccessToken` where the authorization server supports it.
- Assign a distinct OAuth audience and required connection scope per application, environment, and trust domain. Do not let a broadly accepted token turn one authenticated service into a confused deputy for another.
- Use `preAuthorizePeer` for an organization-wide endpoint-key allow-list and inbound admission. This hook runs before the session handshake and must remain a cheap key-admission check; outbound calls also enforce their required per-call expected endpoint. It does not replace expected-principal matching, credential verification, or operation policy.
- Keep `peerBinding: 'required'`, or implement `bindPrincipalToPeer` against an authoritative managed-key directory.
- Rotate/revoke endpoint keys and signing keys through organizational lifecycle controls. Use short JWT/session lifetimes or introspection for urgent revocation.
- Treat RPC headers as caller assertions even after normalization and freezing. Middleware must derive identity and membership from `ctx.auth.principal` and compare metadata such as a requested tenant against verified claims or authoritative policy.
- For non-idempotent mutations, require a bounded `idempotency-key` header and atomically key durable operation state by the complete verified principal tuple, verified tenant, procedure path, and key. The caller-supplied key is replay-control input, not identity or permission.
- Restrict outbound route candidates with `iroh.allowDirectAddress` and `iroh.allowRelayUrl` where egress policy forbids private or unapproved networks/services. Native DNS/mDNS route discovery is disabled: dialing uses only signed locator candidates. Configuring `allowRelayUrl` requires explicit, prevalidated `relayUrls` (or disabled relays), so the native endpoint cannot contact a default relay before policy runs.
- Resolve authorized application object IDs inside service-owned source roots; never pass caller-supplied paths to `fileSource()`. Source and destination parent directories must be inaccessible to untrusted local users who could replace a path component. Put received files in quarantine and run malware, DLP, and content-type policy before making them available. A BLAKE3 digest proves transfer consistency, not that content is safe or trusted.
- Treat file capability tokens as secrets. Return them only through authorized procedures, never place them in request metadata, and redact them from logs, traces, and durable audit records.
- Treat a surviving `.p2prpc.lock` as potentially live. There is no automatic stale-lock breaking; after a crash, remove it only after establishing that no writer owns that destination.
- Ensure long-lived subscriptions produce application data or heartbeat events inside the configured per-read I/O timeout. The built-in client defaults to 30 seconds and the protocol has no heartbeat frame.
- Treat trace IDs, tenant headers, filenames, metadata, and rejection text as untrusted when logging or displaying them.
- Do not put credentials, personal data, or other secrets in application-authored tRPC error messages. Non-internal messages are sanitized and capped, but are intentionally visible to the authenticated caller.
- Apply application-specific rate, tenant, aggregate disk, and business-operation limits above the library defaults.
- Export `onSecurityEvent` records to a durable sink and monitor delivery health. The callback is best-effort and in-process; it is not a durable, complete, or backpressured audit log.
- Review the pinned native Iroh dependency, provenance, SBOM, platform builds, relay configuration, and QUIC behavior as part of the production supply-chain review.
- Review the packaged dependency licenses and the Iroh artifact caveat recorded in [`packages/core/THIRD_PARTY_NOTICES.md`](./packages/core/THIRD_PARTY_NOTICES.md).

## Known residual risks

- `@momics/iroh-http-node` is pinned to 0.6.0 because its 0.6.1 wrapper reports an internal native-binding version of 0.6.0 and fails when napi-rs strict version enforcement is enabled. CI loads the pin with `NAPI_RS_ENFORCE_VERSION_CHECK=1`. Upstream's Linux binaries require glibc 2.34 or newer; Alpine/musl and older glibc distributions are unsupported. Its npm artifacts also omit their declared MIT/Apache license texts, as detailed in the third-party notices.
- `@momics/iroh-http-node` 0.6 does not expose custom native QUIC ALPN, stream priorities (`setPriority` is a no-op), configured stream-count limits, or configured receive-window limits through this adapter. Flow control remains native-managed. The authenticated application handshake supplies protocol isolation, while JavaScript admission limits, deadlines, and cleanup bound dispatched work. A native stream-open operation cannot currently be aborted; a stream which resolves after its caller timed out is cleaned up when it arrives.
- During outbound bootstrap the initiator presents its credential only after the ticket and connection match the separately trusted expected endpoint ID, but before it can authenticate and compare the remote application principal. Trusted target provisioning, `preAuthorizePeer`, proof-of-possession binding, narrow audience, and short token lifetime limit disclosure to an approved endpoint key running an unexpected application identity.
- The handshake refresh model is reconnect-on-expiry rather than in-place token refresh. Existing work ends when the connection closes.
- JWT revocation is not instantaneous without short lifetimes or a custom introspection-backed authenticator.
- OIDC `authorize` is deliberately unable to override missing mandatory scopes. Custom policy can only reduce the access granted by the connection and operation scopes.
- Application callbacks and tRPC procedures can still consume unbounded CPU, memory, disk, or time. Use deadlines, rate limits, worker isolation, and tenant quotas appropriate to the workload.
- Prefer `allowedPrincipals: [ctx.auth.principal]` for file capabilities. `allowedSubjects` is deprecated because it compares a raw issuer-scoped subject. `allowBearer: true` permits omission of endpoint-ID binding only; an explicit `allowedPeerIds` list still applies, and `allowedPrincipals` can bind the complete issuer/subject/client/tenant identity.
- `maxDownloads` counts logical operation IDs, not exactly-once network delivery. Explicit revocation aborts active reservations. Passive expiry prevents a new or reconnecting reservation but is not a standalone timer that guarantees termination of active work at the exact expiry instant. A disconnected operation has a fixed 30-second reconnect lease and five reconnects by default, and it is reauthenticated and reauthorized on every new connection.
- Resume state is bound to file digest, size, and chunk size, and saved chunks are re-hashed, but it is not bound to a peer, principal, session, or capability. Authorization is independent. Resume state is not a substitute for an enterprise transfer database, retention policy, or cleanup service.
- Leaf-level no-follow and identity checks do not defend against a local attacker who controls a source or destination parent directory, and they do not authorize a caller to select a source path.
- Custom file sources and destinations must cooperate with abort signals. The library waits for a side-effecting callback to settle after abort so callers cannot observe a timeout followed by late publication; a callback that ignores cancellation can therefore leave its transfer promise pending. Isolate or wrap untrusted implementations.
- Custom file destinations are trusted storage adapters and must verify complete staged content against the manifest immediately before publishing it. The transport checks each received chunk, but it cannot independently re-read an opaque custom destination. Prefer `fileDestination()` or require equivalent verification and atomic-commit behavior in storage-adapter review.
- Concurrency limits bound simultaneous unauthenticated handshakes but do not impose a source-IP or endpoint-key attempt rate, which the current native adapter does not expose. Internet-facing deployments should add relay, network-edge, or admission-directory rate limiting in addition to `preAuthorizePeer`.
- Security-event callbacks can lose events on process failure or sink failure. Once policy evaluation begins, exceptions/timeouts emit a generic denied authorization event; a stale-session rejection before evaluation begins does not.
- Cancellation is cooperative and cannot undo a mutation that has already begun.
- RPC delivery is not exactly once. Durable, atomic application-level idempotency is required wherever replaying or losing the response to a completed mutation would be unsafe.
- Production and maintainer dependencies are audited in CI. The maintainer toolchain overrides `tsup`'s esbuild dependency to a patched compatible release until `tsup` updates its declared range.

## Reporting vulnerabilities

Do not publish secrets or exploit details in a public issue. Use GitHub's [private vulnerability reporting](https://github.com/arduano/p2prpc/security/advisories/new) with affected versions, impact, reproduction details, and suggested remediation. Maintainers will acknowledge reports as availability permits and coordinate disclosure after a fix or mitigation is ready. Rotate any credentials or endpoint keys included in a report.

## Breaking migration from 0.1

- Replace `connect(ticket)` with `connect({ ticket, expectedPeerId, expectedPrincipal })`. The principal matcher requires exact `subject`, `issuer`, `clientId`, and `tenantId` expectations (`null` means absent) and accepts an optional canonical `id` check. Source expectations independently of the locator; shared-secret peers use the endpoint ID as `id`/`subject` with the optional fields set to `null`.
- Add required `security`; replace `authorizePeer` with optional `preAuthorizePeer` only for cheap endpoint-key filtering.
- `PeerContext` now contains `auth` and per-call `request`, including normalized `request.headers`.
- The library-owned `PeerContext` object passed to `createContext` is now frozen. Context factories which augmented that input by mutation must return a new application context instead.
- Node options are snapshotted at construction, including captured security methods and copied Iroh secret-key/relay lists. Do not rely on later mutation of the original options object for policy or key rotation.
- Use `p2pRpcContext(headers)` in tRPC call options; credentials cannot be sent as request headers.
- File sharing must specify `allowedPeerIds` unless `allowBearer: true` is deliberate. Defaults are five minutes and one logical download.
- Incoming file offers now include the verified `principal`, `sessionId`, and an offer-decision abort signal tied to the authenticated connection attempt.
- OIDC `principal.id` is now `oidc:<base64url SHA-256>` over a domain-separated encoding of `[issuer, subject, clientId ?? null]`. Migrate ACLs, database keys, cached grants, and audit correlation keyed by the earlier readable/delimiter ID. `issuer`, `subject`, and `clientId` remain separately available.
- OIDC tokens now have a one-hour default maximum age and cannot configure an age above 24 hours. Custom OIDC `authorize` callbacks no longer grant operations missing their required scope.
- RPC metadata now reserves HTTP credential/routing names and all `p2prpc-*`/`x-p2prpc-*` names. Rename any application metadata that used them.
- Protocol v2 control frames now reject MessagePack extensions, non-string or duplicate map keys, `__proto__`, invalid UTF-8 keys, excessive decoded values, and excessive nesting. Custom peers must emit the documented plain-data wire subset.
- Locator-ticket signatures now include an explicit domain separator. Regenerate any previously issued `p2prpc2` locator tickets; earlier protocol-v2 tickets intentionally fail signature verification after this upgrade.
- Active file capability revocation now aborts its reservations. Reconnects retain a logical operation only for the same complete principal tuple and negotiated chunk-size/lane fingerprint within bounded retry policy.
- Code constructing a complete `P2PNodeLimits` value must add `maxControlFrameItems`, `maxControlFrameDepth`, `maxFileChunkSize`, `maxGlobalFileTransfers`, `maxPeers`, and `connectTimeoutMs`; ordinary partial `limits` objects need no change.
- `peer.close()` now permanently retires that handle instead of allowing a later RPC to reconnect it implicitly.
- Wire identity is `p2prpc/2/...`; v1 peers and unsigned `p2prpc1` tickets are intentionally incompatible.
