# @p2prpc/core security

Production nodes must configure `SessionSecurity`; there is no anonymous default. A locator or Iroh peer ID is not application authorization. Prefer short-lived OAuth access tokens verified by `createOidcSessionSecurity` with exact issuer/audience/algorithm/JWKS checks, mandatory operation scopes, a one-hour default/24-hour maximum age, and default `cnf.jkt` binding to the Iroh endpoint key. The shared-secret helper is intended for securely provisioned workload groups. `dangerouslyAllowInsecureSessions()` is only for isolated tests.

Locator tickets are signed but are not authorization secrets. Every outbound `connect()` requires a separately trusted expected endpoint ID and exact canonical principal matcher. Ticket/connection mismatch fails before credentials are requested, principal mismatch fails before the peer is installed or returned, and the frozen target remains required on reconnect. Provision the ticket and both expectations through a trusted bootstrap channel. Use `preAuthorizePeer` for a broader endpoint-key allow-list and inbound admission, then retain session authentication and per-operation authorization.

Native DNS/mDNS route discovery is disabled; only signed locator candidates are dialed. Restricted-relay deployments must configure explicit `relayUrls` with `allowRelayUrl`, ensuring egress policy runs before the native endpoint contacts a relay.

RPC metadata and remote filenames are untrusted. File capabilities should remain peer- and, where applicable, issuer-aware principal-bound. Resolve authorized object IDs inside service-owned source roots and never pass caller-supplied paths to `fileSource()`. Received content should use a service-owned destination parent, be quarantined, and be scanned before use. The built-in destination performs whole-file verification before publication; a custom destination is a trusted adapter and must provide equivalent final digest verification, cancellation, and atomic commit behavior. Do not automatically break a destination lock after a crash. Long-lived subscriptions require application heartbeats within their I/O timeout.

Use distinct OAuth audiences and connection scopes per application/environment/trust domain. Non-idempotent mutations require durable application-level idempotency keyed by the verified principal and tenant, procedure, and caller-supplied key. Prefer `allowedPrincipals` for capabilities; `allowedSubjects` is deprecated, and `allowBearer: true` only permits endpoint-ID binding to be omitted.

`onSecurityEvent` is best-effort observability, not a durable audit log. Export it to a monitored durable sink. OIDC principal IDs are now hashed from issuer/subject/client; migrate security state keyed by the former readable IDs.

The repository-level `SECURITY.md` documents the full threat model, controls, operational requirements, residual native-transport limitations, migration notes, and private reporting guidance.
