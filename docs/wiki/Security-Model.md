# Security model

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Files](File-Transfers.md) · [Audit guide](Audit-Guide.md) · [Validation](Production-Validation.md)

## Security objective

Knowledge of a locator, network address, endpoint ID, RPC path, transfer ID, or filename must not be enough to invoke application work or attach a file lane.

The model assumes the network, routes, remote endpoint, RPC metadata/input, manifests, filenames, file content, and capability presentations may be hostile. It trusts configured local code, managed endpoint keys, configured identity issuers/JWKS, and application authorization/storage policy.

## Decision pipeline

```text
outbound: validate + snapshot independently trusted target expectations
  → resolve explicit ticket, DNS/PKARR, or mDNS locator for expected peer ID
  → for tickets, require signed locator peer ID == expected peer ID
  → egress checks, then native dial
  → encrypted endpoint-key-authenticated QUIC
  → require connected endpoint ID == expected peer ID
  → optional endpoint admission (`preAuthorizePeer`)
  → mutual application credential verification
  → require authenticated principal == expected principal
  → active short-lived session
  → strict operation parse
  → configured `SessionSecurity.authorize` policy
  → tRPC dispatch, file offer, or capability lookup
```

Inbound connections enter at the QUIC step; they do not present a locator or caller-supplied outbound target expectations. For an outbound connection, locator resolution/binding, connected-endpoint mismatches, and endpoint-admission rejection occur before `SessionSecurity.getCredential` is called. The principal check occurs immediately after mutual authentication and before the peer runtime is installed, returned, or exposed through `onPeer`.

Failure at any step is fail-closed. In particular, file pull authorization receives only a non-secret capability hash and runs before registry lookup, reducing capability-oracle behavior.

`SessionSecurity` defines the operation policy. The OIDC helper first requires the operation's OAuth scope and then invokes its optional custom policy; that policy can narrow but cannot restore a missing scope. Shared-secret and custom implementations may apply different rules, so an audit must inspect the configured implementation.

## Outbound target binding

Outbound callers must supply a locator and two expectations obtained from a trusted source independently of that locator:

```ts
await node.connect<RemoteRouter>({
  locator: { kind: 'ticket', ticket },
  expectedPeerId,
  expectedPrincipal: {
    subject,
    issuer,
    clientId,
    tenantId,
    // Optional additional exact match of SessionPrincipal.id:
    id
  }
});
```

`subject`, `issuer`, `clientId`, and `tenantId` are all mandatory matcher fields. For the optional principal fields, `null` means the authenticated field must be absent; it is not a wildcard. `id`, when present, adds an exact check of the authenticator's canonical principal ID. Unknown fields and malformed or missing values are rejected before dialing, and the complete target is defensively copied and frozen for reconnects.

For shared-secret security, the authenticated subject and ID are the endpoint ID and the optional OIDC-shaped fields are absent, so the exact matcher is:

```ts
const expectedPrincipal = {
  id: expectedPeerId,
  subject: expectedPeerId,
  issuer: null,
  clientId: null,
  tenantId: null
};
```

The shared-secret helper denies every RPC and file action unless its `authorize` callback explicitly allows it. `authorize: () => true` is a coarse all-holders policy suitable only when possession of the provisioned secret is intentionally the complete authorization boundary; production services should inspect the verified principal and requested action.

The locator remains untrusted routing material for target-selection purposes. Supplying expectations copied only from an attacker-supplied locator defeats the independent binding; production callers should resolve the expected endpoint/principal tuple from an authenticated directory, enrollment record, or similarly trusted bootstrap channel.

The three locator forms are explicit and closed: a signed ticket, Iroh DNS/PKARR lookup, or LAN mDNS browse. They select the initial route strategy, not an exclusive native route source. Node configuration must enable DNS, and doing so installs an endpoint-wide Iroh lookup that may be used after ticket or mDNS hints fail. An mDNS locator explicitly browses, while node-level mDNS configuration controls its default service and automatic advertisement. The locator never chooses relay policy or supplies identity expectations. A signed ticket can be freshly generated with `createTicket()`, which samples current addresses and home relay before signing.

## OAuth/OIDC without HTTP

p2prpc is an OAuth resource server, not an authorization server or browser client:

- The application obtains and refreshes access tokens out of band.
- Each endpoint presents an access token inside the encrypted session handshake, not in RPC headers.
- Verification requires a configured issuer, explicit configured audience(s), explicit signature algorithms, configured HTTPS JWKS or key, `iat`, `exp`, accepted access-token `typ`, maximum token age, and connection scopes.
- By default, `cnf.jkt` must equal the JWK thumbprint of the presenting endpoint's Iroh Ed25519 key. This binds the token to transport-key possession without claiming HTTP DPoP semantics.
- When no usable `cnf.jkt` is present, a managed-directory callback may supply endpoint binding for an issuer that cannot mint bound tokens. A present, non-empty but mismatched `jkt` always fails and cannot be overridden. Optional or disabled peer binding is an explicit weaker bearer-token mode.

Default operation scopes are `p2prpc:rpc`, `p2prpc:rpc:<path>`, `p2prpc:file:push`, and `p2prpc:file:pull`; `p2prpc:*` is an administrative wildcard. Custom OIDC policy can narrow these grants but cannot restore a missing mandatory scope.

### Bootstrap caveat

The initiator sends its credential only after route resolution and the connected transport endpoint match `expectedPeerId`, and after `preAuthorizePeer` accepts the endpoint. However, the remote application principal cannot be known until that credential exchange completes. An `expectedPrincipal` mismatch therefore rejects the connection before peer installation but may occur after the initiator has disclosed its credential to the expected endpoint key.

This ordering is an unavoidable bootstrap limit, not principal preauthentication. Use short-lived, audience-specific and preferably endpoint-key-bound tokens; obtain the complete endpoint/principal expectation from a trusted directory; and use `preAuthorizePeer` when an endpoint-key allow-list is available. Direct-address and relay callbacks remain the pre-dial egress controls.

## Other `SessionSecurity` modes

Shared-secret mode uses an HMAC challenge over the fresh nonce and endpoint tuple. It creates a principal whose ID/subject is the endpoint ID and whose scope is `p2prpc:*`; the secret proves group membership but does not distinguish users or tenants, so the explicit policy remains the authorization boundary. A custom `SessionSecurity` defines the system's actual credential, principal, and authorization strength and must be audited as part of the trusted computing base.

`dangerouslyAllowInsecureSessions()` is an explicit test/development escape hatch with a public fixed credential and allow-all policy. It nullifies the application-authentication objective and must be rejected by production configuration and review.

## RPC metadata and tRPC middleware

`ctx.request.headers` is headers-like for ergonomics, not HTTP and not identity. Names are lowercased; defaults are 64 fields, 64-byte names, 8 KiB values, and 16 KiB total. Defaults and per-call overrides are separately validated, then merged and validated again. Unsafe controls are rejected, duplicate names within each input are rejected, and the result is frozen. Reserved names/prefixes are `authorization`, `cookie`, `set-cookie`, `connection`, `forwarded`, `host`, `origin`, `proxy-*`, `x-forwarded-*`, `x-real-ip`, `p2prpc-*`, and `x-p2prpc-*`.

Middleware should use metadata only as a request selector and compare it with verified state. For example, a requested tenant header may select a tenant, but membership must come from `ctx.auth.principal.tenantId` or authoritative policy.

The server authorizes the RPC path/type/metadata before creating context and dispatching tRPC. `SessionSecurity.authorize` does not receive parsed procedure input; input-aware decisions belong in middleware or the procedure after runtime parsing.

Core passes a frozen `PeerContext` seed to `createContext`. If the application returns a different tRPC context shape, it must deliberately preserve or expose the verified `auth` and untrusted `request` fields needed by middleware.

## File authorization

- Push: active session + `file.push` authorization + the receiver's `onIncomingFile` decision.
- Pull: active session + `file.pull` authorization + an unexpired capability whose peer/principal/operation policy matches.
- Data lane: exact authenticated connection object + transfer ID + fresh attempt ID + fresh 256-bit lane token + unused lane number.

These checks are cumulative. A capability is not a login credential; a lane token is not a file capability.

Data lanes do not perform a new OIDC exchange. They inherit the exact mutually authenticated physical connection and must also prove fresh attempt/lane credentials issued over that transfer's authorized control stream.

## Defensive controls

- Bounded handshakes, frames, decoded items/depth, headers, paths, peers, streams, files, chunks, lanes, transfers, queues, and timeouts.
- MessagePack rejects extensions, invalid UTF-8 keys, duplicate keys, `__proto__`, and trailing data.
- Reuse or replacement of one peer runtime requires fresh authentication and stable endpoint/principal identity; a later fresh inbound runtime relies on configured key binding, directory, and policy rather than historical process state.
- Session replacement, expiry, close, shutdown, and active capability revocation propagate cancellation.
- Remote error shapes omit stacks, custom formatter data, and internal messages; public text is sanitized and bounded.
- Structured security events contain identifiers and decisions, not credentials or capability tokens.
- Every dial starts from an explicit locator. DNS/PKARR is disabled until configured; once enabled, it is an endpoint-wide native fallback and can supplement ticket or mDNS hints. mDNS browsing starts only when selected by a locator or explicit browse API. Every resolved path remains subordinate to the independently trusted expected endpoint/principal.
- On a DNS-disabled endpoint, signed-ticket and mDNS routes pass through direct/relay egress callbacks. Enabling DNS with either callback fails closed because the pinned wrapper cannot expose DNS-resolved candidates before dial. mDNS defaults to private/link-local/loopback direct addresses; a callback can explicitly broaden them. Use distinct endpoints when route-source isolation is required.
- Relay configuration is explicit: default, custom HTTPS URLs, or disabled. Default-network mDNS relay hints require an explicit callback. Custom ticket/mDNS hints must belong to configured canonical origins before any callback can narrow them; disabled endpoints reject all relay hints. Custom relays may still upgrade to direct. In exact-pinned `@momics/iroh-http-node` 0.6.0, disabled means loopback-only, so relay-less production operation is not claimed.

## Enterprise deployment profile

Use managed persistent endpoint keys, unique audience and connection scope per trust domain, required proof-of-possession binding, short token/session lifetimes, narrow operation scopes, authoritative tenant/role policy, durable security-event export, edge rate limiting, quotas, mutation idempotency, service-owned storage roots, and quarantine/malware/DLP scanning.

The full residual-risk register is in [SECURITY.md](../../SECURITY.md).
