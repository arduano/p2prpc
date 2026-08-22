# Architecture and security audit guide

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md)

## Fast audit path

1. Confirm how the deployment obtains each trusted expected endpoint/principal tuple independently of locator tickets.
2. Trace an outbound connection through pre-dial locator binding, post-connect endpoint binding, endpoint admission, authentication, principal binding, and peer installation.
3. Trace one RPC from frame parsing through `SessionSecurity.authorize` into tRPC middleware.
4. Trace one capability pull from authorized tRPC issuance through lane attachment and atomic publication.
5. Review reconnect, expiry, cancellation, revocation, and mutation uncertainty.
6. Separate library controls from application and infrastructure responsibilities.

## Control-to-code map

| Question | Primary implementation | Evidence |
|---|---|---|
| Can a peer ID alone invoke work? | `src/node.ts`, `src/security/handshake.ts` | Native raw-peer negative test in `test/node.integration.test.ts` |
| Can a locator select a different outbound target? | `src/node.ts`, `src/transport/iroh.ts` | Expected-endpoint and connect-options tests in `test/node-security.test.ts` |
| Can the expected endpoint authenticate as an unexpected principal and become visible? | `src/node.ts` | Principal-mismatch-before-install/`onPeer` tests in `test/node-security.test.ts` |
| Are target expectations retained across reconnect without caller mutation? | `src/node.ts` | Target snapshot/freeze and reconnect tests in `test/node-security.test.ts` |
| How is OAuth verified and key-bound? | `src/security/oidc.ts`, `src/security/types.ts` | `test/security.test.ts` |
| Does every operation pass policy? | `src/node.ts`, `src/rpc/server.ts`, `src/files/manager.ts` | `test/node-security.test.ts`, `test/files.test.ts` |
| Can metadata spoof credentials? | `src/rpc/headers.ts`, `src/rpc/link.ts` | `test/headers.test.ts`, `test/rpc-link.test.ts` |
| Are frames allocation-bounded? | `src/protocol.ts`, `src/files/validation.ts` | `test/protocol.test.ts`, `test/files.test.ts` |
| Can stale file lanes attach? | `src/files/manager.ts` | transfer connection/attempt tests in `test/files.test.ts` |
| Are capabilities replay-bounded? | `src/files/share.ts` | share/reconnect/revocation tests in `test/files.test.ts` |
| Does built-in `fileDestination()` verify before publication? | `src/files/fs.ts` | filesystem, resume, race, and integrity tests in `test/files.test.ts` |
| Are errors and audit text safe? | `src/rpc/server.ts`, `src/text.ts`, `src/node.ts` | RPC and node security tests |
| Are dial routes constrained? | `src/transport/iroh.ts` | ticket and egress tests in `test/node-security.test.ts` |

Paths above are relative to `packages/core/`.

## Deployment questions

- Are Iroh private keys persistent, non-exportable where possible, rotated, and mapped to managed workloads?
- Are expected endpoint IDs and complete expected principal tuples distributed by an authenticated directory or enrollment system independently of user-supplied tickets?
- Does every outbound call provide all principal matcher fields intentionally, using `null` only to require absence and optional `id` only when the authenticator's canonical ID is stable and trusted?
- Is it understood that an expected-principal mismatch is detected after credential exchange, so credentials are short-lived, audience-limited, preferably endpoint-bound, and protected by pre-credential endpoint admission?
- Does each environment/trust domain have a distinct OAuth audience and required connection scope?
- Are access tokens short-lived, `at+jwt`, endpoint-key bound, and free of ID/refresh tokens?
- Does authorization derive tenant, roles, and membership from the verified principal rather than RPC metadata?
- Does `createContext` preserve the verified `auth` and untrusted `request` separation required by middleware?
- Are dangerous mutations durably idempotent across process restarts?
- Are source object IDs authorized before mapping into service-owned roots?
- Are shares principal-bound with `allowedPrincipals`, are any `allowBearer` uses deliberate, and is deprecated issuer-ambiguous `allowedSubjects` avoided?
- Are destinations quarantined in service-owned directories and scanned before release?
- Do custom destinations independently verify the final digest and publish atomically?
- Are peer, tenant, CPU, memory, stream, transfer, and aggregate disk quotas suitable for the deployment?
- Are `onSecurityEvent` records exported to a monitored durable sink without credentials or capability tokens?
- Is edge or relay rate limiting present for unauthenticated connection attempts?
- Is the deployment on a published native target, and has it reviewed the pinned Iroh version and [license-artifact caveat](https://github.com/arduano/p2prpc/blob/main/packages/core/THIRD_PARTY_NOTICES.md)?
- Do production builds/configuration prohibit `dangerouslyAllowInsecureSessions()`?

## What the library does not guarantee

- Exactly-once RPC or mutation rollback after cancellation.
- Immediate JWT revocation without short lifetimes or a custom introspection-backed authenticator.
- That a valid digest means content is safe, authentic, or policy-compliant.
- Safety when an untrusted local user controls a source/destination parent directory or a custom storage adapter.
- Durable capability state, audit delivery, transfer history, retention, or cross-process quotas.
- Network-edge source-IP rate limiting.
- Browser or React Native transport support in this release.
- Alpine/musl or glibc older than 2.34; the pinned Iroh dependency's Linux binaries require glibc 2.34 or newer.
- Effective custom native QUIC ALPN, stream priorities, or configured native stream/window limits through the current Iroh adapter.

## Verification commands

```bash
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run test:minimum-runtime
npm run build
npm audit --audit-level=low
```

The native integration suite is security-relevant: it regression-tests that a raw Iroh peer with the signed routes cannot dispatch an RPC mutation without completing application authentication.

## Review conclusion template

A useful approval should state:

- which endpoint and application identities are trusted;
- how tickets, tokens, scopes, and key bindings are provisioned;
- which operation and storage policies were reviewed;
- which residual risks were accepted or mitigated externally;
- which limits and revocation/idempotency expectations apply in production.

Do not summarize the design as “the ticket authenticates the peer” or “tRPC authorizes the call.” The accurate statement is: the caller independently names its expected endpoint and principal, Iroh authenticates the connected endpoint key, the application handshake authenticates the principal, p2prpc checks both expectations before exposing the peer, p2prpc invokes the configured operation policy before dispatch, and tRPC supplies typed dispatch after those checks.
