# Architecture and security audit guide

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md)

## Fast audit path

1. Confirm the deployment's identity, endpoint-key, ticket-bootstrap, and token issuance model.
2. Trace one RPC from frame parsing through `SessionSecurity.authorize` into tRPC middleware.
3. Trace one capability pull from authorized tRPC issuance through lane attachment and atomic publication.
4. Review reconnect, expiry, cancellation, revocation, and mutation uncertainty.
5. Separate library controls from application and infrastructure responsibilities.

## Control-to-code map

| Question | Primary implementation | Evidence |
|---|---|---|
| Can a peer ID alone invoke work? | `src/node.ts`, `src/security/handshake.ts` | Native raw-peer negative test in `test/node.integration.test.ts` |
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
- Are tickets and expected endpoint IDs distributed through an authenticated directory rather than user-supplied bootstrap?
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
- Do production builds/configuration prohibit `dangerouslyAllowInsecureSessions()`?

## What the library does not guarantee

- Exactly-once RPC or mutation rollback after cancellation.
- Immediate JWT revocation without short lifetimes or a custom introspection-backed authenticator.
- That a valid digest means content is safe, authentic, or policy-compliant.
- Safety when an untrusted local user controls a source/destination parent directory or a custom storage adapter.
- Durable capability state, audit delivery, transfer history, retention, or cross-process quotas.
- Network-edge source-IP rate limiting.
- Browser or React Native transport support in this release.
- Effective custom native QUIC ALPN, stream priorities, or configured native stream/window limits through the current Iroh adapter.

## Verification commands

```bash
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run build
npm audit --omit=dev
```

The native integration suite is security-relevant: it regression-tests that a raw Iroh peer with the signed routes cannot dispatch an RPC mutation without completing application authentication.

## Review conclusion template

A useful approval should state:

- which endpoint and application identities are trusted;
- how tickets, tokens, scopes, and key bindings are provisioned;
- which operation and storage policies were reviewed;
- which residual risks were accepted or mitigated externally;
- which limits and revocation/idempotency expectations apply in production.

Do not summarize the design as “the ticket authenticates the peer” or “tRPC authorizes the call.” The accurate statement is: Iroh authenticates an endpoint key, the application handshake authenticates a principal, p2prpc invokes the configured operation policy before dispatch, and tRPC supplies typed dispatch after those checks.
