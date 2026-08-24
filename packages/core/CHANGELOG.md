# @p2prpc/core

## 0.2.0

### Minor Changes

- 69a13a4: Require independently trusted endpoint and canonical-principal expectations for outbound connections; add signed-ticket, DNS/PKARR, and mDNS locators with fail-closed route egress policy; add immutable per-request metadata; bind file capabilities to endpoint and principal; add bounded fair admission with independent inbound/outbound file-control and file-data reserves; harden mutual authentication, OIDC, wire decoding, filesystem publication/resume/cleanup, reconnect arbitration, and exact stream/task ownership; split safe, advanced, and testing APIs; and publish as an exact-pinned ESM-only package with verified Node.js 20.3 support and gated release evidence.

  Wire protocol v4 adds a fresh receiver completion challenge and sender receipt before terminal FIN. Receiver reconciliation now keeps active or acknowledgement-ambiguous operations in a non-evictable hard store while moving acknowledged/rejected replay protection into separately bounded, evictable tombstones. This preserves conservative `OUTCOME_UNKNOWN` behavior without making acknowledged throughput proportional to reconciliation capacity.

  `FileDestination.finalize()` now receives an explicit `markCommitted()` context. Custom destinations must invoke it at the publication boundary so post-publication cleanup failures cannot be misreported as rejection or trigger rollback/retry.

  Canonical OIDC principal IDs now include the validated tenant claim as well as issuer, subject, and client. This prerelease ID-domain change prevents tenant-local subjects from sharing aggregate quotas, reconnect identity, or audit correlation.

  Stream-open cancellation is now admission-safe. Pre-aborted BI/UNI opens perform no native call; cancellation after native opening begins rejects promptly, quarantines the physical connection, and retains the stream/buffer lease until native rejection, confirmed late-stream cleanup, or fulfilled physical closure. RPC and file operation signals propagate through this boundary.

  Session expiry now removes the runtime from the public live-peer view in the expiry timer turn, before transport shutdown, while retaining native/resource ownership until physical settlement.

  File traffic can no longer borrow the final general/RPC stream or control-frame buffer at global, peer, or principal scope. RPC header normalization now consumes wide records and iterables incrementally under the configured count bound and rejects proxies/accessors without evaluating them.

  The single-connection stress gate now cancels only after an adopted data lane reports progress and records that trigger explicitly, separating ordinary transfer cancellation from the intentional connection-quarantine behavior for cancellation racing an unrevocable native stream open.

  Release publication is now retry-safe: an existing immutable npm version is accepted only when its integrity, exact tarball bytes, requested dist-tag, provenance source commit, and original trusted workflow invocation match the candidate. Ambiguous npm acknowledgements and partial GitHub releases can therefore be recovered without weakening byte or provenance checks.

  The production OIDC issuer API now accepts only a configured HTTPS JWKS, static JWKS, or single static public verification key. Arbitrary JOSE key-resolver callbacks are rejected because they receive unverified token headers and could otherwise let attacker-controlled `jku`/`x5u` choose trust roots.

  OIDC option objects and mutable single JWKs are captured at construction without evaluating accessors. Single keys must be public; static and fetched JWKS are limited to 64 keys/256 KiB and reject private, unimportable, or algorithm-incompatible material. Static JWKs require explicit compatible `alg`; fetched keys may omit it, but any present value must be allow-listed/compatible and every fetched key requires a bounded unique `kid`. Remote JWKS uses HTTPS only with a 5-second timeout, 30-second success/failure cooldown, and 10-minute cache. `irohPeerIdJwkThumbprint()` exposes the canonical `cnf.jkt` binding for a presenting node's local Iroh key.

  Receiver push reconciliation is now a node-lifetime ledger rather than connection-owned state, so acknowledgement-ambiguous commits and replay tombstones survive physical connection replacement and same-process runtime revival. Hard records are independently capped per peer, per canonical principal across endpoint keys, and node-wide, and are never capacity-evicted; replay tombstones have separate evictable caps at all three scopes. Expiry uses an indexed deadline heap instead of whole-ledger scans. Shutdown rejects new ledger admission immediately and clears retained state only after its owned work settles. The ledger remains process-local and is lost on crash. A retained disconnected outbound runtime can also be revived by a newly authenticated inbound connection only when endpoint and canonical principal still match.

  Peer capacity is now owned by a keyed runtime-slot registry: distinct pending endpoint IDs count toward `maxPeers`, same-endpoint attempts share one slot, and failed claims release exactly once. Outbound capacity is reserved before dialing and inbound capacity before authentication, closing the concurrent admission race without changing the public API.

  Physical connection replacement now publishes one immutable live epoch before retiring the old epoch. Initial install, replacement, duplicate arbitration, retained-runtime revival, and outbound reconnect converge on one final admission-success gate after synchronous security, abort, expiry, and transport-close callouts. Public connect/reconnect continuations cross that gate again after their last `await`, and queued `onPeer` delivery requires the exact selection to remain current. A peer is returned only while the node, registry slot, live-map entry, exact epoch, and session remain current; callback-triggered closure rejects `DISCONNECTED` instead of returning a stale handle.

  Capability-pull reconnect authority is now private to the exact connection attempt rather than encoded in reusable error identity. Callback signals expose ordinary sanitized errors, so a stale abort reason, replayed transport error, plain `DISCONNECTED`, or untyped connection abort cannot authorize redial. A current typed transport loss becomes retryable only after current-attempt stream drain and successful prepared-source close; the reservation remains active until cleanup settles, and cleanup uncertainty completes it terminally with `OUTCOME_UNKNOWN`.

  These two lifecycle corrections do not change wire v4 or the documented public TypeScript API.
