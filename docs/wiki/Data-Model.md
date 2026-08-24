# Data model

This page names the objects an audit will encounter and the authority each carries.

## Ownership tree

```text
P2PNode
├── Iroh endpoint and immutable configuration snapshot
├── resource scheduler and handshake rate limiter
├── bounded share/operation registry
├── node-lifetime receiver commit/replay ledger
└── Peer runtime slot, keyed by endpoint; at most maxPeers including pending admission
    ├── expected locator + endpoint/principal matcher (outbound only)
    ├── authenticated session
    ├── one current managed QUIC connection
    ├── RPC/file stream tasks
    └── transfer manager
```

Outbound runtimes retain their snapshotted trust expectations and canonical principal while disconnected. They can be revived by an outbound reconnect or a newly authenticated inbound connection for the same endpoint and exact principal. Purely inbound runtimes have no trusted reconnect target and are removed when their connection ends.

The runtime-slot registry is the sole `maxPeers` owner. Outbound connects reserve the expected endpoint before dialing; inbound connects reserve the transport-authenticated endpoint before application authentication. Concurrent claims for one endpoint share one slot, while a new endpoint is rejected once committed runtimes plus distinct pending endpoint IDs reach the limit. A failed claim releases exactly once; a committed slot remains occupied until that runtime's physical and task ownership settles.

## Identity and routing

| Object | Fields that matter | Invariant |
|---|---|---|
| Protocol identity | wire v4, `applicationId`, `contractVersion` | Produces exact ALPN `p2prpc/4/<application>/<contract>` and domain-separates incompatible applications. |
| Locator | ticket, DNS, or mDNS selector | Selects reachability only. It never supplies trust expectations. |
| Expected target | endpoint ID plus exact principal matcher | Validated and copied before dial; reused unchanged on reconnect. |
| Endpoint identity | Iroh public key / node ID | Authenticated by QUIC; proves possession of the endpoint key. |
| Principal | stable ID, issuer, subject, client, tenant, expiry, scopes, claims | Produced only by a configured authenticator; deeply bounded and immutable. The built-in OIDC ID hashes issuer, subject, client, and validated tenant as one identity tuple. |
| Session | ID, establishment/expiry, principal | Derived from the complete mutual transcript and tied to one physical authenticated connection. |

Optional matcher fields use `null` to require absence. A reconnect cannot replace the principal ID, issuer, subject, OAuth client, or tenant of its retained runtime.

## RPC objects

| Object | Meaning |
|---|---|
| Request | Exact `{id, path, type, headers, input}` control frame. |
| Headers | Lowercase string map with count/name/value/total-byte limits and reserved-name rejection. |
| RPC value | A bounded, acyclic SuperJSON tree using only built-in scalar, collection, date/URL/regexp/error, and typed-array annotations. Class, symbol, custom-transformer, alias, and cycle annotations are not wire types. |
| `ctx.p2p` | Reserved frozen library context containing peer identity, authenticated session, request, connection stats, and an exact-session file facade. Verified fields are not duplicated at mutable top-level aliases. |
| Response | Data frames followed by exactly one completion, or one validated error frame. |

The codec owns a private SuperJSON instance, so application-global transformer registration cannot affect remote decoding. Semantic annotation checks run before construction, including typed-array shape checks that prevent a tiny frame from requesting a large allocation. The tRPC type graph is a compile-time contract, not an authorization boundary; runtime input schemas and authorization remain mandatory.

## File objects

| Object | Meaning and invariant |
|---|---|
| Source | Application-owned bytes; the prepared-source lifecycle pins one validated file descriptor from hashing through sending. |
| Manifest | Exact name, size, BLAKE3 digest, transfer ID, chunk geometry, and optional schema-validated metadata. |
| Destination | Stages chunks, records bounded binary resume state, verifies the complete digest, atomically publishes, then explicitly marks the irreversible boundary before cleanup. |
| Share handle | 256-bit opaque token returned to an authorized caller; only a domain-separated hash is stored. |
| Share policy | Expiry and logical-download count. The safe peer API adds current endpoint and complete-principal bindings automatically. |
| Pull operation ID | Optional stable `DownloadFileOptions.operationId`; its hash indexes one capability redemption across reconnect/retry. It is sent as pull `requestId` and becomes that delivery's manifest transfer ID, but the public option remains distinct from push `SendFileOptions.transferId`. |
| Hard push record | Non-evictable `active` or outcome-ambiguous `committed` record, bound to principal and exact manifest fingerprint. |
| Replay tombstone | Recent `acknowledged` or `rejected` push outcome. Bounded and evictable; it prevents recent replay but is not correctness-critical after the sender receipted success. |
| Transfer | Non-constructible handle with immutable manifest, terminal result, cancellation, and independent progress iterators. |

Transfer metadata is rejected unless the node has a Standard Schema v1 runtime schema. Before schema code runs, the wire decoder has already required bounded accessor-free plain data, forbidden prototype-confusing keys, and copied every byte array. Schema output is validated and snapshotted again; a public manifest returns fresh byte-array copies so callers cannot mutate its private canonical state.

## Resource model

Every admitted unit is a vector over handshakes, streams, outbound transfers, inbound transfers, buffered bytes, and callbacks. A request must fit global, per-peer, and—after authentication—per-principal limits before it can enter a bounded fair queue. Transfer admission has independent inbound/outbound capacity. Streams and buffers additionally reserve one path for each of outbound control, inbound control, outbound data, and inbound data at every scope; general work and the other classes cannot borrow them. All file overflow is summed rather than checked pairwise and may spend only the borrowable remainder; one general/RPC stream and one control-frame buffer are never borrowable by file traffic. The minimum stream quota is therefore five. The minimum buffer quota is three maximum control frames plus two data buffers, where each data buffer is `max(maxControlFrameBytes, maxFileChunkSize + 64 KiB)`. Principal limits prevent endpoint-key rotation or multiple devices for one service identity from multiplying workload limits.

Diagnostics report logical admission state. Closing the scheduler rejects new and queued work but deliberately retains active leases until their owners settle; it cannot manufacture a leak-free zero. A connection-terminal event can end logical stream ownership, while native handle return-to-baseline remains a separate production gate.

Receiver-side push reconciliation uses two node-lifetime stores partitioned by peer and keyed by the complete canonical principal plus transfer ID. The hard store contains `active` work and `committed` outcomes whose acknowledgement is ambiguous. Its default caps are 1,024 per peer (`maxFileReconciliationRecords`), 1,024 per canonical principal across endpoint keys (`maxPrincipalFileReconciliationRecords`), and 4,096 node-wide (`maxGlobalFileReconciliationRecords`). Active records never expire; committed records default to a 15-minute TTL. Reaching any hard cap rejects a new operation and never evicts active/ambiguous evidence.

After a valid sender receipt, an acknowledged outcome moves to the replay-tombstone store; rejected terminal outcomes also use it. Its default caps are 1,024 per peer, 2,048 per principal, and 8,192 node-wide (`maxFileReplayTombstones`, `maxPrincipalFileReplayTombstones`, and `maxGlobalFileReplayTombstones`). At capacity, the oldest tombstone in the applicable peer/principal/node scope is evicted, so tombstones never consume hard capacity or block unrelated acknowledged throughput. An indexed minimum-deadline heap removes only expired committed records/tombstones instead of scanning every scope. Both stores survive physical connection replacement and same-process runtime revival. Committed reconciliation lasts until process loss or TTL; acknowledged/rejected replay protection lasts until the earliest of process loss, TTL, or bounded eviction. Node close stops new ledger admission before clearing state only after its owned work settles. Application authorization still runs on every offer.
