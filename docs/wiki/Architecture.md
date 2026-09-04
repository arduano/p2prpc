# Architecture

p2prpc keeps routing, transport identity, application identity, authorization, RPC, and bulk bytes as separate layers. The separation is the main correctness mechanism.

## Layers

```text
application procedures and storage policy
─────────────────────────────────────────
tRPC runtime schemas and middleware
  reads verified ctx.p2p + untrusted request headers
─────────────────────────────────────────
p2prpc operation policy
  authorize RPC path/type or file push/pull
─────────────────────────────────────────
p2prpc wire v4 session
  mutual credential-handshake v3 and expiring principal
─────────────────────────────────────────
managed QUIC streams
  admission, buffering, priority, cancellation, exact cleanup
─────────────────────────────────────────
Iroh QUIC
  encryption, endpoint key proof, multiplexing, relay/direct paths
─────────────────────────────────────────
locator/discovery
  signed ticket, DNS/PKARR, or mDNS reachability hints
```

No lower layer silently grants the authority of a higher one. In particular, knowing a node ID or ticket cannot dispatch application work.

## One connection, independent streams

Each RPC owns one bidirectional stream. A file operation owns one bidirectional control stream and a bounded number of unidirectional data lanes. There is no application-level shared write lock, so a slow file lane cannot serialize unrelated RPC traffic. QUIC provides transport flow control; the scheduler bounds work before opening outbound streams or dispatching accepted inbound streams.

Locally opened streams pass through `ManagedConnection`. Its lease remains until both halves reach a terminal operation. A pre-aborted open never reaches native QUIC. Once native opening begins, cancellation rejects the caller promptly and quarantines the multiplexed physical connection; admission remains charged until native rejection, terminal cleanup of a late stream, or fulfilled physical closure. A rejected `closed()` observation is not proof and releases nothing. Inbound streams acquire admission before their kind is dispatched.

Connection/session owners and receiver commit ownership are deliberately different. A replacement connection gets a fresh authenticated session and transfer manager, while the receiver reconciliation ledger belongs to the node. This lets exact push retries reconcile across physical replacement and same-process runtime revival without carrying streams, session signals, or other connection resources forward. Hard records are bounded per peer, canonical principal, and node and cannot be capacity-evicted; replay tombstones use separate evictable bounds at those scopes. Deadline-indexed expiry avoids a whole-ledger scan on each request. The ledger is process-local, not crash-durable.

File retry authority is connection-attempt-local and never travels through an application-visible exception. Only a typed transport-loss observation made by the current attempt can become a retry candidate, and it becomes retryable only after that attempt proves its streams drained and its prepared source closed. Callbacks receive ordinary sanitized errors, so retaining or rethrowing an earlier attempt's abort reason cannot authorize a later retry.

## Correctness by construction

The implementation uses these design rules rather than scattered recovery branches:

1. Validate exact keys and bounds at every wire/configuration boundary.
2. Snapshot caller-owned configuration and identity values before the first relevant `await`.
3. Give each stream, callback, transfer, prepared source, destination reservation, and capability operation one owner.
4. Release ownership exactly once in a terminal path; late native results are still closed.
5. Carry retry decisions as private attempt-local outcomes, never infer them from caller-visible errors or error codes.
6. Admit memory/concurrency before starting expensive work.
7. Treat transport failure after a mutation or transfer commit boundary as `OUTCOME_UNKNOWN`, never as permission for an implicit retry.
8. Keep route discovery separate from expected endpoint and principal trust.

MessagePack bodies are byte-, item-, and depth-limited. RPC values use a private SuperJSON codec with an acyclic built-in-only wire model; global application transformers, classes, symbols, aliases, and cycles are excluded. Outbound shape is preflighted before SuperJSON or MessagePack allocation. Inbound MessagePack is scanned before decoding, then annotation targets are semantically checked before built-in values are constructed.

## Scheduling and backpressure

The node has a peer-fair scheduler with global, endpoint, and principal ceilings for:

- handshakes;
- streams;
- outbound and inbound transfers as separate resources;
- library-controlled frame/chunk buffers;
- application callbacks;
- queued admission requests.

Principal quotas are applied after authentication and aggregate all endpoint keys for that identity. Transfer admission is direction-separated. At every quota level, streams and buffers have four independent file reserves: outbound control, inbound control, outbound data, and inbound data. General work and the other directions cannot consume a file reserve. Each file class spends its own reserve first; all file overflow is summed into one borrowable pool, so idle reserves are never double-counted. File overflow cannot borrow the final general/RPC stream or its control-frame buffer. Configuration must therefore admit that protected general path plus all four file paths, and three control-frame buffers plus both data buffers. A data buffer covers the larger of a control frame or one maximum chunk plus its 64 KiB segmented-read transient.

An accepted bidirectional stream must reveal its kind before the scheduler knows whether it is RPC or file control. One sequential accept loop per authenticated connection reads exactly that one byte under the header deadline, so at most one BI stream per connection exists before admission. It then tries the stream's real class directly: RPC uses general capacity and file control uses the inbound-control class. Saturated classes are load-shed instead of queued in the accept loop, and a blocked general waiter cannot hide an available directional reserve. Malformed, late, or uncleanable classifiers are terminated or quarantine the connection. This makes symmetric control and lane progress a quota invariant rather than a task-ordering assumption. Lanes allocate from a bounded bitmap/range plan. Progress observers see independent conflated iterators, so a slow observer retains only the latest event and cannot block transport progress.

`maxBufferedBytes` is deliberately narrow and auditable: it accounts for simultaneous library-controlled handshake frames (64 KiB per admitted handshake), control-frame/RPC serialization buffers owned by an admitted stream, and file chunks owned by data streams. It does not claim to cap caller-owned input that already exists, application procedure/database memory, native QUIC flow-control buffers, or operating-system caches. Those require process/container limits and the native memory gate.

## Application work

Cancellation is cooperative in JavaScript: aborting a signal cannot kill an arbitrary application promise. p2prpc stops wire work promptly and retains ownership/accounting for registered callback or procedure work until it actually settles. Applications must observe supplied signals for prompt shutdown. Closing admission rejects queued/new work but retains active ownership; shutdown cannot undo side effects already started inside non-cooperative application code. `Peer.close()` and `node.close()` wait up to `shutdownTimeoutMs`, then reject with `TIMEOUT` while the still-live task/resource ledgers remain truthful. Node shutdown also closes receiver-ledger admission synchronously, but clears its reconciliation evidence only after all node-owned work actually settles.

## API compartments

| Import | Intended use |
|---|---|
| `@arduano/p2prpc-core` | Production-safe branded security factories, nodes, peers, metadata, and files. |
| `@arduano/p2prpc-core/advanced` | Custom security/transport seams and raw protocol components; part of the deployment TCB. |
| `@arduano/p2prpc-core/testing` | Injected endpoints and explicitly insecure sessions. Never ship in production code. |

The alternate transport seam has a fail-closed shape check, but transport semantic conformance still requires the repository integration/lifecycle suite. Raw adapters must ignore managed stream-open options: the wrapper owns cancellation while continuing to observe the native promise, because an adapter must never reject early while a hidden native open can still produce a stream. `closed()` must fulfill only after the physical connection and all native streams are terminal, must expose one shared lifecycle to every caller, and must reject—not fulfill—if closure cannot be observed. A rejection is diagnostic failure, never closure proof; p2prpc then retains admission rather than reporting false quiescence.

`onPeer` is a best-effort notification and is never a correctness dependency. Applications can inspect `peersSnapshot()` and obtain a current authenticated handle with `getPeer()`; session-bound file issuance inside a procedure uses `ctx.p2p.files` directly. Inbound `Peer` objects are scoped to their authenticated session, so a durable reverse-RPC binding stores the pinned endpoint ID and resolves `getPeer()` at dispatch time instead of retaining an `onPeer` object across expiry and reauthentication.

A disconnected outbound runtime retains only its frozen locator/endpoint/principal expectations and may be revived by a matching authenticated inbound connection. Initial installation, replacement, revival, duplicate arbitration, and outbound reconnect all converge on one admission-success gate after synchronous callback-capable work. The gate requires an open node, registry ownership, live-map membership, the exact current epoch, and an unexpired session; public promise continuations recheck it after their last `await`, while queued `onPeer` delivery rechecks the captured exact selection. A callback that closes the node or selected peer therefore makes acquisition reject `DISCONNECTED` instead of returning or notifying a dead handle. Endpoint admission, mutual authentication, exact canonical-principal comparison, session expiry, and operation authorization are still rerun. A purely inbound runtime has no trusted dial target and closes with its connection.

## Known transport boundary

Iroh path selection can migrate between relay and direct routes without changing the authenticated endpoint or application session. Remote ticket direct routes and default-network relay hints require explicit egress decisions; custom relays use configured canonical-origin membership. Policies receive immutable candidates and fail closed if absent or throwing. With the pinned wrapper, DNS-resolved candidates cannot be inspected before dial, so DNS plus custom relay or address callbacks is unsupported rather than weakly filtered. Relay-disabled endpoints keep direct UDP networking but advertise/select no relay; a version-locked compatibility seam corrects the wrapper's conflation of “no relay” with its loopback-only test mode and fails closed when that assumption changes.
