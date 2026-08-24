# Lifecycles

Review lifecycle boundaries before reviewing individual error branches. Every long-lived object has one terminal owner.

## Node and peer

```text
create node
  -> snapshot and validate options/security/schema/relay policy
  -> create endpoint and start bounded accept loop
  -> authenticate connections
  -> install at most one preferred runtime per endpoint
  -> run independent RPC/file accept loops
close node
  -> mark terminal and abort admission
  -> revoke shares and transfer reservations
  -> reject new receiver-ledger operations
  -> close runtimes and endpoint
  -> join library-owned tasks
  -> clear receiver ledger after owned work settles
```

`Peer.close()` is asynchronous and terminal for that handle. It immediately removes the peer from the usable-peer view, prevents automatic reconnect, aborts the authenticated connection, and closes transfers. The runtime remains as a non-usable tombstone until its tasks, admission leases, and physical QUIC closure have actually settled; this prevents a same-ID reconnect from hiding old native work. A successful return proves settlement. A bounded `TIMEOUT` return leaves the tombstone and late work owned, and a later same-ID `node.connect()` rejects until settlement completes. After settlement, reconnecting requires a new explicit `node.connect()`.

`P2PNode.close()` applies the same ownership rule to receiver reconciliation. It immediately closes ledger admission, so shutdown cannot create new file-operation records. Existing transfer transitions retain the ledger until runtime tasks, transport closure, and resource ownership settle; only then is it cleared. If the public shutdown deadline returns `TIMEOUT`, that background settlement and retained evidence continue rather than being reported or erased as clean shutdown.

An outbound runtime may survive a physical disconnect and retains the same frozen locator expectations and canonical principal. It can be revived either by its own outbound reconnect or by a newly authenticated inbound connection for the same endpoint and exact principal; deterministic connection arbitration applies if both arrive. Every replacement repeats endpoint admission, the complete mutual handshake, principal comparison, and authorization. A purely inbound runtime has no trusted reconnect target and is removed when its connection closes.

Peer admission has one success linearization rule shared by initial installation, replacement, retained-runtime revival, duplicate arbitration, and outbound reconnect. A distinct endpoint still reserves its `maxPeers` slot before dial/authentication work starts. Replacement constructs one immutable epoch, publishes it as the runtime's sole live state, then aborts and closes the superseded epoch. All paths converge after synchronous security events, abort listeners, expiry scheduling, and adapter `close()` callbacks. Public promise continuations repeat the same gate after their last `await`; queued `onPeer` delivery repeats it for the exact captured selection. The gate succeeds only if the node remains open, the runtime still owns its registry slot and live-map entry, the exact selected epoch remains live, and its session is unexpired. If a callback closed the selected peer or node, acquisition rejects `DISCONNECTED`; terminal state always wins.

## Mutual session handshake

Wire/ALPN v4 carries this unchanged credential-handshake v3 sequence:

```text
initiator                                      responder
ClientHello(v3, protocol, nonce A, time A)  ->
                                             <- ServerChallenge(nonce B, echo A, time B)
ClientCredential(role/transcript proof)     ->
                                             <- ServerCredential(proof, grant B)
ClientFinished(session ID, grant A)          -> FIN
                                             <- ServerFinished(session ID, expiry) + FIN
```

The responder does not fetch or disclose its credential until the initiator credential authenticates. Both sides reject unknown fields, wrong roles/IDs/protocols, stale timestamps, nonce reuse shapes, transcript mismatches, excessive credentials, invalid expiries, trailing bytes, and incomplete finishes. A timeout aborts the handshake stream and the physical connection is not installed.

The session expires at the minimum verified grant, principal expiry, and configured maximum TTL. In the same timer turn, expiry removes the runtime from `getPeer()`/`peersSnapshot()` and aborts every RPC/file signal tied to that physical session. Native close and resource ownership may continue settling without making the expired session publicly usable.

## OIDC key lifecycle

Remote JWKS fetches time out after 5 seconds. A successful set is cached for 10 minutes; unknown-key refresh and failed-fetch retry use a 30-second cooldown. Static JWKs require explicit compatible `alg`; fetched keys may omit it, but a present value must be compatible/allow-listed and every fetched key has a bounded unique `kid`.

A newly rotated key may therefore wait for the unknown-key cooldown before refresh. A removed key can remain usable until an earlier successful refresh or the 10-minute cache expiry. Changing JWKS does not reauthenticate an established session: that session ends at its own token/grant/configured expiry. Deployments needing faster revocation require shorter lifetimes or authoritative online policy.

## RPC

```text
open/admit bidirectional stream
  -> stream kind + exact bounded Request
  -> authorize(path, type, headers)
  -> create frozen ctx.p2p
  -> parse input and dispatch tRPC procedure
  -> Data* then Complete, or one Error
  -> FIN/reset both halves and release ownership
```

The client never automatically retries an RPC. Cancellation before a complete request is `CANCELLED`; failure or cancellation after dispatch is `OUTCOME_UNKNOWN`. A mutation may already have committed. Applications should use durable idempotency keyed by verified principal/tenant, procedure, and a bounded caller key.

Setup and individual transport operations have deadlines. Waiting for a long-running procedure or the next subscription item is controlled by the caller's `AbortSignal`; there is no hidden 30-second response-liveness timer or protocol heartbeat.

RPC and file deadlines propagate into stream admission. Cancellation while queued removes the request without opening QUIC. If it races a native open that JavaScript cannot revoke, the caller still fails promptly, the physical connection is quarantined, and the stream/buffer lease remains owned until the native open rejects, a late stream is reset/stopped, or physical closure fulfills. This prevents repeated timed-out opens from silently exhausting a long-lived connection's capacity.

## Push transfer

```text
prepare one stable source -> hash -> manifest
  -> Offer on control stream
  -> authenticate/authorize and schema-validate at receiver
  -> application returns {accept: destination} or {reject: true|string}
  -> destination prepares/resumes and returns completed chunks
  -> sender opens bounded lanes, sends missing chunks, and finishes each lane
  -> sender Complete(attempt), keeping its control send half open
  -> receiver drains lane bytes/FIN, verifies, and atomically publishes
  <- receiver Complete(attempt, fresh 256-bit receipt token)
  -> sender Receipt(exact token) + FIN
  <- receiver validates receipt and sender FIN, then sends FIN
```

The receiver waits for every lane's bytes and FIN before `destination.finalize()`. The destination calls `markCommitted()` at its exact irreversible publication boundary. Before that signal a rejection is rollback-safe; after it, no later receipt or cleanup failure may call `abort()`, send `Reject`, or report receiver failure. The fresh receiver challenge prevents a sender from pre-sending a convincing acknowledgement-of-acknowledgement.

For a push, the receiver stores the committed principal/manifest outcome in a node-lifetime ledger before sending its completion. That ledger survives physical connection replacement and same-process runtime revival, so retrying the exact same `transferId`, principal, and manifest can reconcile without running destination callbacks again. Once the sender begins its terminal completion but never sees the receiver completion, it conservatively returns `OUTCOME_UNKNOWN`. Once it validates the receiver completion, success is permanent: it echoes the receipt and closes, and any later receipt/FIN cleanup failure quarantines the connection rather than changing success. A valid receipt lets the receiver replace its hard committed record with a bounded replay tombstone. Process restart loses this ledger; durable application state owns that crash boundary.

The source handle remains owned from hashing through transmission and always closes. The receiver's offered filename is display metadata only; the application chooses an explicit destination path.

The configured idle timeout is a no-progress deadline, not a total transfer duration. Receiver progress refreshes one session watchdog at lane admission, chunk headers, every 64 KiB body segment, successful destination writes, lane FIN, and valid completion transitions. Its control read runs concurrently without a fixed wall-clock deadline, so a healthy transfer may last through many idle-timeout intervals. Individual stalled network and application operations remain bounded.

## Capability pull

```text
authorized procedure: ctx.p2p.files.share(source, policy)
  -> registry stores token hash + automatic endpoint/full-principal binding
remote obtains handle (usually as typed tRPC data)
  -> peer.files.download(handle, destination, { operationId? })
  -> reserve the supplied stable or generated operation ID atomically
  -> transfer using the same authenticated file protocol
  -> commit once, or enter one bounded reconnect lease
```

The request file facade captures the exact session and rejects share/revoke after replacement or expiry. Expiry prevents a new/reconnecting reservation; explicit revoke aborts active reservations. A reconnect must repeat authentication/authorization and match endpoint, complete principal, operation ID, and transfer fingerprint. `DownloadFileOptions.operationId` identifies the capability redemption; it is not the push-only `transferId`. Process-local operation records prevent the serving peer from treating a replay as a fresh capability redemption; a process crash remains a durable application-reconciliation boundary.

A shared-pull reservation becomes reconnectable only after three facts are proven by the same connection attempt: the current authenticated transport reported a typed loss, every current-attempt stream drained, and the prepared source closed successfully. Retry authority is an internal attempt result, not an error subclass or code, and disappears with the attempt. Callback signals expose only sanitized ordinary errors; a retained earlier abort reason, an application-created `DISCONNECTED`, or an untyped connection abort is terminal. The reservation remains active while cleanup is pending. Failed stream cleanup or source cleanup consumes it terminally; cleanup uncertainty is `OUTCOME_UNKNOWN`.

## Cancellation and cleanup

Network cancellation closes both stream halves. File cancellation closes lane/control streams, prepared sources, destination state, and registry reservations. Failed receive state is retained only when secure resume is allowed; integrity or policy failures discard it.

Application promises cannot be forcibly terminated by `AbortController`. p2prpc retains their admission ownership until settlement, including after a timeout wins; application callbacks and procedures must cooperate with their signals. Closing admission rejects queued/new work but does not erase active leases. Close waits are bounded by `shutdownTimeoutMs`: expiry rejects `close()` with `TIMEOUT`, closes transport, and leaves non-cooperative tasks/resources visibly active rather than reporting a false clean shutdown. Production tests separately prove streams, handles, tasks, and memory return to baseline.
