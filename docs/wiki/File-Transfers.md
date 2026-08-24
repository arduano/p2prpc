# File transfers

File bytes never enter tRPC or SuperJSON. tRPC may return a typed `SharedFileHandle`; the same authenticated peer then uses a separate binary transfer protocol on parallel QUIC streams.

## Push API

```ts
const receiver = await createP2PNode({
  // router, protocol, security, createContext...
  onIncomingFile: async (offer) => {
    if (offer.principal.tenantId !== 'tenant-a') {
      return { reject: 'tenant policy' };
    }
    // offer.manifest.name is untrusted and is never used as this path.
    return { accept: fileDestination('/srv/quarantine/incoming.bin') };
  }
});

const transfer = await peer.files.sendFile(await fileSource('/srv/export/report.pdf'));
for await (const progress of transfer.progress()) updateUi(progress);
await transfer.result;
```

The offer contains a verified principal/session ID and a signal tied to this authenticated attempt. Its manifest remains untrusted until exact-field/accessor checks, geometry and digest bounds, a detached plain-data metadata snapshot, and the optional metadata schema all pass. The schema never receives a live decoder-owned or peer-accessor object.

## Pull capability API

```ts
// Inside an authorized tRPC procedure on the serving peer:
const handle = ctx.p2p.files.share(
  await fileSource('/srv/export/report.pdf'),
  { expiresAt: Date.now() + 60_000, maxDownloads: 1 }
);

// Send `handle` as an ordinary typed tRPC result. On the requester:
const transfer = await peer.files.download(
  handle,
  fileDestination('/home/service/downloads/report.pdf'),
  { operationId: durableRedemptionId }
);
await transfer.result;
```

The request facade closes over the exact authenticated session and rejects after replacement or expiry. It automatically binds the handle to `ctx.p2p.peer.id` and the complete principal tuple; it does not accept arbitrary bindings or a bearer flag. `peer.files.share()` provides the same safe derivation for local code already holding a peer. Advanced registry policy is available only through `/advanced` and becomes part of the application security review.

Omit `operationId` to generate a fresh random capability redemption. Supply and persist it only when the same logical download must reconnect or be reconciled; reusing it with another endpoint, principal, token, chunk size, or lane count fails. This pull option is deliberately distinct from `SendFileOptions.transferId`, which is the manifest ID for a push and may be reused only for the exact same push manifest.

## Source integrity

`fileSource()` rejects non-regular files and symlinks, captures device/inode/size/timestamps, and later opens one no-follow descriptor for the prepared lifecycle. The same validated handle stays open for manifest hashing and every transmitted read. Identity is rechecked so path replacement or mutation cannot swap bytes between authorization/hash/send.

A fresh transfer deliberately makes one sequential hash pass before sending its offer, then reads the chunks the receiver reports missing. This gives authorization, resume, and final verification one stable content identity, at the cost of O(file size) time-to-offer and roughly two source reads when no chunks are already present. It is an explicit integrity/resume tradeoff, not a claim of single-pass transfer startup.

Custom sources must honor abort, return the exact requested chunk, and close prepared resources promptly.

## Destination integrity

`fileDestination()` never derives its path from a remote name. It owns explicit `.part`, `.state`, and `.lock` files using no-follow checks and stable file identities. Resume state is a bounded binary v3 format, not attacker-controlled JSON. Chunks are range-checked, digest-checked, written with bounded segments, and durably recorded.

Before publication, the destination recomputes the complete BLAKE3 digest over staged bytes. Publication is atomic and defaults to durable sync. Existing targets are not overwritten unless explicitly requested. Integrity/policy failures discard unsafe state; transport failures may retain securely validated resume state. Descriptor, staging, resume, lock, or post-commit sync failures are surfaced; a failure after publication is `OUTCOME_UNKNOWN`, never a false success with silently abandoned cleanup.

Custom destinations must perform equivalent complete verification immediately before atomic publication, check `context.signal` immediately before committing, and call `context.markCommitted()` synchronously just after publication and before any fallible cleanup. That explicit boundary lets p2prpc distinguish a safe pre-commit rejection from post-commit cleanup uncertainty; omitting it fails closed without acknowledging the transfer.

## Streams and backpressure

One control stream negotiates the exact manifest, resume bitmap/ranges, transfer fingerprint, and terminal result. A bounded lane plan assigns missing chunks without a per-chunk promise array. Each data lane owns its unidirectional stream through finish or reset, including a stream that resolves after cancellation. Reads, writes, hashes, and stream buffer leases are chunk-bounded.

At global, peer, and principal scopes, the scheduler has four non-borrowable stream/buffer reserves: outbound control, inbound control, outbound data, and inbound data. A class uses its own reserve first; excess control/lanes share only the general remainder with RPC and all other excess. A valid configuration admits those four paths plus one general/RPC stream, so every stream ceiling is at least five. Its buffer ceiling admits three maximum control frames plus both data buffers; each data buffer is the larger of a control frame or one maximum chunk plus 64 KiB. These invariants keep symmetric peers from consuming one another's only control or lane progress path.

`streamIdleTimeoutMs` is a no-progress deadline, not a maximum transfer duration. The receiver reads control concurrently and refreshes its session watchdog for lane admission, every chunk header, each 64 KiB body segment, a completed destination write, lane FIN, and terminal progress. Healthy large or slow transfers may therefore run longer than the idle interval; a stalled segment, callback, lane, or terminal exchange still times out.

Progress delivery is independent and conflated for every iterator. A slow consumer retains at most the newest snapshot and cannot delay or fail the transfer. Node-level progress hooks are also best effort.

## Logical operations and retries

`maxDownloads` counts distinct pull operation IDs, not network attempts. The capability registry stores hashed IDs in a bounded global table. A disconnected reservation receives a fixed, bounded reconnect lease and attempt limit; reconnect requires the same endpoint, complete principal, operation ID, chunk/lane fingerprint, and fresh file authorization.

Every delivery has private retry provenance scoped to its exact connection attempt. Only a typed transport-loss event observed by that current attempt, before a possible commit, can become a retry candidate. Application callbacks see ordinary sanitized `P2PError` reasons rather than retry markers: retaining and rethrowing an earlier attempt's reason, constructing a `DISCONNECTED` error, or triggering an untyped connection abort is terminal and cannot cause redial.

For a shared pull, a candidate becomes a retry result only after every current-attempt stream has drained and its prepared source has closed; the reservation remains active while cleanup is pending. The retry coordinator consumes that explicit result and never derives authority from a later thrown error. Failed stream/source cleanup consumes the capability terminally, with source-cleanup uncertainty reported as `OUTCOME_UNKNOWN`. Policy, shape, integrity, local I/O, and application errors are also terminal. Every file delivery in wire v4 closes with this receipt exchange:

1. The sender sends `Complete` but keeps its send half open.
2. The receiver drains every lane through FIN, verifies, and atomically finalizes the destination.
3. The receiver records the committed outcome, then sends `Complete` with a fresh 256-bit `receiptToken`.
4. The sender validates that completion, making success permanent, echoes the token in `Receipt`, and sends FIN.
5. The receiver validates the receipt and sender FIN, then sends FIN.

For a push, loss after the sender begins step 1 but before step 4 produces sender `OUTCOME_UNKNOWN`; the application must reconcile rather than blindly retry. A retry with the same authenticated principal, `transferId`, and exact manifest can replay the completion exchange without invoking destination callbacks. After either side knows local/remote publication succeeded, later receipt or stream-cleanup failure cannot turn success into failure; the physical connection is quarantined if cleanup cannot be proved.

Receiver-side push state lives in a node-lifetime ledger. Hard `active` and acknowledgement-ambiguous `committed` state defaults to 1,024 records per peer, 1,024 per canonical principal across endpoint keys, and 4,096 node-wide. These are `maxFileReconciliationRecords`, `maxPrincipalFileReconciliationRecords`, and `maxGlobalFileReconciliationRecords`; a full applicable scope rejects new work and never evicts hard state. Active entries do not expire, while committed entries use `fileReconciliationTtlMs` (default 15 minutes).

A valid receipt moves success to the replay-tombstone store; terminal rejection also uses it. `maxFileReplayTombstones`, `maxPrincipalFileReplayTombstones`, and `maxGlobalFileReplayTombstones` default to 1,024, 2,048, and 8,192 respectively. Tombstones evict oldest-first at an applicable bound and never consume hard capacity, so acknowledged throughput is not limited to the hard-record TTL. Expiry processes only due entries through a deadline index. The ledger survives physical connection replacement and same-process runtime revival, allowing an exact principal/manifest/`transferId` replay to reconcile on a new connection. Node shutdown rejects new ledger admission and retains existing evidence until owned transfers settle. Protection ends at the earliest of process loss, TTL, or—only for acknowledged/rejected state—bounded tombstone eviction. Authorization still runs on every offer. This is process-local reconciliation, not crash-durable exactly-once delivery.

## The 10,000-file invariant

The required production gate sends 5,000 pushes and 5,000 peer/principal-bound capability pulls over one authenticated physical QUIC connection, split between sequential and concurrency-16 phases. Qualifying evidence must checkpoint stream halves, scheduler leases/queues, transfer/reconciliation/share/task state, native handles, file descriptors, memory, event-loop delay, and RPC canaries; fault phases must cover cancellation, rejection, I/O failure, timeout, reconnect ambiguity, and lost receipt.

The checked-in driver validates p2prpc ownership and protocol integration, not Iroh throughput. Its eligibility flag covers the exact count/profile and required diagnostics, but the current driver does not automate every required fault or mixed-load measurement. A local, loopback, mocked, reduced, reconnecting, or diagnostics-incomplete run is not production evidence. The first npm release remains blocked until the exact candidate produces the remaining protected external evidence and the separate two-host discovery/relay matrix in [Production Validation](Production-Validation.md); this repository does not claim that evidence has already been obtained.
