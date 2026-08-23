# Lifecycles

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md) · [Audit guide](Audit-Guide.md) · [Validation](Production-Validation.md)

## Node and peer runtime

```text
create node
  → validate and snapshot configuration
  → create Iroh endpoint and accept loop
  → outbound: validate/snapshot target, resolve locator for expected endpoint, dial
    inbound: accept physical connection
  → outbound: verify connected endpoint matches expectation
  → optional endpoint-key admission (before credential retrieval)
  → mandatory application handshake
  → outbound: verify authenticated principal matches expectation
  → install peer runtime and stream loops
  → active
  → disconnected | replaced | expired | explicitly closed
```

Node configuration is snapshotted at creation so later mutation of the options object cannot widen security policy. Each outbound `ConnectOptions` object and nested principal matcher is likewise validated and snapshotted before any dial. Unknown fields are rejected rather than ignored. `P2PNode.close()` is terminal.

A `Peer` represents one logical remote endpoint and its current authenticated connection. `Peer.close()` permanently retires that local handle. To reconnect from that side, call `node.connect({ locator, expectedPeerId, expectedPrincipal })` explicitly for a new handle; the remote endpoint may independently establish a later inbound runtime.

## Mutual session handshake

```text
Initiator                                      Responder
   │ ClientHello(protocol, nonce A, credential A)  │
   ├──────────────────────────────────────────────>│ verify A
   │ ServerHello(nonce B, echo A, credential B,    │
   │             grant)                            │
   │<──────────────────────────────────────────────┤
verify B                                          │
   │ ClientAck(echo B, session ID, grant)          │
   ├──────────────────────────────────────────────>│ derive same ID
   │ ServerReady(session ID, final expiry)         │
   │<──────────────────────────────────────────────┤
   │              application streams enabled     │
```

Both nonces are 256-bit random values. The session ID is domain-separated SHA-256 over the protocol, both endpoint IDs, and both nonces. Final expiry is bounded by both credential grants and the local maximum session TTL. The handshake is time-, size-, item-, and depth-bounded.

The first accepted bidirectional stream must be session authentication, and RPC/file dispatch loops do not start before it completes. A raw peer which opens an RPC or file stream first is rejected.

## Connection replacement and reconnect

| Event | Result |
|---|---|
| Simultaneous or duplicate connection | Deterministic connection preference retains one; the other closes. |
| Valid replacement | Old session signal aborts; active RPC/file work is cancelled; new stream loops and expiry are installed. |
| Principal change on the same endpoint runtime | Replacement is rejected. |
| Session expiry | Connection and all session-bound work close. |
| Outbound runtime loses its connection | The next operation redials the snapshotted locator: it reuses a signed ticket or re-resolves DNS/mDNS, then rechecks the connected endpoint, reruns admission/authentication, and matches both the retained expected principal and the runtime's prior principal. |
| `Peer.close()` | The complete outbound target (locator, expected endpoint, and principal matcher) is discarded and implicit reconnect is permanently disabled for that handle. |

Reconnect retains the exact immutable outbound target, but never carries an authenticated session forward. It repeats locator/endpoint binding, endpoint admission, authentication, and expected-principal checks before installing a fresh session. Each retried or subsequent RPC/file control request is then separately authorized; connecting by itself does not authorize an operation.

A caller sharing a ticket should use `await node.createTicket()`, which samples current direct addresses and the home relay before signing. `node.ticket()` signs the endpoint's cached route snapshot for compatibility. DNS/PKARR and mDNS are dynamic locators and therefore look up the retained expected endpoint again on each physical reconnect. When DNS is enabled on the endpoint, native Iroh may also use it as fallback while reconnecting a ticket- or mDNS-bootstrapped target.

## RPC lifecycle

```text
typed proxy call
  → snapshot and normalize default + per-call metadata
  → acquire active authenticated connection
  → open one bidirectional RPC stream
  → send kind + bounded request frame
  → server validates path/type/headers
  → operation authorization
  → create frozen request context
  → tRPC input parsing and procedure/middleware dispatch
  → data frame(s) → complete, or sanitized error
  → stop/reset/finish stream cleanup
```

Queries and mutations return one data result; subscriptions may return many. Cancellation, stream failure, connection replacement, session expiry, and node shutdown abort the request signal.

After a terminal `Complete` or `Error` frame, the client requires a clean response FIN before it reports completion or the remote error. Unexpected trailing bytes or a missing FIN fail the call; terminal cleanup then FINs the request side and releases both stream handles.

RPC calls are not automatically replayed after a disconnect. A mutation can complete remotely while its response is lost, so unsafe mutations require durable application-level idempotency keyed by verified identity, tenant, procedure, and a caller-supplied idempotency key.

## File lifecycle summary

```text
source or capability
  → strictly parse offer manifest or pull request
  → authorize push or pull operation
  → push: receiver admission + destination
    pull: capability lookup/reservation + source manifest
  → receiver creates attempt ID + lane token
  → transfer missing chunks over bounded lanes
  → verify each chunk and whole staged file
  → atomically publish
  → receiver acknowledges completion
```

File operations retry only transport disconnections, up to five times with backoff. Pull reconnect also requires the same logical operation, endpoint, full principal binding, and negotiated chunk/lane fingerprint within its fixed lease. See [File transfers](File-Transfers.md).

## Cleanup ordering

Success and abort are cooperative but ordered. On success, the receiver consumes every data-lane FIN before it finalizes the destination, publishes the file, and acknowledges completion. A valid control completion cannot overtake lane cleanup merely because QUIC streams are independently scheduled.

On failure, the receiver first writes and FINs a bounded, sanitized rejection on the control stream. It then aborts the attempt, stops or resets its lanes, waits for every claimed lane handler and callback such as `writeChunk()` to settle, and finally calls destination cleanup. Sending the rejection first prevents a racing lane `STOP_SENDING` from disguising a terminal destination failure as a retryable disconnect; waiting last prevents a timed-out custom adapter write from publishing after `abort()` or racing a retry against the same destination.
