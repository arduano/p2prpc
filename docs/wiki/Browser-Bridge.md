# Browser Peer and trusted Gateway bridge

The Host owns its actual tRPC router. A browser infers its caller from that router;
the Gateway does not copy procedures, unpack RPC envelopes, or spool files.
The bridge is an opt-in stream service. Existing native RPC/file formats, native
pins, authentication handshakes, and direct Peer use remain unchanged.

```text
browser /browser entry             Gateway /bridge entry               Host
connectBridge<HostRouter>()         authenticate HTTP upgrade            native onBridge
  actual inferred rpc              authorize requested Host             createBridgeHost
  existing file protocol           relayBridge(socket, peer, headers)    actual router
          binary WebSocket ────────────────┘          Iroh Bridge stream ───┘
          standard Yamux logical streams carry existing RPC/control/data bytes
```

## Public contracts and module ownership

| Boundary | Contract | Owner and state |
| --- | --- | --- |
| Browser | `connectBridge`, `ConnectBridgeOptions` in `src/bridge/client.ts` | One retained engine, private resume secret, one admission attempt at a time |
| Gateway | `relayBridge` in `src/bridge/gateway.ts` | Two bounded byte pumps and one owned stream, borrowing its authenticated native Peer |
| Host | `createBridgeHost`, `BridgeHostOptions` in `src/bridge/host.ts` | Delegation, logical peer registry, expiry and revocation |
| Logical Peer | `src/bridge/contracts.ts` | Existing RPC/file engines, shares, reconciliation ledger, callback/resource ownership |
| Carrier | `src/bridge/transport/contracts.ts` | Backpressured binary channel and positive closure proof; standard Yamux framing/credit |
| Native service | `NativeBridgeOffer`, `OpenBridgeOptions` in `src/bridge/native.ts` | Versioned stream admission on the actual authenticated Iroh connection |
| Browser file IO | `src/files/browser.ts` | Immutable Blob source; explicitly bounded memory destination |

The native entry still owns filesystem IO and intrinsic Proxy detection. Shared
algorithms live in portable RPC/file modules, with no second RPC implementation,
alternate codec, or browser transport polyfill. Import browser runtime code from
`@arduano/p2prpc-core/browser`, and router definitions with `import type`.
Native Host/Gateway helpers are in `@arduano/p2prpc-core/bridge`.

For a portable file-only library, import contracts and Blob/memory helpers from
`@arduano/p2prpc-core/files` instead. This leaf excludes RPC and native endpoint
dependencies from both JavaScript and declarations:

```ts
import { blobSource, memoryDestination } from '@arduano/p2prpc-core/files';
import type { PeerFiles, FileMetadataSchema } from '@arduano/p2prpc-core/files';
```

It uses the same `PeerFiles` and transfer contracts as the native and browser
Peers. It adds no transport, transfer engine, or filesystem adapter. CI compiles
an actual built-entry consumer with DOM libraries and no ambient Node types, and
bundles its runtime for the browser while rejecting Node, tRPC and Iroh imports.

## Host and Gateway composition

```ts
import { createP2PNode } from '@arduano/p2prpc-core';
import { createBridgeHost, relayBridge } from '@arduano/p2prpc-core/bridge';

const bridge = createBridgeHost({
  router: hostRouter,
  createContext: ({ bridge }) => ({ user: bridge.principal.subject }),
  authorizeDelegation: async (offer) => {
    // Verify offer.peer.id AND offer.auth.principal against a trusted Gateway
    // directory, then resolve the delegated user from its verified assertion.
    // Headers alone are never proof of identity.
    return directory.resolveDelegation(offer);
  },
  authorizeOperation: ({ principal, action, via, signal }) =>
    policy.allow({ principal, action, via, signal }),
  onIncomingFile: receiveAuthorizedFile
});
const host = await createP2PNode({
  ...nativeHostOptions,
  onBridge: bridge.accept
});

// In an authenticated, origin-checked WebSocket upgrade handler:
// Select an allowed Host from server-owned routing, never an arbitrary URL.
await relayBridge(socket, authenticatedHostPeer, {
  headers: { 'app-user': verifiedSession.userId },
  signal: requestLifetime.signal
});
```

The application supplies its own HTTP/WebSocket server and login policy. Do not
accept upgrades until authentication, origin/CSRF checks and Host routing policy
succeed. Cookies/token acquisition and persistence are application responsibilities.
The native session's authorization policy must independently allow `bridge`.
OIDC requires `p2prpc:bridge` (or `p2prpc:*`); file-pull scope cannot grant it.
Shared-secret deployments still have their explicit custom authorization policy.
`AuthorizationAction` gains `bridge`; update exhaustive application policy switches
to explicitly deny or allow it. Existing native RPC/file behavior is retained.

Both the actual Gateway endpoint/principal and the delegated user are verified
before logical admission. Every RPC, push and capability pull uses the same
immutable delegated principal and actual Gateway provenance. The effective grant
expires at the earlier Gateway/delegated expiry. Host policy must enforce its own
RPC/file scopes and tenant permissions; there is no guessed intersection of
unrelated Gateway/user scope names.

This is trusted delegation with TLS and Iroh hop encryption. It is not
browser-to-Host end-to-end cryptographic authentication/encryption: the Gateway
can see or change traffic and may assert users only within its trusted policy.

## Browser caller and binary files

```ts
import { connectBridge, blobSource, memoryDestination } from '@arduano/p2prpc-core/browser';
import type { HostRouter } from './host-router.js';

// Keep this owner outside mounted React views; unmounting a listener is not close.
const peer = await connectBridge<HostRouter>({
  url: 'wss://gateway.example/hosts/work',
  expectedHostId: trustedHostEndpointId
});
const receipt = await peer.rpc.session.send.mutate({ requestId, text });
const handle = await peer.rpc.files.preview.query({ fileId });
const destination = memoryDestination({ maxBytes: 8 * 1024 * 1024 });
const download = await peer.files.download(handle, destination);
await download.result;
const preview = destination.blob();
const upload = await peer.files.sendFile(blobSource(selectedFile, { name: selectedFile.name }));
await upload.result;
```

The examples' procedures and directory/policy are application-defined; p2prpc
does not invent a Host router. Normal tRPC inference rejects unknown paths and
incorrect input types. Host procedures can issue capability handles through
`ctx.bridge.files.share`; control/data bytes use existing p2prpc file lanes.
Browser inbound file pushes require explicit `incoming`. Reverse RPC additionally
requires explicit `local` router/context and `authorize`. Browser-local routers
use tRPC’s official `initTRPC.create({ allowOutsideOfServer: true })` option;
default browser policy
only allows capability pull and explicitly configured incoming files.

Subscriptions use existing p2prpc subscription semantics. Nested Promise or
AsyncIterable fields in query/mutation results are not supported by the existing
p2prpc wire codec. This bridge does not claim tRPC HTTP JSONL transport parity.

## Loss, resume and effect ownership

1. A fresh admitted browser gets a random logical peer ID and a separate opaque
   server-issued resume secret. The Host stores only its hash. The browser keeps
   the secret in its retained owner; it is not a public identity or log field.
2. A carrier loss ends that carrier's RPC observations and authorization epoch.
   It never stops a native agent or undoes an admitted effect. The actual Host
   procedure/callback remains charged until it settles, even after abort/timeout.
3. `reconnect()` or a later operation can admit a replacement carrier. An
   interrupted RPC is never transparently replayed; reconcile its original receipt
   through application state. The browser must explicitly recreate subscriptions
   and reconcile application history/cursors; the library does not infer them.
4. Reattachment requires the secret and the same complete stable delegated
   identity. Unknown, expired, revoked or cross-principal resumes fail closed.
   Prior carrier cleanup must positively complete before replacement; rejected
   closure is not proof and retains capacity. One active carrier per logical Peer.
5. The retained Host logical engine preserves shares and file operation ledgers
   across transport epochs. Existing file rules alone determine whether a
   transfer can resume safely; bridge reconnect does not grant retry authority.
6. `peer.close()` ends that browser owner. Host revoke/expiry/service close ends
   Host custody. None closes the borrowed Gateway Peer or other viewers. The
   Host retains disconnected entries until expiry/revocation, within `maxPeers`.
   Browser close is transport close, not immediate remote-registry deletion.

`peer.expiresAt` exposes the latest verified `BrowserReady` admission deadline in
Unix milliseconds. Successful carrier reattachment updates it; disconnection or
close does not invent a later deadline. Once it expires, close the retained
browser peer and authorize a fresh logical lifetime with `connectBridge` rather
than keep resending an expired resume secret. Application originals and history
remain authoritative; a new bridge lifetime never authorizes replaying a mutation.

A full browser reload loses the private owner/secret and creates a new logical
Peer. There is no durable browser crash/secret recovery promise. A Host process
restart loses its in-memory bridge registry and file ledgers. Durable application
idempotency/history remains authoritative across either process boundary.

## Resource and compatibility limits

- The native root entry retains Node 20.3+. The new optional `/bridge` Host and
  Gateway API requires Node 22+; its upstream message-stream engine uses
  `Promise.withResolvers`. Browser consumers require modern WebSocket, WebCrypto,
  Blob and `Promise.withResolvers` support (the real browser gate uses Chromium).
  There is no injected platform polyfill or React Native support.

- Host defaults to 32 retained logical peers. Each uses the existing bounded
  scheduler/TaskGroup; callbacks that ignore abort stay charged. Application
  policies should bound aggregate tenant work above these per-peer limits.
- Yamux defaults to 64 logical streams, 16 pending incoming pairs, 1 MiB maximum
  read, 8 MiB buffered/read reservation and 15-second pairing/header timeout.
  Two Yamux directions implement one logical bidirectional stream so send reset
  and receive stop remain independent. Numeric QUIC reset codes are not carried;
  stream priority is advisory because standard Yamux has no matching scheduler.
- Binary WebSocket queues, messages and native carrier packets are bounded.
  Write promises provide backpressure. The Gateway does not retain whole files.
- `memoryDestination` requires an explicit quota, at most 64 MiB; publication can
  temporarily use twice that quota plus protocol lane buffers. It verifies the
  complete BLAKE3 digest immediately before publishing and marking committed.
  Release destination/Blob references when no longer needed. No OPFS, disk spool,
  durable publication or unbounded browser cache is implied.
- Stream kind 5 is opt-in Bridge v1, with a bounded versioned request/accept and
  bounded browser hello/ready exchange. Old Hosts reject it; there is no automatic
  fallback to application RPC or old Host compatibility claim for Bridge calls.
- Native Iroh/ALPN/auth/file pins remain unchanged. Release qualification of
  relay reachability, proxies, mobile browsers or cross-machine loads is separate
  from local real-browser/Iroh integration evidence.
