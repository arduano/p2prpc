# @p2prpc/core

Type-safe tRPC calls, subscriptions, and resumable parallel file transfer over mutually authenticated Iroh QUIC sessions.

```bash
npm install @p2prpc/core @trpc/client @trpc/server
```

Requires Node.js 20.3 or newer and an ES module application. Native Iroh targets are glibc 2.34+ Linux x64/arm64, macOS x64/arm64, and Windows x64; Alpine/musl and older glibc distributions are not currently supported.

```ts
import { initTRPC } from '@trpc/server';
import {
  createP2PNode,
  createSharedSecretSecurity,
  p2pRpcContext,
  type PeerContext
} from '@p2prpc/core';

const t = initTRPC.context<PeerContext>().create();
const router = t.router({
  ping: t.procedure.query(({ ctx }) => ({
    pong: true,
    subject: ctx.auth.principal.subject,
    trace: ctx.request.headers.traceparent
  }))
});
type Router = typeof router;

const node = await createP2PNode({
  router,
  protocol: { applicationId: 'my-app', contractVersion: '1' },
  security: createSharedSecretSecurity(process.env.P2PRPC_SHARED_SECRET!, {
    // Coarse MVP policy; replace with application-specific authorization.
    authorize: () => true
  }),
  createContext: (context) => context
});

const peer = await node.connect<Router>({
  locator: { kind: 'ticket', ticket: remoteTicket },
  expectedPeerId: remotePeerId,
  expectedPrincipal: {
    id: remotePeerId,
    subject: remotePeerId,
    issuer: null,
    clientId: null,
    tenantId: null
  }
});
console.log(await peer.rpc.ping.query(undefined, {
  context: p2pRpcContext({ traceparent: '00-...' })
}));
```

`security` is required. A route, signed ticket, or Iroh peer ID authenticates only the transport endpoint and never grants application work. Outbound `connect()` accepts `{ kind: 'ticket', ticket }`, `{ kind: 'dns' }`, or `{ kind: 'mdns', serviceName? }`, and additionally requires a separately trusted endpoint ID and exact principal matcher. The matcher always specifies `subject`, `issuer`, `clientId`, and `tenantId`; `null` requires an optional field to be absent, and optional `id` adds the authenticator's canonical stable ID. These fields are not OIDC-specific: the shared-secret helper uses the remote endpoint ID for `id`/`subject` and leaves the other fields absent. Production OAuth deployments can use `createOidcSessionSecurity`, including strict issuer/audience/JWKS verification, mandatory operation scopes, a one-hour default/24-hour maximum token age, and default `cnf.jkt` binding to the Iroh endpoint key. Custom OIDC `authorize` policy can narrow those scopes but cannot grant a missing one.

Shared-secret authentication and operation authorization are separate: omitting the helper's `authorize` callback denies every RPC and file action. The example's `authorize: () => true` deliberately gives every authenticated secret holder the complete application surface; production policies should inspect the verified principal and requested action.

The signed ticket, DNS/PKARR result, or mDNS result supplies routes only; `expectedPeerId` independently selects the endpoint and is checked against the connected transport before credentials are requested. The initiator then presents its application credential before it can verify the endpoint's application principal; the required matcher is checked before the peer is installed or returned. Provision expectations independently of discovery, use short-lived peer/audience-specific tokens, and configure `preAuthorizePeer` when a broader endpoint-key allow-list or inbound admission rule is needed. The frozen target is retained across automatic reconnects: tickets are reused, while DNS and mDNS are resolved again. Use `await node.createTicket()` when sharing a ticket so its direct addresses and home relay are freshly sampled; legacy `ticket()` does not refresh route information.

Configure connectivity with `iroh.relay` (`default`, `custom` HTTPS URLs, or `disabled`). Enable `iroh.discovery.dns` before using the DNS locator; this is an endpoint-wide native lookup and may also be used after ticket or mDNS hints fail. `iroh.discovery.mdns` chooses a default service and automatic advertisement, while the mDNS locator itself explicitly starts browsing. Custom relays are relay-assisted and may upgrade to direct. For route-source isolation or filtered egress, use a separate DNS-disabled endpoint: signed-ticket and mDNS candidates can then pass through egress callbacks. Enabling DNS with `allowDirectAddress` or `allowRelayUrl` fails closed because the pinned wrapper cannot expose DNS-resolved candidates before dial. mDNS direct hints default to private/link-local/loopback ranges, default-network mDNS relay hints need an explicit callback, custom mode restricts relay hints to configured origins, and disabled mode rejects them. In exact-pinned `@momics/iroh-http-node` 0.6.0, disabled relays imply loopback-only networking, so this version makes no production relay-less support claim.

The exact-pinned `@momics/iroh-http-shared` 0.6.1 session sink needs a narrow native-writer compatibility seam. When `sendChunk` rejects, p2prpc invokes `finishBody` once on the opaque handle and preserves the original error; startup fails closed if the node wrapper resolves a different shared-package instance. Native-handle lifecycle assertions are part of the repository's 10,000-file production-validation gate.

RPC headers are normalized, frozen, and bounded, but remain caller-controlled. Credential, cookie, forwarding, origin/authority, proxy, and `p2prpc-*` namespaces are reserved. tRPC middleware should compare requested tenant or routing metadata with the verified `ctx.auth.principal`, never treat metadata itself as identity.

Use a distinct OAuth audience and required connection scope for each application/environment/trust domain. For non-idempotent mutations, use a bounded `idempotency-key` as caller-supplied replay-control input and atomically deduplicate by verified principal, tenant, procedure, and key; it is not authentication metadata. Node configuration is snapshotted at construction rather than dynamically widened by later options-object mutation.

`peer.close()` permanently retires that local handle, aborts its active request/file signals, and disables implicit reconnect. Reconnect from that side with an explicit `node.connect()` to obtain a new handle; the remote may independently create a later inbound runtime.

Files use a separately authorized control stream and bounded parallel data lanes; raw bytes do not pass through tRPC. Return a short-lived handle from an authorized tRPC procedure and bind it with `allowedPeerIds: [ctx.peer.id]` plus `allowedPrincipals: [ctx.auth.principal]`, then pass that typed result to `peer.files.download()`. Push handlers receive the verified principal, session ID, and attempt abort signal and select a local `fileDestination`. Transfer lanes bind to the exact authenticated connection and fresh attempt secrets; reconnects reauthenticate and reauthorize. Explicit capability revocation aborts active reservations, while passive expiry gates later reservations rather than acting as an exact active-transfer timer. The built-in destination verifies the complete BLAKE3 digest before atomic publication; custom destinations are trusted adapters and must provide the same final integrity and commit guarantees. Resolve authorized object IDs only inside service-owned source roots—never pass a remote path directly to `fileSource()`—and use only service-owned destination parents. Treat stale `.p2prpc.lock` files as live until operators prove otherwise.

`allowBearer: true` permits omission of the endpoint-ID restriction; an explicit `allowedPeerIds` list, session/file authorization, and capability limits still apply, and `allowedPrincipals` can retain an exact issuer/subject/client/tenant binding. The older `allowedSubjects` option is deprecated because subjects are issuer-scoped.

OIDC principal IDs are hashed from the verified issuer/subject/client tuple. Deployments upgrading from readable/delimiter IDs must migrate ACLs, database keys, cached grants, and audit correlation. Long-lived subscriptions also need application heartbeat/data within the default 30-second per-read timeout.

See the [repository README](https://github.com/arduano/p2prpc#readme), [security policy](./SECURITY.md), and [architecture wiki](https://arduano.github.io/p2prpc/) for the complete API, OIDC setup, file-transfer pattern, wire model, limits, threat model, validation contract, and migration notes.
