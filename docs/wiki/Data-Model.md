# Data model

[Home](Home.md) · [Architecture](Architecture.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md) · [Audit guide](Audit-Guide.md)

## Object graph

```text
P2PNode
├─ endpoint { endpointId, signed locator ticket }
├─ router + SessionSecurity + resource limits
├─ peerRuntime[endpointId]
│  ├─ current physicalConnection
│  ├─ authenticatedSession ──> remote SessionPrincipal
│  ├─ outboundTarget? { ticket, expectedPeerId, expectedPrincipal }
│  ├─ many independent RPC streams
│  └─ many bounded transfer attempts
└─ shareRegistry[SHA-256(capability token)]
   └─ shareEntry { FileSource, policy, logical operations }

transfer attempt
├─ exact physicalConnection + authenticatedSession
├─ FileManifest + FileDestination
├─ transferId + fresh attemptId + secret laneToken
└─ one control stream + N data lanes
```

## Identity is deliberately split

| Identity | Form | Lifetime | Use |
|---|---|---|---|
| Endpoint identity | Iroh Ed25519 public key / peer ID | Key lifetime | Transport authentication, route signing, optional admission allow-list, token proof-of-possession binding. |
| Application principal | `SessionPrincipal` | Credential lifetime | Authorization and audit subject. Includes issuer, subject, client, tenant, scopes, verified claims, and expiry. |
| Session identity | Transcript-derived SHA-256 ID | One authenticated physical connection | Correlates operations and uniquely names one handshake transcript. Runtime and exact-connection checks reject stale state. |

The endpoint ID says which key is connected. The principal says which workload or user the application trusts. The session ID says which fresh handshake instance established that relationship. Equality of one does not imply equality of the others.

When reusing or replacing one peer runtime, the endpoint ID and canonical principal tuple—ID, issuer, subject, OAuth client, and tenant—must match. A fresh session ID is always created. A later fresh inbound runtime has no historical comparison; durable endpoint-to-principal ownership must come from token key binding, a directory, or policy.

## Core records

| Record | Important fields | Interpretation |
|---|---|---|
| Locator ticket | `version`, `peerId`, direct socket addresses, relay URL, protocol, `issuedAt`, `expiresAt`, signature | Self-signed route bootstrap. It may disclose network topology and is neither enterprise identity nor authorization. |
| `ConnectOptions` | `ticket`, `expectedPeerId`, `expectedPrincipal` | Strict outbound target. It is validated and snapshotted before dialing; its expectations must come from a trusted source independently of the locator. |
| `PrincipalMatcher` | optional `id`; required `subject`, `issuer`, `clientId`, `tenantId` | Exact identity-provider-neutral match against the authenticated `SessionPrincipal`. `null` requires an optional field to be absent; optional `id` adds canonical-ID equality. There are no omitted-field wildcards. |
| `SessionPrincipal` | `id`, `subject`, optional `issuer`/`clientId`/`tenantId`, `expiresAt`, `scopes`, `claims` | Frozen output of the configured authenticator. The OIDC helper derives `id` from `[issuer, subject, clientId ?? null]`; tenant, scopes, claims, and expiry are not part of that ID. |
| `AuthenticatedSession` | `id`, `establishedAt`, `expiresAt`, `principal` | Local view of the remote party on the current connection. |
| `PeerContext` | `peer`, `auth`, `request`, `connection` | Frozen context seed for tRPC. Trusted identity and untrusted request data remain separate. |
| `RpcServerRequest` | `id`, `path`, `type`, `headers`, `signal` | One authorized stream-scoped request. Headers are normalized assertions, not credentials. |
| `FileManifest` | `transferId`, `name`, `size`, whole digest, chunk geometry, metadata | Validated description of bytes. It is not a signature, ACL, or local path. |
| `SharedFileHandle` | random token, display expiry | Secret capability normally returned by an authorized tRPC procedure. |
| Share policy | `allowedPeerIds` unless `allowBearer`, optional `allowedPrincipals`, `expiresAt`, `maxDownloads` | Bounds who may redeem a handle, until when, and for how many logical operations. Principal binding is recommended but explicit. |
| Share operation | peer, principal binding, negotiated fingerprint, operation ID, state | Server-side replay/reconnect accounting for one logical capability redemption. |
| Transfer attempt | connection context, manifest, missing chunks, attempt ID, lane token | Ephemeral receiver state used to attach and bound parallel streams. |

Outbound metadata flows from validated `getRequestHeaders` defaults plus validated `p2pRpcContext` per-call overrides; per-call values win, then the merged record is validated again. The receiving `RpcServerRequest.headers` is an immutable, untrusted string map.

## Data classification

| Data | Confidentiality | Trusted after validation? | May authorize work? |
|---|:---:|:---:|:---:|
| Locator ticket | May expose route topology; not an authorization secret | Only as a self-signed route assertion | No |
| Expected endpoint/principal tuple | Deployment-dependent; normally directory data | Only if obtained independently from a trusted bootstrap source | Selects the intended outbound target; does not grant operation permission |
| Endpoint ID | Public key | As transport key identity, not enterprise ownership | No |
| Session credential / OAuth token | Secret | Untrusted until the configured authenticator verifies it; confined to the encrypted handshake | Establishes a principal, never sent as RPC metadata |
| `SessionPrincipal` | May contain sensitive verified identity/claims; no token material | Yes; immutable verified view | Policy input |
| RPC headers | Application-dependent | No; bounded and immutable only | Never alone |
| RPC input | Application-dependent | No; requires procedure input parser | Only through business policy |
| Capability token | Yes | Opaque | Only with an active authorized session and matching policy |
| Capability ID | No | Hash for audit/policy correlation | No |
| Transfer, attempt, and lane IDs | Lane token is secret; other IDs are not | Only within matching attempt state | Attach streams, not business permission |
| Filename, manifest metadata, content | Application-dependent | No | No |
| Security audit event | Credential-free | Locally generated | No |

## Immutability and snapshots

Verified principals and claims, sessions, outbound targets and nested principal matchers, RPC request/header views, manifests, and library context facades are frozen or defensively copied. This prevents application callbacks from changing a value after validation or authorization. Immutability proves consistency, not truth: a frozen remote header is still a remote assertion, and target expectations copied from an untrusted locator are still untrusted.

## Persistent versus transient state

- Endpoint keys should be persistent and managed externally; ephemeral keys break stable peer binding.
- Peer runtimes, sessions, transfer attempts, and the in-memory capability registry are process-local.
- Built-in destination resume files persist partial content and verified chunk state, but are content-bound rather than principal- or capability-bound.
- Durable authorization, transfer history, idempotency, retention, and audit records remain application responsibilities.
