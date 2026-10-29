---
"@arduano/p2prpc-core": minor
---

Add an opt-in browser Peer and trusted Gateway bridge over bounded binary
WebSocket/Yamux and authenticated Iroh streams. Reuse existing tRPC/file protocols,
require explicit delegated admission and per-operation authorization, retain
logical file state across carrier replacement, and expose bounded Blob/memory
file primitives without native browser dependencies. Native RPC/file behavior and Iroh pins
remain unchanged. AuthorizationAction gains bridge; exhaustive policies must
handle it, and OIDC admission requires p2prpc:bridge. The optional Host/Gateway
bridge requires Node22+; existing native root usage retains its Node20.3 floor.
