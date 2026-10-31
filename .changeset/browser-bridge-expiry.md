---
"@arduano/p2prpc-core": patch
---

Expose the latest verified browser bridge admission deadline as readonly
`BrowserBridgePeer.expiresAt`. It updates only after successful carrier admission,
so applications can retire an expired logical peer and obtain fresh authorization
instead of retrying its expired resumption secret. Existing expiry enforcement,
carrier reconnection and interrupted-mutation non-replay rules remain unchanged.
