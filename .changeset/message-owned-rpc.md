---
"@arduano/p2prpc-core": minor
---

Move RPC buffer admission from idle streams to shared directional message budgets.
Permit 64 MiB RPC envelopes, preserve small control progress, reject queued input
growth before encoding, and stream bodies through bounded carrier reads. Browser
admission 2/native protocol 6 require upgrading both ends. Preserve initiating
RPC error diagnostics and distinguish observation loss from mutation uncertainty.
Remove per-frame empty-buffer polling from WebSocket writes; capacity remains
bounded. Encoded-span quotas do not claim a JavaScript heap/codec arena bound.
