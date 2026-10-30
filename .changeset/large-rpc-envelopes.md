---
"@arduano/p2prpc-core": patch
---

Allow an explicit control-frame byte limit up to 64 MiB and forward frameLimits
from createBridgeHost to each logical peer. Defaults remain 1 MiB. Applications
must configure compatible limits at both endpoints and enough aggregate buffer
capacity; existing resource accounting, shape limits, carrier chunks and file
transfer limits remain authoritative.

Use bounded WebSocket admission without waiting for a full flush after every
fragment. This removes a TLS/window-update throughput collapse. Classify a
truncated logical-stream read as disconnected, matching the native carrier so
interrupted file transfers retain their existing resumable identity.

Honor explicitly configured tRPC error formatters through tRPC's own error-shape
function. The application owns disclosure in that formatter; default errors stay
sanitized and diagnostic callbacks still cannot change the already derived
response. The former test that discarded custom formatter data is replaced by
the inferred public error-contract oracle.
