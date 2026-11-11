---
"@arduano/p2prpc-core": patch
---

Keep concurrent logical stream admission and RPC queue deadlines isolated to each opening. Remove the conflicting pending-header/accept-queue limit, promptly retire rejected pairs, and preserve established streams when another opening is refused or expires before transport I/O begins. RPC streams now reserve their stream slot separately from message buffers; file control and data progress reservations remain intact.

WebSocket writes wait for bounded capacity instead of an empty socket buffer after every frame, avoiding artificial per-frame polling latency while retaining finite queued-byte ownership.
