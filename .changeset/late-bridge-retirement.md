---
"@arduano/p2prpc-core": patch
---

Allow browser bridge shutdown and Host revocation to observe late cleanup after
a timed-out close, without replaying work, replacing an unclosed owner, or
accumulating cleanup waiters. Bound browser shutdown during unfinished admission
and forward logical-peer errors through the Host's optional onError callback.
