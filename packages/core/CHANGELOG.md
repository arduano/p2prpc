# @p2prpc/core

## 0.2.0

### Minor Changes

- 69a13a4: Require independently trusted endpoint and canonical-principal expectations for outbound connections; add signed-ticket, DNS/PKARR, and mDNS locators plus fail-closed relay/route egress policy; make shared-secret authorization deny by default; strictly validate security, node, share, and discovery options; verify clean QUIC FINs, harden native writer cleanup, and expose transport/file diagnostics; harden OIDC claim parsing and filesystem race handling; and publish the package as ESM-only with verified Node.js 20.3 support.
