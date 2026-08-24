---
layout: home

hero:
  name: p2prpc
  text: Typed peer-to-peer RPC and file transfer
  tagline: Mutually authenticated tRPC and resumable parallel files over one Iroh QUIC connection.
  image:
    src: /mark.svg
    alt: Connected peer streams
  actions:
    - theme: brand
      text: Understand the system
      link: /Home
    - theme: alt
      text: Review security
      link: /Security-Model

features:
  - icon: ↔️
    title: One secure connection
    details: Independent QUIC streams carry RPC calls, subscriptions, file control, and bounded parallel data lanes.
    link: /Architecture
    linkText: Architecture
  - icon: 🔐
    title: Identity before authority
    details: Endpoint possession, application principal, and connection session are distinct; every operation is authorized before dispatch.
    link: /Data-Model
    linkText: Data model
  - icon: 📦
    title: Capability-based files
    details: tRPC authorizes and issues typed handles while raw, integrity-checked bytes stay on the dedicated file protocol.
    link: /File-Transfers
    linkText: File transfers
  - icon: 🔎
    title: Built for review
    details: Concise lifecycles, trust boundaries, control evidence, deployment requirements, and explicit non-guarantees.
    link: /Audit-Guide
    linkText: Audit guide
---

<div class="home-intro">

This site documents **p2prpc wire protocol v4** as implemented by `@p2prpc/core`. Start with the [five-minute system model](Home.md), then follow the lifecycle and audit pages when you need control-level detail.

</div>
