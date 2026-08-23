# Production validation

[Home](Home.md) · [Architecture](Architecture.md) · [Data model](Data-Model.md) · [Lifecycles](Lifecycles.md) · [Security model](Security-Model.md) · [Files](File-Transfers.md) · [Audit guide](Audit-Guide.md)

This page defines the evidence required to call a p2prpc build production-ready. The tests pressure p2prpc's dispatch, authentication, transfer, and cleanup behavior. They do not claim to benchmark or certify Iroh itself.

## Release gates

| Gate | Where | Required evidence |
| --- | --- | --- |
| Pull request | GitHub-hosted runners | Unit/security tests, deterministic transport lifecycle tests, and a small native integration smoke |
| Nightly | Controlled self-hosted Linux lab | Discovery and relay matrix, 100-peer mixed load, and the 10,000-file lifecycle test |
| Release | Controlled self-hosted Linux lab | Same-commit topology and 10,000-file evidence, four-hour soak, 16 GiB filesystem transfer, identity rotation, relay failover, and clean shutdown |

Correctness, authorization, integrity, and cleanup are absolute gates. The file harness enforces a bounded within-run progressive-slowdown ratio and records latency, wall time, RSS, heap, and file descriptors for later baseline analysis. This repository does not yet implement a historical cross-run performance gate, so it does not claim one.

GitHub-hosted pull-request jobs never target private lab runners. The production-validation workflow is manually selectable, and its scheduled nightly run is disabled unless the repository variable `P2PRPC_LAB_ENABLED` is exactly `true`.

Publishing requires the numeric ID of a successful manual `release` run for the exact `main` commit. The publish workflow verifies the workflow identity, commit, conclusion, non-expired topology/file/mixed-load artifacts, and then revalidates every raw-Iroh, topology, p2prpc file, mixed-load, and release evidence file before npm publication.

## The 10,000-file single-connection gate

This is primarily a stream-lifecycle test, not a throughput benchmark. Two nodes authenticate once, pin one physical QUIC connection, and transfer 10,000 deterministic files: 5,000 pushes and 5,000 capability pulls. Each direction runs 2,500 sequentially and 2,500 at concurrency 16. The corpus contains 9,000 files of 1–4 KiB and 1,000 files of 256 KiB.

Every 100 files, the harness records connection/session IDs, authentication count, streams and native handles, transfer queues, file descriptors, RSS, and JavaScript heap. At each checkpoint, after waiting up to five seconds for resources to quiesce:

- the authenticated session and physical connection IDs have not changed;
- active transfers, lanes, queues, and pending stream headers are zero;
- native readers, writers, and handles equal the post-authentication baseline;
- the wrapper-authoritative native `activeSessions` gauge remains exactly one; the p2prpc physical-connection fingerprints remain unchanged, while the wrapper's advisory `activeConnections` gauge may report zero or one but never more than one;
- file descriptors are at most baseline +8, and never peaked above baseline +64;
- every file has the expected name, size, BLAKE3 digest, content, and exactly one accepted result;
- within each phase, late-batch milliseconds per file are no more than 1.5× early batches.

The same connection then carries 50 rejected pushes, 50 revoked pulls, 50 sender cancellations, 50 destination failures, and 100 successful RPC canaries. Each failure class uses the configured bounded concurrency. For every class, the artifact records logical cases, sender `openedBi`, receiver `acceptedBi`, and an exact-match verdict; all three counts must be 50. An intentional destination failure must also arrive as an explicit `REJECTED` terminal in one attempt: the harness records a per-logical-case attempt vector and requires every entry to equal one. It may not be reclassified as `DISCONNECTED`, retried, or replace the connection. Genuine transport disconnections remain retryable under the file protocol's bounded policy. Success paths must leave globally balanced finish/EOF accounting. Failure classes must fail, quiesce, and leave globally balanced reset/stop accounting; the harness does not claim an exact per-case reset/stop delta. Any unexpected retry or reconnect, leaked handle, trailing byte, partial output, or state/lock debris fails the gate.

### Native writer compatibility boundary

The exact-pinned `@momics/iroh-http-shared` 0.6.1 session sink does not finalize its opaque native writer when `sendChunk` rejects. A later WHATWG `abort()` cannot help because the stream is already errored and no longer invokes the sink's abort callback. p2prpc installs one isolated adapter seam before Iroh creates an endpoint: a rejected `sendChunk(handle, chunk)` invokes `finishBody(handle)` once on a best-effort basis, then rethrows the original transport error. A cleanup error is suppressed only to keep that original error authoritative. The seam does not inspect Node internals or alter successful writes. Startup fails if the node wrapper resolves a different shared-package instance, and the 10,000-file gate requires native readers, writers, and total handles to return exactly to baseline after every failure class. Remove the seam only after an upstream release implements equivalent cleanup and passes that gate.

### Local lifecycle evidence (not a production gate)

A 2026-08-23 final-source local run passed all scenario assertions: 10,000 unique files (5,000 pushes and 5,000 pulls), the four sequential/concurrency-16 phases, all four groups of 50 negative cases with exactly 50 control attempts each, and 100 post-failure RPC canaries. Both endpoints authenticated exactly once; their physical-connection fingerprints remained stable. At the final checkpoint, every connection had zero active send/receive streams; each endpoint reported zero active readers/writers, one active session, and one total native handle; all transfer, lane, queue, and reservation counters were zero. Baseline/final/peak file descriptors were 35/33/72, peak RSS was 389,292,032 bytes, and elapsed time was 75,236 ms. The four within-phase slowdown ratios were 1.04, 0.88, 0.92, and 1.12, below the 1.5× limit. These resource and timing values describe one run, not a performance baseline; an earlier attempt on the same busy workstation failed only the slowdown gate after a transient batch-latency spike, while its last recorded resource checkpoint was quiescent.

The manifest has `status: "passed"` and `qualification.productionGateEligible: false`. It used a signed ticket with disabled relays under the wrapper's loopback-only behavior, so it proves local protocol, stream, and native-handle lifecycle only. It is not evidence for real relay-less LAN, DNS/PKARR, mDNS, custom relays or failover, cross-platform operation, or overall production readiness. Its `/tmp/p2prpc-files-10000-final-source-5.json` artifact (SHA-256 `b0844ef3414bcebd5915471a929ef9755ab82371a2cc0926ff0d9c7e26fabd3d`) is intentionally not committed and is therefore non-durable local evidence; the figures above are informative, not a release attestation.

## Connectivity and discovery matrix

Route information locates an endpoint; it never authorizes one. Every row must independently verify the expected Iroh endpoint key and complete application principal before RPC or file dispatch.

| Locator/path | Required cases |
| --- | --- |
| Signed ticket | IPv4, IPv6, dual stack, multiple candidates, blackholed-first fallback, address refresh, expiry, tampering, staleness, and wrong endpoint/principal |
| DNS/PKARR | Default and controlled resolver, TTL refresh, route replacement, poisoned/stale records, and reconnect resolution |
| LAN mDNS | Advertise/browse on a multicast-capable L2 segment, duplicates, expiry, reappearance, address change, service isolation, and spoofed node IDs |
| Default relay | Public-relay smoke and relay-to-direct upgrade during RPC, subscription, and file work |
| Custom relay | Publicly trusted HTTPS relay, multiple relays, outage/failover, invalid TLS, egress denial, and relay-to-direct upgrade |

Custom relay means relay-assisted, not relay-only: Iroh may upgrade to a direct path. Address-level egress policy must fail closed when a resolver cannot expose candidates before dialing.

Each locator row uses a fresh, isolated endpoint configuration. DNS is enabled only for DNS/PKARR cases because the pinned wrapper installs it as an endpoint-wide fallback; a ticket or mDNS dial made from a DNS-enabled endpoint would not prove which discovery source supplied the successful path. Lab evidence must record the endpoint discovery configuration and the raw-Iroh canary must use the same isolation.

### Relay-less support boundary

The exact-pinned `@momics/iroh-http-node` 0.6.0 maps its relay-disabled option to loopback-only networking, so the current local integration test is not evidence of real relay-less connectivity. Production relay-less support is explicitly **not claimed** until a fixed upstream version passes real-LAN IPv4, IPv6, multi-candidate fallback, and mDNS gates. A release report must name the exact wrapper version and may not waive this boundary.

## Workloads and faults

The balanced nightly workload maintains 100 peers, 1,000 concurrent RPC streams, and 16 simultaneous push/pull transfers. Release testing adds a real 16 GiB transfer and a four-hour soak. It covers subscriptions, reconnect/resume, bounded partitions, relay restart, session expiry, OIDC token/JWKS rotation, issuer outage, capability revocation, storage failure, admission overflow, and repeated connect/work/close waves.

Malformed frames, stalled streams, handshake floods, cancellations, and exact terminal-call accounting use the deterministic fake transport. Network tests apply bounded topology faults; they do not saturate Iroh merely to measure QUIC congestion behavior.

## Raw-Iroh canary and failure classification

Each lab topology first runs a minimal raw-Iroh connect/open/echo/close canary using the same binaries, route, relay, network namespace, and policy. Results are classified as follows:

- canary fails: infrastructure/upstream result; the p2prpc scenario is invalid and must be rerun;
- canary succeeds and p2prpc fails: p2prpc failure;
- both succeed: scenario may contribute release evidence.

A canary success does not waive a p2prpc assertion, and an invalid run is never counted as a pass.

## Self-hosted lab contract

The authoritative lab uses dedicated Linux x64 runners labelled `self-hosted`, `linux`, `x64`, and `p2prpc-lab`. It provides isolated network namespaces, IPv4 and IPv6 routing, controllable loss/blackholes/partitions, a multicast-capable L2 segment, controlled DNS/PKARR, publicly trusted HTTPS custom relays, an OIDC issuer with JWKS rotation, pinned CPU/memory limits, synchronized clocks, and enough private storage for artifacts and a 16 GiB transfer.

The runner image also supplies four versioned, fixed-name topology drivers: `p2prpc-lab-canary` performs raw-Iroh connect/open/echo/close; `p2prpc-lab-topology-suite` applies the route-specific positive, spoofing, fallback, upgrade, and outage cases; `p2prpc-lab-mixed-suite` orchestrates the multi-process balanced workload; and `p2prpc-lab-release-suite` performs the 16 GiB and identity/fault campaign. These are lab infrastructure, not package code. They accept only the workflow arguments shown in `.github/workflows/production-validation.yml` and return nonzero on a failed assertion. The release driver receives every configured `--relay-url`; a release run requires at least two distinct canonical HTTPS relay origins. Case, an explicit default port, or a trailing slash cannot make one relay count twice.

`P2PRPC_LAB_DRIVER_MANIFEST` pins the installed tools as a JSON object keyed by those four names. Every entry contains a nonempty `version`, a 64-digit hexadecimal `sha256` of the resolved executable, and an integer `schemaVersion` of at least 2. Before use, each driver must answer `--version-json` with exactly matching `name`, `version`, and `schemaVersion` fields. Every successful result uses this non-vacuous envelope (additional metrics are allowed):

```json
{
  "schemaVersion": 2,
  "driver": { "name": "p2prpc-lab-canary", "version": "1.2.3" },
  "status": "passed",
  "assertions": { "passed": 5, "failed": 0 },
  "campaign": {
    "id": "raw-iroh-canary",
    "parameters": { "locator": "ticket", "relay": "custom", "dnsEnabled": false, "customRelayCount": 2 },
    "metrics": { "connectionsOpened": 1, "connectionsClosed": 1, "streamsOpened": 1, "streamsClosed": 1, "echoedBytes": 32, "activeConnectionsAfter": 0, "activeStreamsAfter": 0 }
  },
  "scenarios": [
    { "id": "transport.connect", "status": "passed", "assertions": { "passed": 1, "failed": 0 } },
    { "id": "stream.open", "status": "passed", "assertions": { "passed": 1, "failed": 0 } },
    { "id": "stream.echo-integrity", "status": "passed", "assertions": { "passed": 1, "failed": 0 } },
    { "id": "stream.close", "status": "passed", "assertions": { "passed": 1, "failed": 0 } },
    { "id": "transport.close", "status": "passed", "assertions": { "passed": 1, "failed": 0 } }
  ],
  "startedAt": "2026-08-23T00:00:00Z",
  "finishedAt": "2026-08-23T00:00:10Z"
}
```

The validator requires a complete driver-specific scenario set. It ties route/dns/relay parameters to the selected matrix row, requires positive assertion counts whose sum matches the envelope, checks elapsed soak time and 100-peer/1,000-RPC/16-file concurrency metrics, requires exactly 16 GiB for the release storage campaign, and requires zero terminal connection/stream/transfer/handle gauges. Custom-relay topology and release evidence must record at least two relays so multiple-relay and failover cases are non-vacuous. Each job canonicalizes its configured URLs to HTTPS origins before passing them to a driver, rejects duplicates after canonicalization, and requires the driver's reported count to equal that input count. Publishing independently revalidates all downloaded evidence, including exact control-stream accounting in the p2prpc topology and 10,000-file manifests.

Schema version 1 drivers are intentionally rejected. Upgrading a lab image therefore requires updating each driver to emit the schema version 2 campaign/scenario contract, teaching the release driver its repeated `--relay-url` input, running `bash scripts/test-lab-driver-validation.sh`, and then independently reviewing the pinned manifest version, digest, and schema change. The workflow also rejects a missing or mismatched executable before running it. `P2PRPC_LAB_RELAY_URLS` and `P2PRPC_LAB_BIND_ADDRESSES` are JSON string arrays; `P2PRPC_LAB_DNS_SERVER_URL` is a required credential-free HTTPS URL for DNS/PKARR matrix rows. Setting `P2PRPC_LAB_ENABLED=true` opts the repository into scheduled use.

The runner must start clean, contain no production credentials, restrict outbound traffic to the declared topology, and remove generated tokens/files after each run. Ordinary CI exercises the native package on macOS and Windows over loopback, but the repository does not yet claim cross-platform direct/mDNS/public-relay release evidence.

The GitHub run metadata, exact repository commit/lockfile, and uploaded JSON artifacts form the evidence set. Together they identify the commit and dependencies, runner OS, topology and any driver seed, thresholds, raw-Iroh result, assertion summaries, and available resource timelines. Logs and artifacts must never contain access tokens, shared secrets, full locator tickets, capability tokens, or file content.

The workflow treats the JSON result as a second completion channel: a stress process must exit successfully *and* leave an atomic manifest with `status: "passed"`; the 10,000-file job additionally requires `productionGateEligible: true` and exactly 10,000 successful files. A scenario can therefore pass locally while remaining ineligible for the production gate; only the controlled-lab topology can supply the missing qualification. This prevents a signal or abrupt native shutdown from turning a still-`running` partial artifact into a false pass.
