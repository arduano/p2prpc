# Production validation

The goal is to validate p2prpc's protocol, scheduling, discovery integration, and lifecycle cleanup—not to benchmark or re-implement Iroh.

## Release rule

No npm publish is approved until the exact candidate commit passes the external topology/stress lab and one tarball built from that same commit passes every artifact gate. The external drivers execute the checked-out commit, not the npm tarball; the publish manifest binds the commit, production-validation run ID, tarball SHA-256, and npm integrity. GitHub run/artifact metadata retains the full commit and logs, while the evidence files retain bounded environment, configuration, timing, and counter data. Relay origins are never copied into public artifacts: configured, attempted, connected, and denied sets use full 64-hex SHA-256 fingerprints. Evidence labels native DNS attempts as opaque because the pinned wrapper does not expose its resolved candidates. A failed or incomplete row is a no-go. The repository contains drivers and validation rules; it does not by itself constitute external production evidence.

## Local candidate gates

```bash
npm ci --strict-allow-scripts
npm run lint
npm run typecheck
npm test
npm run test:integration
npm run build
npm run check:docs
npm run docs:build
bash scripts/test-lab-driver-validation.sh
npm audit --audit-level=low
```

The release workflow additionally validates packed contents/license, `publint`, Are-the-Types-Wrong, installation from the tarball, a tree-shaken native import, SBOM and registry-signature evidence, action syntax, provenance, and post-publish byte equality. Publishing consumes the immutable candidate with lifecycle scripts disabled; it does not rebuild it. A rerun never blindly republishes an immutable npm version: it may recover only when registry integrity, tarball bytes, requested dist-tag, signed source commit, and the original trusted workflow invocation all match. GitHub release creation similarly verifies or replaces only the expected assets.

Release governance is part of the gate: protect `main`, require review for the `npm` environment, and scope npm trusted publishing to this repository and `.github/workflows/publish.yml`. The Changesets workflow may update a release PR, but it has no Actions-approval permission and cannot waive that PR's normal required checks. Lab runners must be dedicated or ephemeral, execute only protected-branch code, keep credentials outside the workspace, and start each run from a clean host boundary. Lab driver binaries are accepted only when their version, schema, and SHA-256 match the protected manifest.

## Required discovery/topology matrix

| Case | Required assertion |
|---|---|
| Signed ticket + default relay | Ticket signature/expiry/protocol, expected endpoint/principal, and explicit direct/relay egress policy all hold; direct upgrade does not change identity. |
| Signed ticket + custom relay | Only a configured canonical HTTPS relay origin is used; an out-of-set hint fails closed. |
| Signed ticket + relay disabled | No relay is advertised or selected; two hosts communicate over non-loopback direct addresses and retain endpoint/principal binding. |
| DNS/PKARR + default relay | Dynamic route succeeds only with independent expected endpoint/principal. |
| mDNS + default relay | Private/link-local candidate policy and explicit default-relay egress rule hold. |
| mDNS + custom relay | Service label/address bounds and configured relay membership hold. |
| mDNS + relay disabled | Discovery and transfer succeed on an isolated LAN with relay egress denied; no loopback address is accepted as evidence. |
| Relay policy negatives | Missing, false, or throwing ticket policy and disabled/custom violations reject before prohibited egress. |

DNS plus custom relay or address/relay filtering is deliberately unsupported because wrapper 0.6.0 cannot expose resolved routes for inspection. Relay-disabled networking uses an exact-version compatibility seam that separates “no relay” from the wrapper's test-only loopback switch. Release evidence must still come from at least two non-loopback lab hosts, report `hostCount >= 2`, `nonLoopbackDirectPathsObserved > 0`, and `relayPathsObserved == 0`, prove `relayUrl === null`, and cover both signed-ticket and mDNS discovery; same-host tests are implementation checks only. One lifecycle run selects one locator/relay policy, so it cannot stand in for the other matrix rows. DNS evidence is necessarily limited to native success/failure and independent identity checks; it cannot claim application inspection of resolved route candidates.

## Mixed workload

Run at least 100 authenticated peers while combining short queries, long queries, mutations with durable idempotency, subscriptions, pushes, pulls, cancellations, reconnects, and large/small files. Saturate global, per-peer, and per-principal ceilings from multiple endpoint keys sharing one principal.

Pass criteria include:

- bounded RSS/external memory and admission queues;
- no event-loop starvation or unbounded RPC latency behind file traffic;
- peer fairness and principal aggregation match configuration;
- overload rejects predictably without credential/file/path leakage;
- no implicit retry after dispatch/commit ambiguity;
- task, lease, transfer, stream-half, and native handle counters return to baseline.

Inject malformed exact-key frames, oversized/deep/item-amplified MessagePack, invalid headers/manifests/resume state, stale/mismatched credentials, wrong principals, revoked/expired capabilities, and slow/non-cooperative policy callbacks.

## 10,000 files over one connection

Use one mutually authenticated physical QUIC connection for exactly 5,000 pushes and 5,000 endpoint/principal-bound capability pulls. Run 2,500 sequential and 2,500 concurrency-16 operations per direction, checkpoint every 100 files, and do not reconnect during the successful workload. A stable session ID alone is insufficient: record one unchanged physical connection ID at both endpoints and exactly one authentication event per endpoint.

Record after warm-up and every fixed batch:

- completed/rejected/ambiguous operations;
- open/accepted QUIC streams and active send/receive halves;
- scheduler active/queued vectors, peer/principal entries, and runtime/task counts;
- transfer/share registry sizes and hard/replay operation counts;
- process file descriptors/native handles;
- heap, external, array-buffer, and RSS memory after optional controlled GC;
- event-loop delay and RPC probe latency during file traffic.

Fault batches must cover cancellation before offer, after offer, mid-lane, before finalize, and across final acknowledgement; receiver rejection; source/destination I/O failure; lane open/write/finish timeout; physical disconnect and secure resume; expired/revoked capability; lost terminal receipt; and peer/node shutdown.

Pass only if every opened half reaches finish/reset/EOF/stop; active transfers, sessions, lanes, hard-active operations, and acknowledgement-ambiguous operations reach zero; replay tombstones remain within their configured bound; share/task/scheduler state returns to baseline; native handles return to the measured baseline envelope; memory has no sustained positive slope after warm-up; commit occurs at most once; and the same connection remains usable for final RPC/transfer canaries. A passing run must expose the required diagnostics—missing connection IDs, stream counters, file descriptors, file state, task/share state, or native endpoint counters makes the single-connection/quiescence claim unqualified rather than inferred.

The checked-in stress driver validates p2prpc's ownership and Iroh integration; it is not an Iroh benchmark and a reduced `--files` run is only a harness smoke test. Its current automated negative batches cover receiver rejection, revoked capability, sender cancellation, and destination-finalize failure, followed by RPC canaries. The single-connection cancellation batch uses one data lane and waits for its first positive progress event before cancelling, proving cleanup of an adopted stream without accidentally selecting the separate fail-closed native-open race (which intentionally quarantines the connection and is covered by unit tests). Evidence records both that trigger and lane count. The driver does **not** yet inject every fault named above or record event-loop delay/RPC latency during the successful file phases. Consequently its `productionGateEligible` field is necessary evidence about count/configuration/diagnostics, not sufficient production approval by itself; the missing fault and mixed-load evidence must come from protected lab runs or further checked-in automation.

A loopback/same-host run cannot prove relay-less discovery, a reconnecting run cannot prove the one-connection invariant, and the file run covers only its selected locator/relay row. Production approval therefore requires both this qualifying native lifecycle artifact and the separate two-host topology matrix for the exact commit. Until those external artifacts are attached and release-bound, the project remains a release candidate, not production-qualified.

## Native compatibility boundary

The exact-pinned shared Iroh package has a narrow writer-cleanup seam: when native `sendChunk` rejects, p2prpc invokes `finishBody` once on the opaque handle and preserves the original error. Startup fails closed if a different shared-package instance resolves. Test rejection, timeout, reset, process warnings, and native handle return-to-baseline on every supported OS/architecture.

## Evidence interpretation

A zero scheduler ledger after shutdown means every tracked logical owner released; scheduler close itself does not erase active leases. It still does not alone prove that opaque native implementations returned all handles, so retain the stream, file-descriptor, native-handle, task, and memory baselines.

Retain the GitHub run, immutable artifact digests, release manifest, checksums, SBOM, registry-signature result, and verified npm provenance for the exact commit. Any code, lockfile, workflow, relay-set, or package-byte change invalidates the candidate and requires the relevant gates again.
