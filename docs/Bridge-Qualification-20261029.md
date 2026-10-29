# Browser bridge implementation and qualification — 2026-10-29

The opt-in browser/Gateway bridge is implemented and passes the local scripted
browser/Iroh journey. This is review evidence, not a release, Multiplex migration,
provider qualification, or production deployment approval.

Source starts at public `main` commit `97161e1` (`0.3.0-renewal.1`). The separately
published renewal.2 tag is not that main baseline. Native Iroh pins are unchanged.
The [contract and review map](wiki/Browser-Bridge.md) identifies each owner/API.

## Exact checks

Maintainer environment: Node24.19.0, npm11.17.0, Linux/NixOS, Chromium152.

| Check | Result |
| --- | --- |
| `npm run lint` | PASS |
| `npm run typecheck` (core, example, benchmarks) | PASS |
| `npm test` | PASS:426 tests in17 files |
| `npm run test:integration` | PASS:26 native cases;2 existing cases skipped |
| `npm run build` | PASS: native and isolated browser ESM/declarations |
| Explicit browser suite | PASS:1 complete journey,8 independent assertions below |
| `npm run check:docs`, lab-driver evidence contract, `npm run docs:build` | PASS |
| Actual tarball content/license/mode/export/dependency policy | PASS:27 allowlisted files, no install scripts |
| Strict publint and Are the Types Wrong (ESM/bundler) on actual tarball | PASS for all5 exports |
| `npm audit --omit=dev --audit-level=low` | PASS:0 runtime vulnerabilities |
| Full `npm audit --audit-level=low` | FAIL:10 existing development-tool dependency findings; see limits |
| `npm run test:minimum-runtime` on local Node24.19.0 | PASS; does not qualify Node20.3 |

The actual browser imports `@arduano/p2prpc-core/browser` through its built
package export. esbuild bundles that entry for the real browser. It reaches a
real local HTTPS/WSS Gateway and two authenticated native Iroh endpoints, with
relays and DNS/mDNS disabled. Native identity/HMAC authentication is real;
browser login/delegation is an explicit controlled fixture, not production auth.
The primary caller's methods are typechecked against the actual scripted Host
router. Private admission helpers are used only for hostile resume probes.

The journey proves:

1. Typed query and subscription expose the correct delegated user/Gateway context.
2. Losing the reply to an admitted mutation does not replay it; reconnect keeps
   the same logical peer and the effect count remains exactly one.
3. A capability issued before loss remains usable afterward under its original
   logical peer and full identity binding.
4. A384KiB Blob push interrupted after a verified chunk resumes the same transfer
   ID, reports resumed delivery, and publishes exactly the expected bytes.
5. Unknown and other-principal resume attempts reach Host authorization refusal
   and allocate no additional logical peer.
6. Browser close proves actual channel closure; Host close returns retained
   peers, channels, admission and owned tasks to zero.
7. The borrowed authenticated Gateway Peer still answers a native health query
   after both browser and bridge-service shutdown.
8. All test-owned endpoints, Chromium, listeners and scratch are reaped; cleanup
   failures0, model calls0, native-agent allocations0.

Two focused admission oracles separately prove that a noncooperative delegation
callback stays charged after timeout/close and cannot attach late, and that a
cancelled native open retains late-stream cleanup until both halves terminate
without closing its borrowed Peer. Six transport oracles cover independent
halves, backpressure, bounded headers, real closure evidence, legal browser close
codes and teardown exceptions. These replace no existing invariants/tests.

## Artifact identity

Candidate tarball (not published):
`arduano-p2prpc-core-0.3.0-renewal.1.tgz`

- Tarball SHA256: `5cf3f562f07dfecbb28b4cd63236b0aaf5b36e77d7e2c0f75d6b6540b712d431`.
- Built and packed browser runtime SHA256: `2081adc4b9196fed3609e39a96bb89a2927a58868136e99bc56c1b9f1860fec3`.
- Browser oracle SHA256: `de743fe154abae1ddf971ffb7f5922e829bfe0bdf68fe8f0deb91b5613f0b3ba`.
- Passing browser log SHA256: `10a56f99cf08c144443aa1fb3221f35ca8c4790d00cbcab605f8a42a561b6bf5`.

The packed browser bytes match the tested built export. This is not an
independently installed packed-consumer/browser qualification. Versioning is
left to Changesets/release review; this candidate must not replace the published
artifact with the same version.

Initial attempts exposed the real browser tRPC server guard, exact file-context
identity across control/data lanes, and browser-invalid WebSocket close code1008.
The implementation now uses tRPC's explicit browser-server option, one file
context per epoch, and application close code4000. The final journey passes
without loosening deadlines or dropping cleanup assertions. Development had
9 owned browser runs plus1 accidentally overlapping native-suite discovery before
browser tests were separated:20 total local Iroh endpoint and10 Chromium
allocations, all reaped. No external/native-agent/provider effects occurred.

## Reproduction and remaining release boundaries

```bash
npm ci --strict-allow-scripts
npm run lint
npm run typecheck
npm test
npm run test:integration
npx playwright-core install --with-deps chromium
npm run test:browser
npm run check:docs
bash scripts/test-lab-driver-validation.sh
npm run docs:build
```

For an existing Chromium, set `P2PRPC_CHROMIUM_EXECUTABLE` when running
`npm run test:browser`. Browser qualification is an explicit command; ordinary
native/unit runs do not launch Chromium. CI includes the dedicated browser step.

- Full dependency audit is not green. A baseline lockfile-only audit reports11
  findings; this change fixes the existing Zod edge when promoting it to runtime,
  and uses fixed ws8.22.0 for the new test server. The remaining10 findings are in
  existing development/documentation tooling (including Vitest and VitePress).
  Runtime-only audit is clean. The full audit gate remains enabled.
- `prepare-reviewed-consumer.mjs` intentionally pins the published renewal.1
  artifact SHA256. This candidate has different bytes, so that release/installed
  consumer path requires a separately reviewed release transition. Its fence is
  unchanged; no publication or updated source/native approval is implied.
- Local attempts to launch an unmodified generic Linux Node20.3.1 binary were
  blocked by NixOS's dynamic-loader environment. The local smoke ran Node24;
  minimum native Node20.3 and cross-platform CI evidence remain separate. New
  optional `/bridge` requires Node22+/modern `Promise.withResolvers`; only
  Yamux-dependent tests explicitly skip on unsupported native runtimes.
- External relay/proxy/mobile/Firefox/Safari reachability, large-load performance,
  production upgrade/auth flows, independent packed-consumer/native closure and
  Multiplex integration are not claimed. The previous application two-viewer
  and history/transport defects remain unresolved under this library evidence.
- No services, credentials, native homes/sessions, production artifacts or
  Multiplex dependency pins were changed. No models were called.
