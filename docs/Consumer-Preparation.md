# Candidate and published native consumers

The packed framework keeps exact numeric Iroh dependencies. Its supported native
consumer must override both Iroh edges with the reviewed published fork URLs and
SHA-512 integrities. Candidate and published consumer preparation share that one
implementation in [consumer-preparation.ts](../scripts/consumer-preparation.ts).

CI source candidates use:

```bash
npm run build
npm run pack:artifact -- /tmp/package-artifact
npm run prepare:candidate-consumer -- /tmp/package-artifact /tmp/new-candidate-consumer
npm run test:packed -- /tmp/new-candidate-consumer
```

The artifact directory must contain exactly the core tarball named by the original
`pack.json`, and its producer `SHA256SUMS`. Preparation validates the package name,
version, size, npm SHA-512 integrity, SHA-1 metadata and SHA-256 checksum before
creating the consumer or running npm. Extra tarballs and mismatched metadata are
refused. These checks bind the tested bytes; they do not approve publication.

The prepared directory contains the core tarball, an application manifest and
lockfile with both explicit Iroh overrides, and:

- `candidate-consumer-receipt.json`, with mode `source-candidate` and hashes of
  the core, producer metadata, checksums, consumer lock, SBOM and signature proof.
- `candidate-consumer-sbom.cdx.json`, describing the actual overridden native
  closure, with its existing permissive runtime license policy enforced.
- `candidate-consumer-registry-signatures.json`, preserving npm's signature
  verification result. The fixed GitHub fork archives retain their separately
  checked URLs, versions and integrities.

Installation disables dependency lifecycle scripts and verifies that nested Iroh
edges resolve to the same approved forks. Preparation removes its installed
`node_modules` on success; subsequent packed/native smoke commands install from
this retained lock. Failure removes only the newly owned destination. Existing
destinations are refused.

Published renewal.1 preparation remains a distinct admission policy:

```bash
npm run prepare:reviewed-consumer -- /path/to/reviewed-package.tgz /tmp/new-reviewed-consumer
npm run prepare:reviewed-consumer -- /path/to/reviewed-package.tgz /tmp/new-local-proof --local /path/to/node-fork.tgz /path/to/shared-fork.tgz
```

It still requires version `0.3.0-renewal.1` and SHA-256
`26867bf16d55c3a7e1a51c72f3c36f40662cefa6a38f0689f6187b955bfa0b10`.
A changed source candidate is refused. Published URL receipts retain mode
`published-url`; local archive proofs retain mode `local-proof`. There is no
environment switch or argument which relaxes the published core hash. This
historical CLI is not the admission policy for new releases.

CI quality, native and minimum-runtime jobs prepare the same source-candidate
artifact. Their artifact includes the actual overridden closure's SBOM and
signature evidence. New releases use the same candidate verifier for their new,
unused version. The tag workflow requires successful main-branch CI for the exact
commit and an exact tag/package-version match before preparing the release. The
publish job retains its `github-packages` environment, immutable artifact checks,
package and closure attestations, registry-byte verification, and downstream
installation with the fixed Iroh overrides. Candidate qualification alone does
not authorize publication or update an installed application.

Release artifacts retain the original producer checksum as `package-SHA256SUMS`
and hash it in the final multiasset `SHA256SUMS`. The candidate receipt binds that
original checksum, `pack.json`, the package bytes and the prepared native closure.
The existing `reviewed-consumer-*` asset names carry this new version's
`source-candidate` receipt and actual closure evidence. `sbom.cdx.json` and
`registry-signatures.json` are byte-identical compatibility aliases of that
closure evidence; the workflow does not install a second, unoverridden graph.
Publication verifies the receipt's exact version, core hash and producer hashes,
then publishes only the unchanged candidate tarball. Historical renewal.1 bytes
and the historical verifier remain unchanged.
