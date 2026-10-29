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
`published-url`; local archive proofs retain mode `local-proof`. The publication
workflow accepts only the former. There is no environment switch or argument
which relaxes the published core hash, and no candidate receipt is publication
approval.

CI quality, native and minimum-runtime jobs prepare the same source-candidate
artifact. Their artifact includes the actual overridden closure's SBOM and
signature evidence. The immutable published workflow and its separately reviewed
release transition remain unchanged. Source-candidate qualification does not
update an installed application or a published registry version.
