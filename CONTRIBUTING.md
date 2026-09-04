# Contributing to p2prpc

Thanks for helping improve p2prpc. Bug reports, design feedback, documentation fixes, tests, and focused pull requests are welcome.

## Before opening an issue

- Search existing issues and discussions.
- Use a GitHub Security Advisory for vulnerabilities; do not publish exploit details in an issue.
- Include the operating system, Node.js version, p2prpc version or commit, Iroh native target, and a minimal reproduction for bugs.

## Development

Use Node.js 24 for the maintainer toolchain. The library supports Node.js 20.3 and newer.

```bash
npm ci
npm run lint
npm run typecheck
npm run check:docs
bash scripts/test-lab-driver-validation.sh
npm test
npm run test:integration
npm run build
npm run test:minimum-runtime
npm run docs:build
npm pack --dry-run -w @arduano/p2prpc-core
npm audit --audit-level=low
```

Native integration tests exercise real Iroh endpoints and can take longer than unit tests.

The controlled network and stress suites are intentionally absent from pull-request runners. Maintainers run them through the `Production validation` workflow on dedicated hosts; its runner contract, scenarios, and pass criteria are documented in the [production-validation guide](./docs/wiki/Production-Validation.md). Do not weaken resource or correctness thresholds to accommodate an unexplained failure.

## Pull requests

- Keep changes scoped and explain observable or security-relevant behavior.
- Add runtime validation and negative tests at every new trust boundary.
- Update the wiki and `SECURITY.md` when data models, lifecycles, protocol behavior, or residual risks change.
- Add a Changesets entry for a user-visible package change with `npm run changeset`. Documentation and repository-maintenance changes normally do not need one.
- Do not commit credentials, endpoint keys, access tokens, locator tickets from real environments, downloaded files, or transfer state.

By contributing, you agree that your contribution is licensed under the repository's MIT License.
