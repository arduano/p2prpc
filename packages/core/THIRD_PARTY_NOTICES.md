# Third-party notices

`@arduano/p2prpc-core` does not bundle third-party runtime source or native binaries. Its npm artifact imports separately installed dependencies, which remain under their own terms. The lockfile records the exact versions used by this repository.

| Direct runtime dependency | Declared license | Source |
|---|---|---|
| `@momics/iroh-http-node` | MIT OR Apache-2.0 | [momics/iroh-http](https://github.com/momics/iroh-http) |
| `@momics/iroh-http-shared` | MIT OR Apache-2.0 | [momics/iroh-http](https://github.com/momics/iroh-http) |
| `@napi-rs/blake-hash` | MIT | [Brooooooklyn/blake-hash](https://github.com/Brooooooklyn/blake-hash) |
| `@trpc/client`, `@trpc/server` | MIT | [trpc/trpc](https://github.com/trpc/trpc) |
| `jose` | MIT | [panva/jose](https://github.com/panva/jose) |
| `msgpackr` | MIT | [kriszyp/msgpackr](https://github.com/kriszyp/msgpackr) |
| `superjson` | MIT | [blitz-js/superjson](https://github.com/blitz-js/superjson) |

The Iroh wrapper, shared package, and platform-binary npm artifacts declare `MIT OR Apache-2.0` but, as of the pinned release, omit license files from those artifacts. The corresponding upstream source release contains [LICENSE-MIT](https://github.com/momics/iroh-http/blob/v0.6.0/LICENSE-MIT) and [LICENSE-APACHE](https://github.com/momics/iroh-http/blob/v0.6.0/LICENSE-APACHE). Organizations that require license text inside every dependency artifact should track an upstream correction or record a compliance waiver before deployment.

## Browser bridge dependencies

- `@chainsafe/libp2p-yamux` 8.0.1 — Apache-2.0 or MIT; standard Yamux multiplexing and flow control.
- `@libp2p/utils` 7.4.5 — Apache-2.0 or MIT; bounded message-stream adapter for Yamux.
- `@libp2p/logger` 6.2.16 — Apache-2.0 or MIT; required Yamux component logger.
- `@noble/hashes` 1.8.0 — MIT; portable SHA-256 and BLAKE3 with native file-protocol compatibility.
- `zod` 4.6.6 — MIT; bounded exact admission schemas.

The existing Iroh packages and native pins remain unchanged. Browser imports
must use the explicit `/browser` entry and a browser-aware bundler; they never
load the native endpoint or filesystem modules.
