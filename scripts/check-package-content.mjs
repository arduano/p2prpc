import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath, URL } from 'node:url';
import { invariant, packageArtifactArgument, readPackageArchive } from './package-validation-utils.mjs';

const artifact = packageArtifactArgument();
const packMetadataPath = process.argv[3];
const archive = await readPackageArchive(artifact);
const paths = [...archive.files.keys()].sort();
invariant(paths.length <= 128, 'Package contains too many files');
invariant(paths.every((path) => path.length <= 240), 'Package contains an overlong path');

const requiredFiles = ['LICENSE', 'README.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'package.json'];
for (const required of requiredFiles) invariant(archive.files.has(required), `Package is missing ${required}`);
for (const path of paths) {
  invariant(
    requiredFiles.includes(path) || /^dist\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/u.test(path),
    `Package contains a file outside the public artifact allowlist: ${path}`
  );
  if (path.startsWith('dist/')) {
    invariant(
      /\.(?:js|mjs|d\.ts|d\.mts|js\.map|mjs\.map|d\.ts\.map|d\.mts\.map)$/u.test(path),
      `Package contains an unexpected dist file type: ${path}`
    );
  }
  invariant(archive.files.get(path).mode === 0o644, `Package file must not be executable: ${path}`);
}
invariant(paths.some((path) => /^dist\/.+\.(?:js|mjs)$/u.test(path)), 'Package has no ESM runtime entry');
invariant(paths.some((path) => /^dist\/.+\.d\.(?:ts|mts)$/u.test(path)), 'Package has no TypeScript declarations');
invariant(paths.some((path) => /^dist\/.+\.(?:js|mjs)\.map$/u.test(path)), 'Package has no JavaScript source map');

let manifest;
try {
  manifest = JSON.parse(archive.files.get('package.json').content.toString('utf8'));
} catch (cause) {
  throw new Error('Packed package.json is not valid JSON', { cause });
}
invariant(manifest.name === '@p2prpc/core', 'Packed package has the wrong name');
invariant(typeof manifest.version === 'string' && /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(manifest.version), 'Packed package version is invalid');
invariant(archive.artifact === `p2prpc-core-${manifest.version}.tgz`, 'Package filename does not match its version');
invariant(manifest.private !== true, 'Packed package must be public');
invariant(manifest.license === 'MIT', 'Packed package must declare MIT');
invariant(manifest.type === 'module', 'Packed package must declare ESM semantics');
invariant(manifest.sideEffects === false, 'Packed package must be tree-shakeable by construction');
invariant(manifest.engines?.node === '>=20.3.0', 'Packed package must preserve its verified Node.js support floor');
invariant(manifest.publishConfig?.access === 'public', 'Packed package must publish publicly');
invariant(manifest.publishConfig?.provenance === true, 'Packed package must request npm provenance');
invariant(Array.isArray(manifest.files), 'Packed package must define an explicit files allowlist');
invariant(
  JSON.stringify([...manifest.files].sort()) === JSON.stringify([
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md',
    'dist'
  ]),
  'Packed package files allowlist is broader than the audited public artifact'
);
invariant(manifest.repository?.url === 'git+https://github.com/arduano/p2prpc.git', 'Packed package repository is invalid');
invariant(manifest.repository?.directory === 'packages/core', 'Packed package repository directory is invalid');
invariant(manifest.homepage === 'https://arduano.github.io/p2prpc/', 'Packed package homepage is invalid');
invariant(manifest.bugs?.url === 'https://github.com/arduano/p2prpc/issues', 'Packed package issue tracker is invalid');
invariant(manifest.types === './dist/index.d.ts', 'Packed package must expose the reviewed root declaration entry');
invariant(archive.files.has('dist/index.d.ts'), 'Packed root types entry does not exist');
invariant(manifest.exports && typeof manifest.exports === 'object', 'Packed package must define explicit exports');
const expectedExports = Object.freeze({
  '.': Object.freeze({ types: './dist/index.d.ts', runtime: './dist/index.js' }),
  './advanced': Object.freeze({ types: './dist/advanced.d.ts', runtime: './dist/advanced.js' }),
  './testing': Object.freeze({ types: './dist/testing.d.ts', runtime: './dist/testing.js' })
});
invariant(
  sameStrings(Object.keys(manifest.exports), Object.keys(expectedExports)),
  'Packed package exports differ from the three reviewed public entry points'
);
for (const [name, expected] of Object.entries(expectedExports)) {
  const entry = manifest.exports[name];
  invariant(entry && typeof entry === 'object' && !Array.isArray(entry), `Packed export is invalid: ${name}`);
  invariant(sameStrings(Object.keys(entry), ['import', 'require']), `Packed export conditions are invalid: ${name}`);
  invariant(entry.require === null, `Packed export must fail closed for CommonJS: ${name}`);
  invariant(
    entry.import && typeof entry.import === 'object' && !Array.isArray(entry.import),
    `Packed ESM export is invalid: ${name}`
  );
  invariant(sameStrings(Object.keys(entry.import), ['default', 'types']), `Packed ESM conditions are invalid: ${name}`);
  invariant(entry.import.types === expected.types, `Packed type target is invalid: ${name}`);
  invariant(entry.import.default === expected.runtime, `Packed runtime target is invalid: ${name}`);
}
for (const field of ['main', 'module', 'browser', 'bin', 'man', 'imports']) {
  invariant(manifest[field] === undefined, `Packed package must not expose an unaudited ${field} entry`);
}
invariant(
  manifest.bundledDependencies === undefined && manifest.bundleDependencies === undefined,
  'Packed package must not bundle hidden dependencies'
);

const installLifecycleScripts = ['preinstall', 'install', 'postinstall', 'prepare'];
for (const name of installLifecycleScripts) {
  invariant(manifest.scripts?.[name] === undefined, `Packed package must not declare ${name}`);
}

const exportedTargets = [];
function collectExportTargets(value) {
  if (typeof value === 'string') exportedTargets.push(value);
  else if (value && typeof value === 'object') {
    for (const nested of Object.values(value)) collectExportTargets(nested);
  }
}
collectExportTargets(manifest.exports);
for (const target of exportedTargets) {
  invariant(target.startsWith('./dist/'), `Export target must stay inside dist: ${target}`);
  invariant(archive.files.has(target.slice(2)), `Export target does not exist: ${target}`);
}

const dependencyGroups = [manifest.dependencies ?? {}, manifest.peerDependencies ?? {}, manifest.optionalDependencies ?? {}];
for (const dependencies of dependencyGroups) {
  invariant(dependencies && typeof dependencies === 'object' && !Array.isArray(dependencies), 'Package dependency map is invalid');
  for (const [name, range] of Object.entries(dependencies)) {
    invariant(typeof range === 'string' && range.length > 0 && range === range.trim(), `Dependency range is invalid: ${name}`);
    invariant(
      !/^(?:file:|git(?:\+|:)|https?:|workspace:|link:|github:|npm:|\*|latest$)/u.test(range),
      `Dependency uses a mutable or non-registry range: ${name}`
    );
  }
}
const reviewedRuntimeDependencies = [
  '@momics/iroh-http-node',
  '@momics/iroh-http-shared',
  '@napi-rs/blake-hash',
  '@trpc/client',
  '@trpc/server',
  'jose',
  'msgpackr',
  'superjson'
];
invariant(
  sameStrings(Object.keys(manifest.dependencies ?? {}), reviewedRuntimeDependencies),
  'Packed runtime dependency set differs from the reviewed supply-chain boundary'
);
invariant(
  sameStrings(Object.keys(manifest.peerDependencies ?? {}), ['@trpc/client', '@trpc/server']),
  'Packed peer dependency set differs from the reviewed tRPC boundary'
);
invariant(
  manifest.optionalDependencies === undefined,
  'Packed package must not add unaudited direct optional dependencies'
);
for (const name of [
  '@momics/iroh-http-node',
  '@momics/iroh-http-shared',
  '@napi-rs/blake-hash',
  '@trpc/client',
  '@trpc/server',
  'jose',
  'msgpackr',
  'superjson'
]) {
  invariant(
    /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(manifest.dependencies?.[name] ?? ''),
    `Audited runtime boundary dependency must be exact-pinned: ${name}`
  );
}

const workspaceLicense = await readFile(resolve(fileURLToPath(new URL('..', import.meta.url)), 'LICENSE'));
invariant(archive.files.get('LICENSE').content.equals(workspaceLicense), 'Packed MIT license differs from the repository license');
const notices = archive.files.get('THIRD_PARTY_NOTICES.md').content.toString('utf8');
for (const name of Object.keys(manifest.dependencies ?? {})) {
  invariant(notices.includes(`\`${name}\``), `Third-party notices omit direct dependency ${name}`);
}

if (packMetadataPath !== undefined) {
  const metadata = JSON.parse(await readFile(resolve(packMetadataPath), 'utf8'));
  invariant(Array.isArray(metadata) && metadata.length === 1, 'npm pack metadata must contain one result');
  const result = metadata[0];
  invariant(result.name === manifest.name && result.version === manifest.version, 'npm pack metadata does not match the artifact manifest');
  invariant(result.filename === archive.artifact, 'npm pack metadata does not match the artifact filename');
  invariant(result.size === archive.compressed.byteLength, 'npm pack size does not match the artifact');
  invariant(
    result.integrity === `sha512-${createHash('sha512').update(archive.compressed).digest('base64')}`,
    'npm pack integrity does not match the artifact'
  );
  invariant(result.shasum === createHash('sha1').update(archive.compressed).digest('hex'), 'npm pack shasum does not match the artifact');
  invariant(Array.isArray(result.files), 'npm pack file metadata is missing');
  const metadataPaths = result.files.map((file) => file.path).sort();
  invariant(JSON.stringify(metadataPaths) === JSON.stringify(paths), 'npm pack metadata does not match tar contents');
  invariant(result.entryCount === paths.length, 'npm pack entry count does not match tar contents');
  invariant(
    result.unpackedSize === [...archive.files.values()].reduce((total, entry) => total + entry.size, 0),
    'npm pack unpacked size does not match tar contents'
  );
  for (const file of result.files) {
    const entry = archive.files.get(file.path);
    invariant(entry.size === file.size && entry.mode === file.mode, `npm pack metadata differs for ${file.path}`);
  }
}

process.stdout.write(`Validated ${archive.artifact}: ${paths.length} allowlisted files, MIT license, explicit ESM/type exports, and no install scripts.\n`);

function sameStrings(left, right) {
  return JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}
