import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath, URL } from 'node:url';
import {
  invariant,
  packageArtifactArgument,
  readPackageArchive,
  run,
  runAndCapture
} from './package-validation-utils.mjs';

const version = '0.3.0-renewal.1';
const coreSha256 = 'a53659552f97e5d10cd3ed4b7c7ab70a2fda9f2b5e06e9856c08f7399637e773';
const forkRelease = 'https://github.com/arduano/iroh-http/releases/download/leo-v6-iroh-0.6.2-d799fa3/';
const fork = [
  {
    name: '@momics/iroh-http-node',
    file: 'iroh-http-node-0.6.2-fork-linux-win-x64.tgz',
    sha256: 'c5562ade5809b2e156a6179654a0c0e46925df6973421abcd771181a527ef02a',
    integrity: 'sha512-jLVYvRtb93CYZSQDwLr/pg2wlIfFijvaCVNN8rdP0TrHXHufhz/Ty1CS8g5E4zo3FDOsI+Kx3iXckEz+o2sLgw=='
  },
  {
    name: '@momics/iroh-http-shared',
    file: 'iroh-http-shared-0.6.2-fork.tgz',
    sha256: '1475bf877f3d3bfddeb01d5464220355981eedb549a81cb4fbed3457c43105bc',
    integrity: 'sha512-LI6vNhKQQZBJV+pC3w/yNxXQoP+pMpmYVHrOo9Y3IHFbMnvkWhV1qzArOn34lQ8JU/pbEMdHVHgZYwmTFnDIDQ=='
  }
];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const sourceRoot = fileURLToPath(new URL('..', import.meta.url));
const artifact = packageArtifactArgument();
const local = process.argv[4] === '--local';
invariant(local ? process.argv.length === 7 : process.argv.length === 4,
  'Usage: prepare-reviewed-consumer <p2prpc.tgz> <new-dir> [--local <node-fork.tgz> <shared-fork.tgz>]');
const destination = resolve(process.argv[3]);

const archive = await readPackageArchive(artifact);
const packed = JSON.parse(archive.files.get('package.json')?.content.toString('utf8') ?? '{}');
const coreIntegrity = `sha512-${createHash('sha512').update(archive.compressed).digest('base64')}`;
invariant(packed.name === '@arduano/p2prpc-core' && packed.version === version,
  'The reviewed consumer requires the exact renewal.1 package');
invariant(sha256(archive.compressed) === coreSha256, 'The p2prpc tarball differs from the reviewed candidate');
for (const input of fork) invariant(packed.dependencies?.[input.name] === '0.6.2',
  `The packed ${input.name} dependency must remain numeric and exact`);
const sourceManifest = JSON.parse(await readFile(join(sourceRoot, 'package.json'), 'utf8'));
const sourceLock = JSON.parse(await readFile(join(sourceRoot, 'package-lock.json'), 'utf8'));
for (const input of fork) {
  const url = forkRelease + input.file;
  const entry = sourceLock.packages?.[`node_modules/${input.name}`];
  invariant(sourceManifest.dependencies?.[input.name] === url && sourceManifest.overrides?.[input.name] === `$${input.name}` &&
    sourceLock.packages?.['']?.dependencies?.[input.name] === url && entry?.version === '0.6.2' &&
    entry.resolved === url && entry.integrity === input.integrity,
  `The source root does not use the reviewed ${input.name} override`);
}

await mkdir(destination);
try {
  await cp(artifact, join(destination, basename(artifact)));
  const dependencies = { '@arduano/p2prpc-core': `file:./${basename(artifact)}` };
  for (const [index, input] of fork.entries()) {
    if (local) {
      const source = resolve(process.argv[index + 5]);
      invariant(basename(source) === input.file && sha256(await readFile(source)) === input.sha256,
        `The reviewed ${input.name} tarball differs`);
      await cp(source, join(destination, input.file));
      dependencies[input.name] = `file:./${input.file}`;
    } else dependencies[input.name] = forkRelease + input.file;
  }
  const manifest = {
    name: 'p2prpc-renewal-1-portable-closure', version: '1.0.0', private: true, type: 'module',
    engines: { node: '>=20' }, dependencies,
    overrides: Object.fromEntries(Object.keys(dependencies).map(name => [name, `$${name}`]))
  };
  await writeFile(join(destination, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  const env = { ...process.env, npm_config_userconfig: join(destination, 'no-user-npmrc') };
  const npm = (args) => run('npm', [...args, '--ignore-scripts', '--strict-peer-deps', '--fund=false', '--audit=false'], { cwd: destination, env });
  await npm(['install', '--package-lock-only']);
  const lockBytes = await readFile(join(destination, 'package-lock.json'));
  const lock = JSON.parse(lockBytes.toString('utf8'));
  invariant(lock.lockfileVersion === 3 && JSON.stringify(lock.packages?.['']?.dependencies) === JSON.stringify(dependencies),
    'The reviewed consumer lock root differs from its manifest');
  const coreEntry = lock.packages?.['node_modules/@arduano/p2prpc-core'];
  invariant(coreEntry?.version === version && coreEntry.resolved === dependencies['@arduano/p2prpc-core'].replace('file:./', 'file:') &&
    coreEntry.integrity === coreIntegrity, 'The reviewed p2prpc lock entry differs from its tarball');
  for (const input of fork) {
    const entry = lock.packages?.[`node_modules/${input.name}`];
    const expected = local ? dependencies[input.name].replace('file:./', 'file:') : dependencies[input.name];
    invariant(entry?.version === '0.6.2' && entry.resolved === expected && entry.integrity === input.integrity,
      `The reviewed ${input.name} lock URL or integrity differs`);
    for (const [path, nested] of Object.entries(lock.packages)) {
      if (path.endsWith(`/node_modules/${input.name}`) && path !== `node_modules/${input.name}`) {
        invariant(nested.version === entry.version && nested.resolved === entry.resolved && nested.integrity === entry.integrity,
          `A nested ${input.name} differs from the reviewed fork`);
      }
    }
  }
  await npm(['ci']);
  const sbom = JSON.parse(await runAndCapture('npm', ['sbom', '--omit=dev', '--sbom-format', 'cyclonedx'], { cwd: destination, env }));
  invariant(sbom.bomFormat === 'CycloneDX' && sbom.specVersion === '1.5', 'The reviewed consumer SBOM is invalid');
  for (const [name, expectedVersion, integrity] of [
    ['@arduano/p2prpc-core', version, coreIntegrity],
    ...fork.map(input => [input.name, '0.6.2', input.integrity])
  ]) {
    const component = sbom.components?.find(item => item.name === name);
    const hash = Buffer.from(integrity.slice('sha512-'.length), 'base64').toString('hex');
    invariant(component?.version === expectedVersion && component.hashes?.some(item => item.alg === 'SHA-512' && item.content === hash),
      `The reviewed consumer SBOM omits the exact ${name} bytes`);
  }
  const signatures = JSON.parse(await runAndCapture('npm', ['audit', 'signatures', '--omit=dev', '--json'], { cwd: destination, env }));
  invariant(Array.isArray(signatures.invalid) && signatures.invalid.length === 0 &&
    Array.isArray(signatures.missing) && signatures.missing.length === 0,
  'A registry dependency signature is missing or invalid');
  const sbomBytes = Buffer.from(`${JSON.stringify(sbom, null, 2)}\n`);
  const signatureBytes = Buffer.from(`${JSON.stringify(signatures, null, 2)}\n`);
  await writeFile(join(destination, 'reviewed-consumer-sbom.cdx.json'), sbomBytes);
  await writeFile(join(destination, 'reviewed-consumer-registry-signatures.json'), signatureBytes);
  const receipt = {
    schema: 1, mode: local ? 'local-proof' : 'published-url',
    package: { name: packed.name, version, sha256: coreSha256 },
    forkCommit: 'd799fa3f200b8ab862bad91ecd13a4389588111c',
    fork: fork.map(input => ({ name: input.name, url: forkRelease + input.file, sha256: input.sha256, integrity: input.integrity })),
    rootDependencies: dependencies, rootOverrides: manifest.overrides,
    lockSha256: sha256(lockBytes), sbomSha256: sha256(sbomBytes), signaturesSha256: sha256(signatureBytes)
  };
  await writeFile(join(destination, 'reviewed-consumer-receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  await rm(join(destination, 'node_modules'), { recursive: true, force: true });
  process.stdout.write(`Prepared ${receipt.mode} reviewed Iroh consumer for ${packed.name}@${version}.\n`);
} catch (error) {
  await rm(destination, { recursive: true, force: true });
  throw error;
}
