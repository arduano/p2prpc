import { cp, mkdtemp, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const expectedBase = 'ca7bb6fb7b791813c937ddbf9bde62423d097373';
const expectedVersion = '0.3.0-renewal.1';
const transportInputs = Object.freeze([
  Object.freeze({
    name: '@momics/iroh-http-node',
    version: '0.6.2',
    argument: 3,
    filename: 'iroh-http-node-0.6.2-fork-linux-win-x64.tgz',
    sha256: 'c5562ade5809b2e156a6179654a0c0e46925df6973421abcd771181a527ef02a',
    sri: 'sha512-jLVYvRtb93CYZSQDwLr/pg2wlIfFijvaCVNN8rdP0TrHXHufhz/Ty1CS8g5E4zo3FDOsI+Kx3iXckEz+o2sLgw==',
    addons: Object.freeze({
      'iroh-http-node.linux-x64-gnu.node': '3d6739abfd441834d4b58b07738280653c7f70eed3649f842d27a2cfce12c550',
      'iroh-http-node.win32-x64-msvc.node': '2dc2e9e7d0e4e946b8dbaac3d66487cf72487d46476c71f33fcc6a3a94595813'
    })
  }),
  Object.freeze({
    name: '@momics/iroh-http-shared',
    version: '0.6.2',
    argument: 4,
    filename: 'iroh-http-shared-0.6.2-fork.tgz',
    sha256: '1475bf877f3d3bfddeb01d5464220355981eedb549a81cb4fbed3457c43105bc',
    sri: 'sha512-LI6vNhKQQZBJV+pC3w/yNxXQoP+pMpmYVHrOo9Y3IHFbMnvkWhV1qzArOn34lQ8JU/pbEMdHVHgZYwmTFnDIDQ==',
    addons: Object.freeze({})
  })
]);

function fail(message) { throw new Error(message); }
function hash(bytes, algorithm, encoding) { return createHash(algorithm).update(bytes).digest(encoding); }
function npm(args, cwd) {
  return execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, npm_config_userconfig: join(tmpdir(), 'p2prpc-no-user-npmrc') }
  });
}
function packedManifest(path) {
  return JSON.parse(execFileSync('tar', ['-xOf', path, 'package/package.json'], { maxBuffer: 64 * 1024 * 1024 }));
}
function packedEntry(path, entry) {
  return execFileSync('tar', ['-xOf', path, `package/${entry}`], { maxBuffer: 64 * 1024 * 1024 });
}
async function digest(path) {
  const bytes = await readFile(path);
  return Object.freeze({ size: bytes.byteLength, sha256: hash(bytes, 'sha256', 'hex'), sri: `sha512-${hash(bytes, 'sha512', 'base64')}` });
}

const destination = resolve(process.argv[2] ?? fail('Pass a new portable artifact directory'));
if (relative(root, destination) === '' || relative(root, destination).startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) === false && destination.startsWith(`${root}/`)) {
  fail('Portable artifact directory must be outside the source checkout');
}
try { await stat(destination); fail(`Refusing to overwrite existing artifact path: ${destination}`); }
catch (error) { if (error.code !== 'ENOENT') throw error; }

const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
try { execFileSync('git', ['merge-base', '--is-ancestor', expectedBase, head], { cwd: root, stdio: 'ignore' }); }
catch { fail('Unexpected p2prpc lineage'); }
if (execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()) fail('p2prpc source must be clean');

const sourceManifest = JSON.parse(await readFile(join(root, 'packages/core/package.json'), 'utf8'));
if (sourceManifest.name !== '@arduano/p2prpc-core' || sourceManifest.version !== expectedVersion) fail('Unexpected p2prpc package identity');
for (const input of transportInputs) {
  if (sourceManifest.dependencies?.[input.name] !== input.version) fail(`Source dependency is not pinned to published ${input.name}@${input.version}`);
}

const resolvedInputs = [];
for (const input of transportInputs) {
  const source = resolve(process.argv[input.argument] ?? fail(`Pass the audited ${input.name} tarball`));
  const details = await digest(source);
  if (basename(source) !== input.filename || details.sha256 !== input.sha256 || details.sri !== input.sri) fail(`Audited bytes differ for ${input.name}`);
  const manifest = packedManifest(source);
  if (manifest.name !== input.name || manifest.version !== input.version) fail(`Packed identity differs for ${input.name}`);
  for (const [addon, expectedHash] of Object.entries(input.addons)) {
    if (hash(packedEntry(source, addon), 'sha256', 'hex') !== expectedHash) fail(`Embedded addon differs: ${addon}`);
  }
  resolvedInputs.push(Object.freeze({ ...input, source, details }));
}

await mkdir(dirname(destination), { recursive: true });
const scratch = await mkdtemp(join(dirname(destination), '.p2prpc-portable-'));
try {
  const coreStage = await mkdtemp(join(tmpdir(), 'p2prpc-core-pack-'));
  try {
    for (const name of ['dist', 'LICENSE', 'README.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md']) {
      await cp(join(root, 'packages/core', name), join(coreStage, name), { recursive: true });
    }
    await cp(join(root, 'packages/core/package.json'), join(coreStage, 'package.json'));
    const packed = JSON.parse(npm(['pack', coreStage, '--ignore-scripts', '--json', '--pack-destination', scratch], root))[0];
    if (packed.name !== sourceManifest.name || packed.version !== expectedVersion) fail('Packed p2prpc identity differs');
  } finally {
    await rm(coreStage, { recursive: true, force: true });
  }

  const p2prpcTarballs = (await readdir(scratch)).filter(entry => entry.endsWith('.tgz'));
  if (p2prpcTarballs.length !== 1) fail('Expected exactly one packed p2prpc tarball');
  const p2prpcFile = p2prpcTarballs[0];
  for (const input of resolvedInputs) await cp(input.source, join(scratch, input.filename), { force: false });

  const dependencies = {
    '@arduano/p2prpc-core': `file:./${p2prpcFile}`,
    '@momics/iroh-http-node': `file:./${transportInputs[0].filename}`,
    '@momics/iroh-http-shared': `file:./${transportInputs[1].filename}`
  };
  const closureManifest = {
    name: 'p2prpc-renewal-1-portable-closure',
    version: '1.0.0',
    private: true,
    type: 'module',
    engines: { node: '>=20' },
    dependencies,
    overrides: Object.fromEntries(Object.keys(dependencies).map(name => [name, `$${name}`]))
  };
  await writeFile(join(scratch, 'package.json'), `${JSON.stringify(closureManifest, null, 2)}\n`);
  npm(['install', '--package-lock-only', '--ignore-scripts', '--strict-peer-deps', '--fund=false', '--audit=false'], scratch);

  const lock = JSON.parse(await readFile(join(scratch, 'package-lock.json'), 'utf8'));
  if (lock.lockfileVersion !== 3 || JSON.stringify(lock.packages?.['']?.dependencies) !== JSON.stringify(dependencies)) fail('Portable lock root dependencies differ');
  for (const [name, specifier] of Object.entries(dependencies)) {
    if (lock.packages?.['']?.overrides !== undefined) fail('Unexpected lockfile root overrides field');
    const locked = lock.packages?.[`node_modules/${name}`];
    const expected = name === '@arduano/p2prpc-core' ? expectedVersion : '0.6.2';
    if (locked?.version !== expected || locked?.resolved !== specifier.replace('file:./', 'file:')) fail(`Portable lock resolution differs for ${name}`);
  }

  const componentNames = [p2prpcFile, ...transportInputs.map(input => input.filename), 'package.json', 'package-lock.json'];
  const components = {};
  for (const filename of componentNames) components[filename] = await digest(join(scratch, filename));
  const receipt = {
    schema: 2,
    sourceCommit: head,
    package: { name: sourceManifest.name, version: expectedVersion, file: p2prpcFile },
    irohForkCommit: 'd799fa3f200b8ab862bad91ecd13a4389588111c',
    components,
    requiredParentDependencies: dependencies,
    requiredParentOverrides: Object.fromEntries(Object.keys(dependencies).map(name => [name, `$${name}`])),
    embeddedAddons: transportInputs[0].addons,
    qualificationLimits: [
      'The p2prpc tarball alone is not a standalone local-fork installation artifact.',
      'Install this directory with npm ci so the sibling Iroh tarballs and root overrides remain authoritative.',
      'Linux x64 native loading is qualified separately; the unchanged Windows x64 addon is hash-identified but was not executed on Windows.'
    ],
    prohibitedEffects: ['no publish', 'no push', 'no consumer edit', 'no Iroh rebuild', 'no live host or service change']
  };
  await writeFile(join(scratch, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  await rename(scratch, destination);
  process.stdout.write(`${JSON.stringify({ destination, ...receipt })}\n`);
} catch (error) {
  await rm(scratch, { recursive: true, force: true });
  throw error;
}
