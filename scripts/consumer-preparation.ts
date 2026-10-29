import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { cp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { z } from 'zod';
import { invariant, readPackageArchive, run, runAndCapture, type PackageArchive } from './package-validation-utils.mjs';

const reviewedVersion = '0.3.0-renewal.1';
const reviewedCoreSha256 = '26867bf16d55c3a7e1a51c72f3c36f40662cefa6a38f0689f6187b955bfa0b10';
const forkRelease = 'https://github.com/arduano/iroh-http/releases/download/leo-v6-iroh-0.6.2-d799fa3/';
const fork = [
  {
    name: '@momics/iroh-http-node',
    file: 'iroh-http-node-0.6.2-fork-linux-win-x64.tgz',
    sha256: '9cf8d5f1a13a7c28e4103f06921badb00b11b76d9287a3b6ecc5f9523d9d2608',
    integrity: 'sha512-CPRn15sDElYcARIbGcdJJtQj1jH9er3ytl7xkXqUSSk6GjsL8xwLrrGKi2izP58XZMjkCQKJA7xi7Be2Z8Q99Q=='
  },
  {
    name: '@momics/iroh-http-shared',
    file: 'iroh-http-shared-0.6.2-fork.tgz',
    sha256: '1475bf877f3d3bfddeb01d5464220355981eedb549a81cb4fbed3457c43105bc',
    integrity: 'sha512-LI6vNhKQQZBJV+pC3w/yNxXQoP+pMpmYVHrOo9Y3IHFbMnvkWhV1qzArOn34lQ8JU/pbEMdHVHgZYwmTFnDIDQ=='
  }
] as const;

const sha256 = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');
const sourceRoot = fileURLToPath(new URL('..', import.meta.url));
const coreName = '@arduano/p2prpc-core';
const packedSchema = z.object({ name: z.literal(coreName), version: z.string().regex(/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u), dependencies: z.record(z.string(), z.string()) });
const metadataSchema = z.array(z.object({ name: z.literal(coreName), version: z.string(),
  filename: z.string().regex(/^arduano-p2prpc-core-[0-9A-Za-z._-]+\.tgz$/u), size: z.number().int().positive(),
  integrity: z.string(), shasum: z.string() })).length(1);
const manifestSchema = z.object({ dependencies: z.record(z.string(), z.string()), overrides: z.record(z.string(), z.unknown()) });
const lockSchema = z.object({ lockfileVersion: z.number(), packages: z.record(z.string(), z.object({
  version: z.string().optional(), resolved: z.string().optional(), integrity: z.string().optional(), dependencies: z.record(z.string(), z.string()).optional()
})) });
const signaturesSchema = z.object({ invalid: z.array(z.unknown()), missing: z.array(z.unknown()) });
const approvedRuntimeLicenses = new Set(['MIT', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', '(MIT OR Apache-2.0)', 'MIT OR Apache-2.0', 'Apache-2.0 OR MIT']);
const sbomSchema = z.object({ bomFormat: z.literal('CycloneDX'), specVersion: z.literal('1.5'),
  components: z.array(z.object({ name: z.string(), version: z.string(), purl: z.string().startsWith('pkg:npm/'),
    licenses: z.array(z.object({ license: z.object({ id: z.string() }).optional(), expression: z.string().optional() })).min(1), hashes: z.array(z.object({ alg: z.string(), content: z.string() })).optional() })) });

interface VerifiedArtifact {
  readonly path: string;
  readonly archive: PackageArchive;
  readonly version: string;
  readonly sha256: string;
  readonly integrity: string;
  readonly candidate?: { readonly metadataSha256: string; readonly checksumsSha256: string };
}
export type LocalForks = readonly [node: string, shared: string];

function packageFacts(path: string, archive: PackageArchive): VerifiedArtifact {
  const packed = packedSchema.parse(JSON.parse(archive.files.get('package.json')?.content.toString('utf8') ?? '{}'));
  for (const input of fork) invariant(packed.dependencies[input.name] === '0.6.2', `The packed ${input.name} dependency must remain numeric and exact`);
  return { path, archive, version: packed.version, sha256: sha256(archive.compressed),
    integrity: `sha512-${createHash('sha512').update(archive.compressed).digest('base64')}` };
}

/** Historical published bytes; there is deliberately no candidate/hash override. */
export async function verifyReviewedArtifact(path: string): Promise<VerifiedArtifact> {
  let artifact = resolve(path);
  if ((await stat(artifact)).isDirectory()) {
    const tarballs = (await readdir(artifact)).filter(name => name.endsWith('.tgz'));
    invariant(tarballs.length === 1, 'Reviewed artifact directory must contain exactly one package tarball');
    artifact = join(artifact, tarballs[0]!);
  }
  const verified = packageFacts(artifact, await readPackageArchive(artifact));
  invariant(verified.version === reviewedVersion, 'The reviewed consumer requires the exact renewal.1 package');
  invariant(verified.sha256 === reviewedCoreSha256, 'The p2prpc tarball differs from the reviewed candidate');
  return verified;
}

/** Bind this source candidate to the CI producer's original npm metadata and
 * checksums. This verifies bytes, not approval to publish a historical version. */
export async function verifyCandidateArtifact(directory: string): Promise<VerifiedArtifact> {
  const root = resolve(directory);
  const metadataBytes = await readFile(join(root, 'pack.json'));
  const checksumsBytes = await readFile(join(root, 'SHA256SUMS'));
  const [metadata] = metadataSchema.parse(JSON.parse(metadataBytes.toString('utf8')));
  invariant(metadata, 'Candidate package metadata is missing');
  const tarballs = (await readdir(root)).filter(name => name.endsWith('.tgz'));
  invariant(tarballs.length === 1 && tarballs[0] === metadata.filename, 'Candidate directory must contain exactly its recorded package tarball');
  const verified = packageFacts(join(root, metadata.filename), await readPackageArchive(join(root, metadata.filename)));
  const checksums = /^([0-9a-f]{64}) {2}([^\r\n]+)\n?$/u.exec(checksumsBytes.toString('utf8'));
  invariant(checksums && checksums[1] === verified.sha256 && checksums[2] === metadata.filename, 'Candidate SHA256SUMS differs from its package bytes');
  invariant(metadata.version === verified.version && metadata.size === verified.archive.compressed.byteLength &&
    metadata.integrity === verified.integrity && metadata.shasum === createHash('sha1').update(verified.archive.compressed).digest('hex'),
  'Candidate npm pack metadata differs from its package bytes');
  return { ...verified, candidate: { metadataSha256: sha256(metadataBytes), checksumsSha256: sha256(checksumsBytes) } };
}

export async function prepareReviewedConsumer(artifact: string, destination: string, local?: LocalForks): Promise<void> {
  await prepare(await verifyReviewedArtifact(artifact), resolve(destination), local);
}
export async function prepareCandidateConsumer(directory: string, destination: string): Promise<void> {
  await prepare(await verifyCandidateArtifact(directory), resolve(destination));
}

/** One implementation of the supported native closure, shared by independent
 * source-candidate and immutable-release admission policies. */
async function prepare(core: VerifiedArtifact, destination: string, local?: LocalForks): Promise<void> {
  const sourceManifest = manifestSchema.parse(JSON.parse(await readFile(join(sourceRoot, 'package.json'), 'utf8')));
  const sourceLock = lockSchema.parse(JSON.parse(await readFile(join(sourceRoot, 'package-lock.json'), 'utf8')));
  for (const input of fork) {
    const url = forkRelease + input.file;
    const entry = sourceLock.packages[`node_modules/${input.name}`];
    invariant(sourceManifest.dependencies[input.name] === url && sourceManifest.overrides[input.name] === `$${input.name}` &&
      sourceLock.packages['']?.dependencies?.[input.name] === url && entry?.version === '0.6.2' &&
      entry.resolved === url && entry.integrity === input.integrity,
    `The source root does not use the reviewed ${input.name} override`);
  }
  await mkdir(destination);
  try {
    await cp(core.path, join(destination, basename(core.path)));
    const dependencies: Record<string, string> = { [coreName]: `file:./${basename(core.path)}` };
    for (const [index, input] of fork.entries()) {
      if (local) {
        const source = resolve(local[index]!);
        invariant(basename(source) === input.file && sha256(await readFile(source)) === input.sha256, `The reviewed ${input.name} tarball differs`);
        await cp(source, join(destination, input.file));
        dependencies[input.name] = `file:./${input.file}`;
      } else dependencies[input.name] = forkRelease + input.file;
    }
    const manifest = { name: core.candidate ? 'p2prpc-source-candidate-portable-closure' : 'p2prpc-renewal-1-portable-closure',
      version: '1.0.0', private: true, type: 'module', engines: { node: '>=20' }, dependencies,
      overrides: Object.fromEntries(Object.keys(dependencies).map(name => [name, `$${name}`])) };
    await writeFile(join(destination, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    const env = { ...process.env, npm_config_userconfig: join(destination, 'no-user-npmrc') };
    const npm = (args: string[]): Promise<void> => run('npm', [...args, '--ignore-scripts', '--strict-peer-deps', '--fund=false', '--audit=false'], { cwd: destination, env });
    await npm(['install', '--package-lock-only']);
    const lockBytes = await readFile(join(destination, 'package-lock.json'));
    const lock = lockSchema.parse(JSON.parse(lockBytes.toString('utf8')));
    invariant(lock.lockfileVersion === 3 && JSON.stringify(lock.packages['']?.dependencies) === JSON.stringify(dependencies), 'The reviewed consumer lock root differs from its manifest');
    const coreEntry = lock.packages[`node_modules/${coreName}`];
    invariant(coreEntry?.version === core.version && coreEntry.resolved === dependencies[coreName]!.replace('file:./', 'file:') &&
      coreEntry.integrity === core.integrity, 'The reviewed p2prpc lock entry differs from its tarball');
    for (const input of fork) {
      const entry = lock.packages[`node_modules/${input.name}`];
      const expected = local ? dependencies[input.name]!.replace('file:./', 'file:') : dependencies[input.name];
      invariant(entry?.version === '0.6.2' && entry.resolved === expected && entry.integrity === input.integrity, `The reviewed ${input.name} lock URL or integrity differs`);
      for (const [path, nested] of Object.entries(lock.packages)) {
        if (path.endsWith(`/node_modules/${input.name}`) && path !== `node_modules/${input.name}`) {
          invariant(nested.version === entry.version && nested.resolved === entry.resolved && nested.integrity === entry.integrity, `A nested ${input.name} differs from the reviewed fork`);
        }
      }
    }
    await npm(['ci']);
    const rawSbom: unknown = JSON.parse(await runAndCapture('npm', ['sbom', '--omit=dev', '--sbom-format', 'cyclonedx'], { cwd: destination, env }));
    const sbom = sbomSchema.parse(rawSbom);
    for (const component of sbom.components) {
      invariant(component.licenses.every(entry => approvedRuntimeLicenses.has(entry.license?.id ?? entry.expression ?? '')),
        `SBOM component is outside the approved permissive-license policy: ${component.name}`);
    }
    for (const [name, version, integrity] of [[coreName, core.version, core.integrity], ...fork.map(input => [input.name, '0.6.2', input.integrity])] as const) {
      const component = sbom.components.find(item => item.name === name);
      const hash = Buffer.from(integrity!.slice('sha512-'.length), 'base64').toString('hex');
      invariant(component?.version === version && component.hashes?.some(item => item.alg === 'SHA-512' && item.content === hash), `The reviewed consumer SBOM omits the exact ${name} bytes`);
    }
    const rawSignatures: unknown = JSON.parse(await runAndCapture('npm', ['audit', 'signatures', '--omit=dev', '--json'], { cwd: destination, env }));
    const signatures = signaturesSchema.parse(rawSignatures);
    invariant(signatures.invalid.length === 0 && signatures.missing.length === 0, 'A registry dependency signature is missing or invalid');
    const sbomBytes = Buffer.from(`${JSON.stringify(rawSbom, null, 2)}\n`);
    const signatureBytes = Buffer.from(`${JSON.stringify(rawSignatures, null, 2)}\n`);
    const stem = core.candidate ? 'candidate-consumer' : 'reviewed-consumer';
    const receipt = { schema: 1, mode: core.candidate ? 'source-candidate' : local ? 'local-proof' : 'published-url',
      package: { name: coreName, version: core.version, sha256: core.sha256 },
      ...(core.candidate ? { candidate: core.candidate } : {}),
      forkCommit: 'd799fa3f200b8ab862bad91ecd13a4389588111c',
      fork: fork.map(input => ({ name: input.name, url: forkRelease + input.file, sha256: input.sha256, integrity: input.integrity })),
      rootDependencies: dependencies, rootOverrides: manifest.overrides,
      lockSha256: sha256(lockBytes), sbomSha256: sha256(sbomBytes), signaturesSha256: sha256(signatureBytes) };
    await writeFile(join(destination, `${stem}-sbom.cdx.json`), sbomBytes);
    await writeFile(join(destination, `${stem}-registry-signatures.json`), signatureBytes);
    await writeFile(join(destination, `${stem}-receipt.json`), `${JSON.stringify(receipt, null, 2)}\n`);
    await rm(join(destination, 'node_modules'), { recursive: true, force: true });
    process.stdout.write(`Prepared ${receipt.mode} Iroh consumer for ${coreName}@${core.version}.\n`);
  } catch (error) {
    await rm(destination, { recursive: true, force: true });
    throw error;
  }
}
