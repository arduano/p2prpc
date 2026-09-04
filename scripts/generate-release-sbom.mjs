import { createHash } from 'node:crypto';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import process from 'node:process';
import {
  invariant,
  packageArtifactArgument,
  readPackageArchive,
  run,
  runAndCapture,
  temporaryDirectory,
  writeExtractedPackage
} from './package-validation-utils.mjs';

const artifact = packageArtifactArgument();
const sbomOutput = resolve(process.argv[3] ?? 'sbom.cdx.json');
const signaturesOutput = resolve(process.argv[4] ?? 'registry-signatures.json');
const approvedRuntimeLicenses = new Set([
  'MIT',
  'Apache-2.0',
  'ISC',
  'BSD-2-Clause',
  'BSD-3-Clause',
  '(MIT OR Apache-2.0)',
  'MIT OR Apache-2.0'
]);
const directory = await temporaryDirectory('release-sbom');
try {
  const archive = await readPackageArchive(artifact);
  await writeExtractedPackage(archive, directory);
  const manifestPath = join(directory, 'package.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));

  // npm treats a package being inspected as a development checkout. Remove
  // development-only declarations in the disposable copy so the SBOM is the
  // exact runtime graph a registry consumer receives.
  const runtimeManifest = { ...manifest };
  delete runtimeManifest.devDependencies;
  delete runtimeManifest.scripts;
  await writeFile(manifestPath, `${JSON.stringify(runtimeManifest, null, 2)}\n`);
  await run('npm', [
    'install',
    '--ignore-scripts',
    '--strict-peer-deps',
    '--omit=dev',
    '--package-lock=true',
    '--fund=false',
    '--audit=false'
  ], { cwd: directory });

  const sbomText = await runAndCapture('npm', [
    'sbom',
    '--omit=dev',
    '--sbom-format',
    'cyclonedx'
  ], { cwd: directory });
  const sbom = JSON.parse(sbomText);
  const rootRef = `${manifest.name}@${manifest.version}`;
  sbom.metadata.component.group = '@arduano';
  sbom.metadata.component.name = 'p2prpc-core';
  sbom.metadata.component.hashes = [
    { alg: 'SHA-256', content: createHash('sha256').update(archive.compressed).digest('hex') },
    { alg: 'SHA-512', content: createHash('sha512').update(archive.compressed).digest('hex') }
  ];
  invariant(sbom.bomFormat === 'CycloneDX' && sbom.specVersion === '1.5', 'npm emitted an unexpected SBOM format');
  invariant(sbom.metadata?.component?.['bom-ref'] === rootRef, 'SBOM root does not match the packed package');
  invariant(sbom.metadata.component.version === manifest.version, 'SBOM version does not match the packed package');
  invariant(sbom.metadata.component.purl === `pkg:npm/%40arduano/p2prpc-core@${manifest.version}`, 'SBOM purl does not match the packed package');
  invariant(
    sbom.metadata.component.licenses?.some((entry) => entry.license?.id === 'MIT'),
    'SBOM root does not declare MIT'
  );
  invariant(Array.isArray(sbom.components) && sbom.components.length > 0, 'SBOM has no runtime components');
  for (const component of sbom.components) {
    invariant(typeof component.name === 'string' && typeof component.version === 'string', 'SBOM component identity is incomplete');
    invariant(typeof component.purl === 'string' && component.purl.startsWith('pkg:npm/'), `SBOM component has no npm purl: ${component.name}`);
    invariant(Array.isArray(component.licenses) && component.licenses.length > 0, `SBOM component has no declared license: ${component.name}`);
    invariant(
      component.licenses.every((entry) =>
        approvedRuntimeLicenses.has(entry.license?.id ?? entry.expression)
      ),
      `SBOM component is outside the approved permissive-license policy: ${component.name}`
    );
  }
  const rootDependencies = sbom.dependencies?.find((entry) => entry.ref === rootRef)?.dependsOn;
  invariant(Array.isArray(rootDependencies), 'SBOM has no dependency edge for the packed package');
  for (const name of Object.keys(manifest.dependencies ?? {})) {
    invariant(rootDependencies.some((reference) => reference.startsWith(`${name}@`)), `SBOM omits direct runtime dependency ${name}`);
  }
  await writeFile(sbomOutput, `${JSON.stringify(sbom, null, 2)}\n`, { flag: 'wx' });

  const signaturesText = await runAndCapture('npm', [
    'audit',
    'signatures',
    '--omit=dev',
    '--json'
  ], { cwd: directory });
  const signatures = JSON.parse(signaturesText);
  invariant(Array.isArray(signatures.invalid) && signatures.invalid.length === 0, 'A registry dependency signature is invalid');
  invariant(Array.isArray(signatures.missing) && signatures.missing.length === 0, 'A runtime dependency is missing a registry signature');
  const signatureEvidence = Object.freeze({
    schemaVersion: 1,
    package: rootRef,
    command: 'npm audit signatures --omit=dev',
    invalid: signatures.invalid,
    missing: signatures.missing,
    auditedRuntimeComponents: sbom.components.map((component) => Object.freeze({
      name: component.name,
      version: component.version,
      purl: component.purl
    }))
  });
  await writeFile(signaturesOutput, `${JSON.stringify(signatureEvidence, null, 2)}\n`, { flag: 'wx' });
  process.stdout.write(`Generated a license-complete CycloneDX SBOM and verified registry signatures for ${rootRef}.\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
