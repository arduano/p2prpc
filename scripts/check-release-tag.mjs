import { readFile } from 'node:fs/promises';
import process from 'node:process';
import { URL } from 'node:url';
import { invariant } from './package-validation-utils.mjs';

const ref = process.argv[2] ?? process.env.GITHUB_REF;
invariant(
  typeof ref === 'string' && /^refs\/tags\/v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/u.test(ref),
  'Release ref must be an exact semver tag such as refs/tags/v0.2.0'
);

const manifest = JSON.parse(await readFile(new URL('../packages/core/package.json', import.meta.url), 'utf8'));
invariant(ref === `refs/tags/v${manifest.version}`, `Release tag ${ref} does not match package version ${manifest.version}`);
invariant(manifest.name === '@arduano/p2prpc-core', 'Release package name is invalid');
invariant(manifest.private === false, 'Release package must be explicitly public');

process.stdout.write(`${manifest.name}@${manifest.version}\n`);
