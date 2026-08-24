import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';
import { invariant, runAndCapture } from './package-validation-utils.mjs';

const outputDirectory = resolve(process.argv[2] ?? 'release-artifact');
await mkdir(outputDirectory, { recursive: true });
invariant((await readdir(outputDirectory)).length === 0, `Package artifact directory must be empty: ${outputDirectory}`);

const resultText = await runAndCapture('npm', [
  'pack',
  '--workspace',
  '@p2prpc/core',
  '--ignore-scripts',
  '--pack-destination',
  outputDirectory,
  '--json'
]);
let results;
try {
  results = JSON.parse(resultText);
} catch (cause) {
  throw new Error('npm pack did not emit valid JSON', { cause });
}
invariant(Array.isArray(results) && results.length === 1, 'npm pack must produce exactly one package');
const [result] = results;
invariant(result.name === '@p2prpc/core', `Unexpected packed package: ${String(result.name)}`);
invariant(typeof result.filename === 'string' && /^p2prpc-core-[0-9A-Za-z._-]+\.tgz$/u.test(result.filename), 'Unexpected npm tarball name');

const artifact = join(outputDirectory, result.filename);
const digest = createHash('sha256').update(await readFile(artifact)).digest('hex');
await writeFile(join(outputDirectory, 'pack.json'), `${JSON.stringify(results, null, 2)}\n`, { flag: 'wx' });
await writeFile(join(outputDirectory, 'SHA256SUMS'), `${digest}  ${basename(artifact)}\n`, { flag: 'wx' });
process.stdout.write(`${artifact}\n`);
