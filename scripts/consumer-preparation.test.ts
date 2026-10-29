import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { verifyCandidateArtifact, verifyReviewedArtifact } from './consumer-preparation.js';

const execute = promisify(execFile);
const sourceRoot = new URL('..', import.meta.url);
const candidateCli = fileURLToPath(new URL('./prepare-candidate-consumer.ts', import.meta.url));
const reviewedCli = fileURLToPath(new URL('./prepare-reviewed-consumer.ts', import.meta.url));

test('candidate bytes require the producer metadata and checksum while immutable published bytes stay fenced', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'p2prpc-consumer-admission-'));
  const fixture = join(directory, 'fixture'), artifact = join(directory, 'artifact'), destination = join(directory, 'must-not-exist');
  try {
    await mkdir(fixture); await mkdir(artifact);
    await writeFile(join(fixture, 'package.json'), JSON.stringify({ name: '@arduano/p2prpc-core', version: '0.3.0-renewal.1',
      dependencies: { '@momics/iroh-http-node': '0.6.2', '@momics/iroh-http-shared': '0.6.2' } }));
    await writeFile(join(fixture, 'index.js'), 'export const fixture = true;\n');
    const packed = await execute('npm', ['pack', fixture, '--ignore-scripts', '--json', '--pack-destination', artifact], {
      cwd: directory, timeout: 15_000, env: { ...process.env, npm_config_userconfig: join(directory, 'no-user-npmrc') }
    });
    const metadata: Array<{ filename: string; integrity: string }> = JSON.parse(packed.stdout);
    assert.equal(metadata.length, 1);
    const file = join(artifact, metadata[0]!.filename);
    const bytes = await readFile(file);
    const digest = createHash('sha256').update(bytes).digest('hex');
    await writeFile(join(artifact, 'pack.json'), packed.stdout);
    const sums = `${digest}  ${basename(file)}\n`;
    await writeFile(join(artifact, 'SHA256SUMS'), sums);
    const accepted = await verifyCandidateArtifact(artifact);
    assert.equal(accepted.sha256, digest);
    assert.equal(accepted.version, '0.3.0-renewal.1');
    assert.ok(accepted.candidate);
    await assert.rejects(verifyReviewedArtifact(file), /differs from the reviewed candidate/);
    // The old --local spelling still parses as one flag plus two fork paths;
    // the immutable core hash rejects before any fork file/install is touched.
    await assert.rejects(execute(process.execPath, ['--import', 'tsx', reviewedCli, file, destination, '--local', 'node.tgz', 'shared.tgz'], {
      cwd: sourceRoot, timeout: 15_000
    }), error => error instanceof Error && error.message.includes('differs from the reviewed candidate'));
    metadata[0]!.integrity = 'sha512-wrong';
    await writeFile(join(artifact, 'pack.json'), JSON.stringify(metadata));
    await assert.rejects(verifyCandidateArtifact(artifact), /npm pack metadata differs/);
    await assert.rejects(execute(process.execPath, ['--import', 'tsx', candidateCli, artifact, destination], { cwd: sourceRoot, timeout: 15_000 }),
      error => error instanceof Error && error.message.includes('npm pack metadata differs'));
    await assert.rejects(access(destination), { code: 'ENOENT' });
    await writeFile(join(artifact, 'pack.json'), packed.stdout);
    await writeFile(join(artifact, 'SHA256SUMS'), `${'0'.repeat(64)}  ${basename(file)}\n`);
    await assert.rejects(verifyCandidateArtifact(artifact), /SHA256SUMS differs/);
    await writeFile(join(artifact, 'SHA256SUMS'), sums);
    await writeFile(file, Buffer.from('different bytes'));
    await assert.rejects(verifyCandidateArtifact(artifact));
    await assert.rejects(access(destination), { code: 'ENOENT' });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('both preparation CLIs expose help and reject unknown options before any package effect', async () => {
  for (const cli of [candidateCli, reviewedCli]) {
    const help = await execute(process.execPath, ['--import', 'tsx', cli, '--help'], { cwd: sourceRoot, timeout: 15_000 });
    assert.match(help.stdout, /prepare-(?:candidate|reviewed)-consumer/);
    await assert.rejects(execute(process.execPath, ['--import', 'tsx', cli, '--not-a-supported-option'], { cwd: sourceRoot, timeout: 15_000 }));
  }
});
