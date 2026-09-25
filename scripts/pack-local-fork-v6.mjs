import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const expectedBase = 'ca7bb6fb7b791813c937ddbf9bde62423d097373';
const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
try { execFileSync('git', ['merge-base', '--is-ancestor', expectedBase, head], { cwd: root, stdio: 'ignore' }); }
catch { throw new Error('unexpected p2prpc lineage'); }
if (execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' }).trim()) throw new Error('p2prpc source must be clean');
const artifacts = resolve(process.argv[2] ?? join(root, 'vendor', 'p2prpc'));
const src = join(root, 'packages', 'core');
const current = JSON.parse(await readFile(join(src, 'package.json'), 'utf8'));
if (!String(current.dependencies?.['@momics/iroh-http-node']).startsWith('file:../../vendor/iroh-http/') ||
    !String(current.dependencies?.['@momics/iroh-http-shared']).startsWith('file:../../vendor/iroh-http/')) {
  throw new Error('fork inputs not locally pinned');
}
const scratch = await mkdtemp(join(tmpdir(), 'p2prpc-fork-pack-'));
try {
  const stage = join(scratch, 'core'); await mkdir(stage);
  for (const name of ['dist', 'LICENSE', 'README.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md']) {
    await cp(join(src, name), join(stage, name), { recursive: true });
  }
  const manifest = { ...current, dependencies: {
    ...current.dependencies, '@momics/iroh-http-node': '0.6.2', '@momics/iroh-http-shared': '0.6.2',
  } };
  await writeFile(join(stage, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
  await mkdir(artifacts, { recursive: true });
  const packed = JSON.parse(execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm',
    ['pack', stage, '--ignore-scripts', '--json', '--pack-destination', artifacts], { cwd: root, encoding: 'utf8' }))[0];
  const target = join(artifacts, packed.filename);
  const bytes = await readFile(target);
  const receipt = { schema: 1, base: head, fork: 'd799fa3f200b8ab862bad91ecd13a4389588111c',
    file: packed.filename, size: bytes.byteLength, sha256: createHash('sha256').update(bytes).digest('hex'),
    sri: `sha512-${createHash('sha512').update(bytes).digest('base64')}`,
    requiredConsumerOverrides: ['@momics/iroh-http-node', '@momics/iroh-http-shared'],
  };
  await writeFile(join(artifacts, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  console.log(JSON.stringify(receipt));
} finally { await rm(scratch, { recursive: true, force: true }); }
