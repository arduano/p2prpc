import { cp, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

const COMMIT = 'd799fa3f200b8ab862bad91ecd13a4389588111c';
const REMOTE = 'https://github.com/arduano/iroh-http.git';
const REF = 'refs/heads/codex/relay-token-auth';
const source = resolve(process.argv[2] ?? '');
const output = resolve(process.argv[3] ?? 'vendor/iroh-http');
if (!process.argv[2]) throw new Error('usage: node scripts/build-iroh-fork-artifacts.mjs SOURCE [OUTPUT]');

const run = (command, args, options = {}) => execFileSync(command, args, {
  cwd: source,
  encoding: 'utf8',
  stdio: options.capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
  ...options
});
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const git = (...args) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8' }).trim();
if (git('rev-parse', 'HEAD') !== COMMIT) throw new Error(`source HEAD must be ${COMMIT}`);
if (git('status', '--porcelain') !== '') throw new Error('source worktree must be clean');
const advertised = execFileSync('git', ['ls-remote', REMOTE, REF], { encoding: 'utf8' }).trim().split(/\s+/)[0];
if (advertised !== COMMIT) throw new Error(`verified branch moved: expected ${COMMIT}, got ${advertised || '<missing>'}`);

run(npm, ['ci', '--omit=optional']);
run(npm, ['run', 'build:shared']);
run(npm, ['run', 'build', '--workspace=packages/iroh-http-node']);

const scratch = await mkdtemp(join(tmpdir(), 'iroh-http-pack-'));
try {
  await mkdir(output, { recursive: true });
  const sharedJson = JSON.parse(run(npm, ['pack', './packages/iroh-http-shared', '--json', '--pack-destination', scratch], { capture: true }));
  const sharedSrc = join(scratch, sharedJson[0].filename);
  const sharedDst = join(output, 'iroh-http-shared-0.6.2-fork.tgz');
  await rename(sharedSrc, sharedDst);

  const nodeStage = join(scratch, 'node');
  await cp(join(source, 'packages/iroh-http-node'), nodeStage, {
    recursive: true,
    filter: (entry) => !entry.includes('/node_modules/') && !entry.includes('/target/')
  });
  const nodeManifestPath = join(nodeStage, 'package.json');
  const nodeManifest = JSON.parse(await readFile(nodeManifestPath, 'utf8'));
  nodeManifest.files = [...new Set([...(nodeManifest.files ?? []), '*.node'])];
  // Fail closed on other platforms instead of falling back to the official
  // optional native packages, which were not built from the verified fork.
  delete nodeManifest.optionalDependencies;
  await writeFile(nodeManifestPath, `${JSON.stringify(nodeManifest, null, 2)}\n`);
  const nodeJson = JSON.parse(execFileSync(npm, ['pack', nodeStage, '--json', '--pack-destination', scratch], {
    cwd: source,
    encoding: 'utf8'
  }));
  const nodeSrc = join(scratch, nodeJson[0].filename);
  const nodeDst = join(output, `iroh-http-node-0.6.2-fork-${process.platform}-${process.arch}.tgz`);
  await rename(nodeSrc, nodeDst);

  const artifacts = [];
  for (const path of [sharedDst, nodeDst]) {
    const bytes = await readFile(path);
    artifacts.push({
      file: basename(path),
      bytes: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex'),
      sri: `sha512-${createHash('sha512').update(bytes).digest('base64')}`
    });
  }
  const receipt = {
    schema: 1,
    source: { remote: REMOTE, ref: REF, commit: COMMIT },
    target: { platform: process.platform, arch: process.arch },
    toolchain: {
      node: process.version,
      npm: execFileSync(npm, ['--version'], { encoding: 'utf8' }).trim(),
      rustc: execFileSync('rustc', ['--version'], { encoding: 'utf8' }).trim(),
      cargo: execFileSync('cargo', ['--version'], { encoding: 'utf8' }).trim()
    },
    artifacts
  };
  await writeFile(join(output, `receipt-${process.platform}-${process.arch}.json`), `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
} finally {
  await rm(scratch, { recursive: true, force: true });
}
