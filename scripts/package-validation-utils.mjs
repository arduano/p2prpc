import { Buffer } from 'node:buffer';
import { spawn } from 'node:child_process';
import { readdirSync, statSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';
import { gunzipSync } from 'node:zlib';

export function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

export function packageArtifactArgument(position = 2) {
  const value = process.argv[position] ?? process.env.P2PRPC_PACKAGE_TARBALL;
  invariant(typeof value === 'string' && value.length > 0, 'Pass the packed @p2prpc/core .tgz artifact path');
  const candidate = resolve(value);
  if (statSync(candidate).isDirectory()) {
    const tarballs = readdirSync(candidate).filter((entry) => entry.endsWith('.tgz'));
    invariant(tarballs.length === 1, `Package artifact directory must contain exactly one .tgz file: ${candidate}`);
    return join(candidate, tarballs[0]);
  }
  invariant(candidate.endsWith('.tgz'), `Package artifact must be a .tgz file: ${candidate}`);
  return candidate;
}

export async function temporaryDirectory(label) {
  return mkdtemp(join(tmpdir(), `p2prpc-${label}-`));
}

export async function run(command, args, options = {}) {
  const executable = process.platform === 'win32' && command === 'npm' ? 'npm.cmd' : command;
  await new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: options.stdio ?? 'inherit',
      windowsHide: true
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} ${args.join(' ')} failed (${signal ?? `exit ${code}`})`));
    });
  });
}

export async function runAndCapture(command, args, options = {}) {
  const executable = process.platform === 'win32' && command === 'npm' ? 'npm.cmd' : command;
  return new Promise((resolvePromise, reject) => {
    const child = spawn(executable, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      stdio: ['ignore', 'pipe', 'inherit'],
      windowsHide: true
    });
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolvePromise(stdout);
      else reject(new Error(`${command} ${args.join(' ')} failed (${signal ?? `exit ${code}`})`));
    });
  });
}

export async function installPackedArtifact(artifact, directory) {
  await writeFile(join(directory, 'package.json'), `${JSON.stringify({
    name: 'p2prpc-packed-verification',
    version: '0.0.0',
    private: true,
    type: 'module'
  }, null, 2)}\n`, { flag: 'wx' });
  await run('npm', [
    'install',
    '--ignore-scripts',
    '--strict-peer-deps',
    '--package-lock=true',
    '--fund=false',
    '--audit=false',
    artifact
  ], { cwd: directory });
  await run('npm', ['prune', '--omit=dev', '--ignore-scripts', '--fund=false', '--audit=false'], { cwd: directory });
}

function parseOctal(field, label) {
  const value = field.toString('ascii').replaceAll('\0', '').trim();
  invariant(/^[0-7]+$/.test(value), `Invalid tar ${label}`);
  const parsed = Number.parseInt(value, 8);
  invariant(Number.isSafeInteger(parsed) && parsed >= 0, `Invalid tar ${label}`);
  return parsed;
}

function validateTarChecksum(header) {
  const expected = parseOctal(header.subarray(148, 156), 'checksum');
  let actual = 0;
  for (let index = 0; index < header.length; index += 1) {
    actual += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  invariant(actual === expected, 'Package tar header checksum is invalid');
}

export async function readPackageArchive(artifact) {
  const compressed = await readFile(artifact);
  invariant(compressed.byteLength > 0 && compressed.byteLength <= 10 * 1024 * 1024, 'Package tarball size is invalid');
  const archive = gunzipSync(compressed, { maxOutputLength: 32 * 1024 * 1024 });
  invariant(archive.byteLength % 512 === 0, 'Package tar archive is not block aligned');

  const files = new Map();
  let offset = 0;
  let zeroBlocks = 0;
  while (offset < archive.byteLength) {
    const header = archive.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      if (zeroBlocks === 2) break;
      continue;
    }
    invariant(zeroBlocks === 0, 'Package tar contains data after an end marker');
    validateTarChecksum(header);
    invariant(header.subarray(257, 263).toString('ascii') === 'ustar\0', 'Package tar entry is not POSIX ustar');
    const rawName = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
    const rawPrefix = header.subarray(345, 500).toString('utf8').replace(/\0.*$/u, '');
    const name = rawPrefix ? `${rawPrefix}/${rawName}` : rawName;
    const size = parseOctal(header.subarray(124, 136), 'entry size');
    const mode = parseOctal(header.subarray(100, 108), 'entry mode');
    const type = header[156];
    invariant(type === 0 || type === 0x30, `Package tar contains unsupported entry type for ${name}`);
    invariant(name.startsWith('package/') && !name.includes('\\'), `Package tar path is invalid: ${name}`);
    const relativePath = name.slice('package/'.length);
    invariant(
      relativePath.length > 0 &&
      !relativePath.startsWith('/') &&
      !relativePath.split('/').includes('..') &&
      !relativePath.split('/').includes('.'),
      `Package tar path escapes its root: ${name}`
    );
    invariant(!files.has(relativePath), `Package tar contains a duplicate path: ${relativePath}`);
    invariant(size <= 16 * 1024 * 1024, `Package entry is unexpectedly large: ${relativePath}`);
    invariant(offset + size <= archive.byteLength, `Package tar entry is truncated: ${relativePath}`);
    files.set(relativePath, Object.freeze({
      content: Buffer.from(archive.subarray(offset, offset + size)),
      mode,
      size
    }));
    offset += Math.ceil(size / 512) * 512;
  }
  invariant(zeroBlocks >= 2, 'Package tar does not contain a complete end marker');
  invariant(archive.subarray(offset).every((byte) => byte === 0), 'Package tar has data after its end marker');
  invariant(files.size > 0, 'Package tar is empty');
  return Object.freeze({ artifact: basename(artifact), compressed, files });
}

export async function writeExtractedPackage(archive, destination) {
  for (const [path, entry] of archive.files) {
    const target = join(destination, ...path.split('/'));
    const parent = target.slice(0, target.length - basename(target).length);
    await mkdir(parent, { recursive: true });
    await writeFile(target, entry.content, { flag: 'wx', mode: 0o600 });
  }
}
