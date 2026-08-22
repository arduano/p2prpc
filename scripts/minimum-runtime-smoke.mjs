import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import process from 'node:process';

process.env.NAPI_RS_ENFORCE_VERSION_CHECK = '1';
const { fileSource } = await import('@p2prpc/core');

const directory = await mkdtemp(join(tmpdir(), 'p2prpc-minimum-runtime-'));
try {
  const path = join(directory, 'smoke.bin');
  await writeFile(path, Uint8Array.of(1, 2, 3));
  const source = await fileSource(path);
  const data = await source.readChunk(0, 64 * 1024);
  assert.equal(source.size, 3);
  assert.deepEqual([...data], [1, 2, 3]);
  process.stdout.write(`Runtime smoke passed on ${process.version}.\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
