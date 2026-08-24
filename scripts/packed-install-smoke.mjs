import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import process from 'node:process';
import {
  installPackedArtifact,
  packageArtifactArgument,
  run,
  temporaryDirectory
} from './package-validation-utils.mjs';

const artifact = packageArtifactArgument();
const directory = await temporaryDirectory('packed-install');
try {
  await installPackedArtifact(artifact, directory);
  const smoke = join(directory, 'smoke.mjs');
  await writeFile(smoke, `
    import assert from 'node:assert/strict';
    import * as p2prpc from '@p2prpc/core';
    import * as advanced from '@p2prpc/core/advanced';
    import * as testing from '@p2prpc/core/testing';

    assert.equal(typeof p2prpc.createP2PNode, 'function');
    assert.equal(typeof p2prpc.fileSource, 'function');
    assert.equal(typeof p2prpc.P2PError, 'function');
    assert.ok(Object.keys(p2prpc).length >= 3);
    assert.equal('dangerouslyAllowInsecureSessions' in p2prpc, false);
    assert.equal('createAdvancedP2PNode' in p2prpc, false);
    assert.equal(typeof advanced.createAdvancedP2PNode, 'function');
    assert.equal(typeof testing.dangerouslyAllowInsecureSessions, 'function');
    process.stdout.write('Packed ESM consumer import passed on ' + process.version + '.\\n');
  `, { flag: 'wx' });
  await run(process.execPath, [smoke], { cwd: directory });
} finally {
  await rm(directory, { recursive: true, force: true });
}
