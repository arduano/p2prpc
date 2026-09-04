import assert from 'node:assert/strict';
import { readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import process from 'node:process';
import { build } from 'esbuild';
import {
  installPackedArtifact,
  packageArtifactArgument,
  run,
  temporaryDirectory
} from './package-validation-utils.mjs';

const artifact = packageArtifactArgument();
const directory = await temporaryDirectory('tree-shaken-native');
try {
  await installPackedArtifact(artifact, directory);
  const installedManifest = JSON.parse(await readFile(join(
    directory,
    'node_modules',
    '@arduano',
    'p2prpc-core',
    'package.json'
  ), 'utf8'));
  const external = [...new Set([
    ...Object.keys(installedManifest.dependencies ?? {}),
    ...Object.keys(installedManifest.peerDependencies ?? {}),
    ...Object.keys(installedManifest.optionalDependencies ?? {})
  ])];
  const entry = join(directory, 'entry.mjs');
  const output = join(directory, 'bundle.mjs');
  await writeFile(entry, `
    import { initTRPC } from '@trpc/server';
    import { createP2PNode, createSharedSecretSecurity } from '@arduano/p2prpc-core';

    export async function smoke() {
      const t = initTRPC.context().create();
      const router = t.router({ ping: t.procedure.query(() => 'pong') });
      const security = createSharedSecretSecurity('p2prpc-native-smoke-secret-32-bytes!', {
        authorize: () => false
      });
      const node = await createP2PNode({
        router,
        protocol: { applicationId: 'packed-native-smoke', contractVersion: '1' },
        createContext: (context) => context,
        security,
        iroh: {
          relay: { mode: 'disabled' },
          discovery: { dns: false, mdns: false }
        }
      });
      try {
        if (typeof node.id !== 'string' || node.id.length === 0) throw new Error('Native endpoint has no ID');
      } finally {
        await node.close();
      }
    }
    await smoke();
  `, { flag: 'wx' });

  const result = await build({
    absWorkingDir: directory,
    entryPoints: [entry],
    outfile: output,
    bundle: true,
    external,
    format: 'esm',
    metafile: true,
    platform: 'node',
    sourcemap: false,
    treeShaking: true,
    write: true
  });
  const bundleInputs = Object.keys(result.metafile.inputs);
  assert.ok(
    bundleInputs.some((path) => path.includes('node_modules/@arduano/p2prpc-core/dist/')),
    'Tree-shaken bundle did not include the packed @arduano/p2prpc-core runtime'
  );
  assert.ok(
    bundleInputs.every((path) => !/[\\/]dist[\\/](?:advanced|testing)\.js$/u.test(path)),
    'Root production bundle unexpectedly included an advanced or testing entrypoint'
  );
  assert.ok(
    Object.values(result.metafile.outputs).flatMap((value) => value.imports)
      .some((value) => value.path === '@momics/iroh-http-node' && value.external),
    'Tree-shaken bundle lost the native Iroh boundary'
  );

  await run(process.execPath, [output], {
    cwd: directory,
    env: { ...process.env, NAPI_RS_ENFORCE_VERSION_CHECK: '1' }
  });
  process.stdout.write(`Tree-shaken packed native smoke passed on ${process.platform}/${process.arch} ${process.version}.\n`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
