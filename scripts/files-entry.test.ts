import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { build } from 'esbuild';
import ts from 'typescript';

test('the built public files entry has browser-only runtime and declaration dependencies', async () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const directory = await mkdtemp(join(tmpdir(), 'p2prpc-files-entry-'));
  try {
    await mkdir(join(directory, 'node_modules', '@arduano'), { recursive: true });
    await symlink(join(root, 'packages', 'core'), join(directory, 'node_modules', '@arduano', 'p2prpc-core'));
    await writeFile(join(directory, 'package.json'), JSON.stringify({ type: 'module' }));
    const consumer = join(directory, 'consumer.ts');
    await writeFile(consumer, `
      import { blobSource, memoryDestination } from '@arduano/p2prpc-core/files';
      import type {
        PeerFiles, FileSource, FileDestination, FileManifest, IncomingFileHandler,
        SharedFileHandle, FileMetadataSchema, MemoryFileDestination
      } from '@arduano/p2prpc-core/files';
      const source: FileSource<{ kind: string }> = blobSource(new Blob(['bytes']), {
        name: 'example.txt', metadata: { kind: 'example' }
      });
      const destination: MemoryFileDestination<{ kind: string }> = memoryDestination({ maxBytes: 32 });
      const receive: IncomingFileHandler<{ kind: string }> = offer => {
        const manifest: FileManifest<{ kind: string }> = offer.manifest;
        const incoming: FileDestination<{ kind: string }> = destination;
        return manifest.metadata?.kind === 'example' ? { accept: incoming } : { reject: true };
      };
      export function useFiles(files: PeerFiles<{ kind: string }>, schema: FileMetadataSchema<{ kind: string }>) {
        const handle: SharedFileHandle = files.share(source);
        void files.download(handle, destination);
        return { source, destination, receive, schema };
      }
    `);
    const program = ts.createProgram([consumer], {
      noEmit: true,
      strict: true,
      skipLibCheck: false,
      types: [],
      lib: ['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts'],
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      ignoreDeprecations: '6.0'
    });
    const diagnostics = ts.getPreEmitDiagnostics(program);
    assert.equal(diagnostics.length, 0, ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCurrentDirectory: () => directory,
      getCanonicalFileName: name => name,
      getNewLine: () => '\n'
    }));
    const forbidden = /(?:\/node_modules\/(?:@types\/node|@trpc\/|@momics\/))|(?:^node:)/;
    for (const file of program.getSourceFiles()) {
      assert.doesNotMatch(file.fileName, forbidden, `Unexpected declaration dependency: ${file.fileName}`);
      for (const statement of file.statements) {
        if ((ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)) &&
            statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)) {
          assert.doesNotMatch(statement.moduleSpecifier.text, /^(?:node:|@trpc\/|@momics\/)/);
        }
      }
    }
    const result = await build({
      entryPoints: [consumer],
      bundle: true,
      platform: 'browser',
      format: 'esm',
      target: 'es2022',
      write: false,
      metafile: true,
      logLevel: 'silent',
      plugins: [{
        name: 'deny-node-and-rpc',
        setup(plugin) {
          plugin.onResolve({ filter: /^(?:node:|@trpc\/|@momics\/)/ }, args => ({
            errors: [{ text: `Files entry must not load ${args.path}` }]
          }));
        }
      }]
    });
    assert.ok(result.outputFiles[0]!.contents.byteLength > 0);
    for (const input of Object.keys(result.metafile.inputs)) assert.doesNotMatch(input, forbidden);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
