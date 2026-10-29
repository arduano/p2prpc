import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: {
      index: 'src/index.ts',
      advanced: 'src/advanced.ts',
      testing: 'src/testing.ts',
      bridge: 'src/bridge.ts'
    },
    format: ['esm'], dts: true, sourcemap: true, clean: true, treeshake: true,
    external: ['@momics/iroh-http-node', '@momics/iroh-http-shared']
  },
  {
    entry: { browser: 'src/browser.ts', files: 'src/files.ts' },
    outDir: 'dist-browser', platform: 'browser', target: 'es2022',
    format: ['esm'], dts: true, sourcemap: true, clean: true, treeshake: true
  }
]);
