import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    advanced: 'src/advanced.ts',
    testing: 'src/testing.ts'
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  external: ['@momics/iroh-http-node', '@momics/iroh-http-shared']
});
