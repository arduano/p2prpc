import { defineConfig } from 'vitest/config';

// Keep independent qualification independent even in an enclosing workspace.
export default defineConfig({ test: { include: ['test/**/*.test.ts'] } });
