import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/types.ts'],
      thresholds: {
        lines: 80,
        functions: 85,
        statements: 80,
        branches: 70,
      },
    },
    include: ['test/**/*.test.ts'],
    testTimeout: 20_000,
  },
});
