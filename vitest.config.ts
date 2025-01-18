import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      include: ['src/**/*.ts'],
      exclude: ['src/utils.ts', 'node_modules/**', 'dist/**'],
      reporter: ['text', 'json', 'html'],
      all: true,
      provider: 'v8',
    },
  },
});
