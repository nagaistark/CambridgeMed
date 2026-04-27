import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
   plugins: [tsconfigPaths()],
   test: {
      // Look for `.env.test` specifically
      env: {
         NODE_ENV: 'test',
      },

      // 'node' environment for backend testing
      environment: 'node',

      // Where to look for the files
      include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],

      // One at a time. No concurrent DB access races
      fileParallelism: false,

      setupFiles: ['./src/tests/setup/testSetup.ts'],
      testTimeout: 10_000,
      reporters: ['verbose'],
   },
});
