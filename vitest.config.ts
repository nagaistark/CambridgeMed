import { loadEnv } from 'vite';
import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

export default defineConfig(({ mode }) => ({
   resolve: {
      tsconfigPaths: true,
   },
   test: {
      environment: 'node',
      include: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
      fileParallelism: false,

      /* fileURLToPath + new URL() gives Vite an unambiguous absolute path. Note: no .ts extension — Vite resolves the file itself once it has the correct absolute path to work from. */
      setupFiles: [
         fileURLToPath(
            new URL('./src/tests/setup/testSetup.ts', import.meta.url)
         ),
      ],

      testTimeout: 10_000,
      reporters: ['verbose'],
      env: loadEnv(mode, process.cwd(), ''),
   },
}));
