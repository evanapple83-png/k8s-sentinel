import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Vitest config for the control-plane.
 *
 * Two notable aliases:
 *   - `server-only` → noop. The lib modules guard against accidental client
 *     import via Next's `server-only` package, which throws at module-eval
 *     time outside a Next build. Vitest is "the server", so we resolve it to
 *     an empty module.
 *   - `@/…` → the app root, matching the tsconfig paths so imports in tests
 *     and source line up.
 */
export default defineConfig({
  resolve: {
    alias: {
      'server-only': resolve(here, 'test/__shims__/server-only.ts'),
      '@': here,
    },
  },
  test: {
    include: ['lib/**/*.test.ts', 'test/**/*.test.ts'],
    environment: 'node',
  },
});
