import { defineConfig } from 'vitest/config';

/**
 * Integration suite — separate from unit tests on purpose (§1J).
 *
 * These hit a real database, so they are slower, need credentials, and must
 * not run on every `npm test`. Keeping them in their own config means the
 * unit suite stays fast and the integration suite cannot silently stop
 * running because someone tuned an include pattern.
 *
 * No `testTimeout` heroics and no retry: a flaky isolation test is a broken
 * isolation test, and retrying one until it passes is how a real leak gets
 * explained away.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.integration.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // One file at a time: the suite shares seeded fixtures, and parallel
    // mutation of them would produce failures that are about the test
    // harness rather than about isolation.
    fileParallelism: false,
  },
});
