import { resolve } from "node:path";

import { defineConfig } from "vitest/config";

// Mirror the `@/*` path alias from tsconfig.json so unit tests can
// import the same way the rest of the codebase does. Without this,
// `@/lib/prisma` etc. fail to resolve in Vitest's bundler.
export default defineConfig({
  resolve: {
    alias: {
      "@": resolve(__dirname, "./src"),
    },
  },
  test: {
    // Unit tests only — e2e/*.spec.ts belongs to Playwright, which
    // vitest's default include pattern would otherwise pick up.
    include: ["src/**/*.test.ts"],
    // Each test file gets its own process so module-level state
    // (env mutation, the issuer cache) doesn't bleed between files.
    isolate: true,
    // We don't have DOM-touching tests at this level — keep it node.
    environment: "node",
  },
});
