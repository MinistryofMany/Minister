import { defineConfig, devices } from "@playwright/test";

import { BASE_URL, E2E_AUTH_SECRET, E2E_DATABASE_URL, E2E_PORT, MAIL_FILE } from "./e2e/env";

// E2E suite. Boots its own dev server on a dedicated port against a
// dedicated database (see e2e/env.ts) so it never collides with a
// running `pnpm dev` or its data. Sequential on purpose — specs share
// one DB and one mail-capture file.
export default defineConfig({
  testDir: "./e2e",
  globalSetup: "./e2e/global-setup.ts",
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
  },
  projects: [
    { name: "setup", testMatch: /.*\.setup\.ts/ },
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
      dependencies: ["setup"],
      testMatch: /.*\.spec\.ts/,
    },
  ],
  // Signet-backed mode (crypto-core Phase 3): playwright merges this env over
  // the caller's process.env, so `set -a; source signet-e2e/.stack/minister.env;
  // set +a` before `test:e2e` boots the dev server with
  // MINISTER_NULLIFIER_BACKEND=signet against the local/compose Signet stack
  // (see signet-e2e/README.md). Nothing sourced → default interim, unchanged.
  webServer: {
    command: `node_modules/.bin/next dev --port ${E2E_PORT}`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      DATABASE_URL: E2E_DATABASE_URL,
      AUTH_SECRET: E2E_AUTH_SECRET,
      AUTH_URL: BASE_URL,
      AUTH_TRUST_HOST: "true",
      MINISTER_ISSUER_DOMAIN: "minister.local",
      OIDC_PAIRWISE_SECRET: "e2e-only-pairwise-secret",
      MINISTER_MAIL_CAPTURE_FILE: MAIL_FILE,
      // The suite drives sign-in and OIDC endpoints far harder than a
      // human would; raise the caps so rate limiting (unit-tested
      // separately) doesn't fail unrelated specs.
      MINISTER_RL_SIGNIN_MAX: "1000",
      MINISTER_RL_AUTHORIZE_MAX: "1000",
      MINISTER_RL_TOKEN_MAX: "1000",
      MINISTER_RL_USERINFO_MAX: "1000",
      MINISTER_RL_SHARE_MAX: "1000",
    },
  },
});
