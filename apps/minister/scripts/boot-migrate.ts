#!/usr/bin/env tsx
// Container boot step: load SSM SecureString secrets into the environment,
// then run `prisma db push` so the schema sync sees DATABASE_URL.
//
// Why this exists: the app self-loads SSM secrets from the Next.js
// instrumentation hook (src/lib/secrets.ts) during `next start`, but the
// production CMD runs `prisma db push` BEFORE `next start`. DATABASE_URL
// lives only in SSM in prod, so without this preload the pre-start push has
// no DATABASE_URL and the container crash-loops. This script performs the
// same SSM load first, then spawns db push with the populated env. `next
// start` still self-loads via instrumentation, so only the pre-start
// migration needs this wrapper.
//
// Fail-closed: loadSecretsFromSsm throws in production if SSM is unreachable
// or a required secret is missing, and a non-zero db-push exit propagates
// here — either way this process exits non-zero and the CMD's `&&` stops the
// container before it can serve against an unmigrated / wrong database. With
// no MINISTER_SECRETS_SSM_PATH set (dev/local) the load is an inert no-op and
// db push runs against the env's DATABASE_URL exactly as before.

import { spawnSync } from "node:child_process";

import { loadSecretsFromSsm } from "../src/lib/secrets";

async function main(): Promise<void> {
  await loadSecretsFromSsm();

  const result = spawnSync("pnpm", ["prisma", "db", "push", "--skip-generate"], {
    stdio: "inherit",
    env: process.env,
  });

  if (result.error) throw result.error;
  process.exit(result.status ?? 1);
}

main().catch((err: unknown) => {
  console.error("[boot-migrate] failed:", err);
  process.exit(1);
});
