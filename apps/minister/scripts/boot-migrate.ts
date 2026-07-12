#!/usr/bin/env tsx
// Container boot step: load SSM SecureString secrets into the environment,
// then run `prisma migrate deploy` so the migration run sees DATABASE_URL.
//
// Why this exists: the app self-loads SSM secrets from the Next.js
// instrumentation hook (src/lib/secrets.ts) during `next start`, but the
// production CMD runs the schema step BEFORE `next start`. DATABASE_URL lives
// only in SSM in prod, so without this preload the pre-start step has no
// DATABASE_URL and the container crash-loops. This script performs the same SSM
// load first, then spawns `migrate deploy` with the populated env. `next start`
// still self-loads via instrumentation, so only the pre-start migration needs
// this wrapper.
//
// Fail-closed: loadSecretsFromSsm throws in production if SSM is unreachable or
// a required secret is missing, and a non-zero migrate-deploy exit propagates
// here — either way this process exits non-zero and the CMD's `&&` stops the
// container before it can serve against an unmigrated / wrong database. With no
// MINISTER_SECRETS_SSM_PATH set (dev/local) the load is an inert no-op and
// migrate deploy runs against the env's DATABASE_URL exactly as before.
//
// Why `migrate deploy`, not `db push --accept-data-loss`: `db push` reconciles
// the live DB to schema.prisma with a data-loss heuristic that we were forced to
// silence with --accept-data-loss to boot past an additive-but-flagged change
// (the crypto-core `User.dedupHandle @unique`). As a permanent default that flag
// meant a future column drop or narrow would silently apply at boot with no
// review. `migrate deploy` instead applies only the reviewed, committed SQL in
// prisma/migrations/ in order, runs no destructive heuristic, and fails closed on
// drift or a checksum mismatch — nothing lands in prod that was not committed and
// reviewed first.
//
// Migrations workflow going forward:
//   1. Edit prisma/schema.prisma.
//   2. `pnpm --filter @minister/app db:migrate` (prisma migrate dev) locally to
//      generate a new prisma/migrations/<timestamp>_<name>/ folder and apply it
//      to your dev DB. Review the generated SQL — a drop/narrow is a real
//      data-loss step and must be intentional.
//   3. Commit the migration folder with the schema change.
//   4. On deploy, this script (`migrate deploy`) applies the pending migration.
//
// One-time prod baseline: the prod DB already has the full current schema (it
// was synced by `db push`), so the initial `0_init` migration must be marked as
// already-applied there, NOT re-run, or `migrate deploy` errors trying to
// recreate existing tables. Once, against prod DATABASE_URL:
//   prisma migrate resolve --applied 0_init
// After that, `migrate deploy` sees 0_init as applied and is a no-op until the
// next committed migration.

import { spawnSync } from "node:child_process";

import { loadSecretsFromSsm } from "../src/lib/secrets";

async function main(): Promise<void> {
  await loadSecretsFromSsm();

  const migrate = spawnSync("pnpm", ["prisma", "migrate", "deploy"], {
    stdio: "inherit",
    env: process.env,
  });

  if (migrate.error) throw migrate.error;
  if (migrate.status !== 0) process.exit(migrate.status ?? 1);

  // Seed the anti-sybil / recovery config tables AFTER the schema is migrated.
  // Idempotent + fail-closed: weights/categories/cutoffs upsert to their seed
  // values, and cohort defs are reconciled to the code-defined BUILTIN_COHORT_DEFS
  // (cohorts are code-authored now — any def not in code is removed). A non-zero
  // seed exit stops the container rather than booting into a half-seeded config
  // the boot-check would (correctly) reject in prod.
  const seed = spawnSync("pnpm", ["exec", "tsx", "scripts/seed-sybil-config.ts"], {
    stdio: "inherit",
    env: process.env,
  });

  if (seed.error) throw seed.error;
  process.exit(seed.status ?? 1);
}

main().catch((err: unknown) => {
  console.error("[boot-migrate] failed:", err);
  process.exit(1);
});
