#!/usr/bin/env tsx
// Seed the anti-sybil / recovery config tables (BadgeWeight, SybilCategory,
// SybilBucketConfig, RecoveryConfig) from the pure constants in
// src/lib/sybil-config.ts.
//
// IDEMPOTENT and INSERT-ONLY: each upsert's `update` is empty, so re-running
// this after an operator has tuned a weight in the admin UI inserts only the
// missing rows and NEVER clobbers existing operator-tuned values. Run at boot
// (from boot-migrate, after `migrate deploy`) and exposed as `sybil:seed`.
//
// Set DATABASE_URL the same way the app does.

import { PrismaClient } from "../src/generated/prisma/index.js";
import {
  RECOVERY_CONFIG_SEED,
  SYBIL_BADGE_WEIGHT_SEED,
  SYBIL_BUCKET_CONFIG_SEED,
  SYBIL_CATEGORY_SEED,
} from "../src/lib/sybil-config.js";

const prisma = new PrismaClient();

async function main(): Promise<void> {
  let created = 0;
  let existing = 0;

  for (const cat of SYBIL_CATEGORY_SEED) {
    const before = await prisma.sybilCategory.findUnique({ where: { name: cat.name } });
    await prisma.sybilCategory.upsert({
      where: { name: cat.name },
      create: { name: cat.name, cap: cat.cap },
      // Insert-only: never reset an operator-tuned cap.
      update: {},
    });
    if (before) existing++;
    else created++;
  }

  for (const row of SYBIL_BADGE_WEIGHT_SEED) {
    const before = await prisma.badgeWeight.findUnique({
      where: { badgeType_qualifier: { badgeType: row.badgeType, qualifier: row.qualifier } },
    });
    await prisma.badgeWeight.upsert({
      where: { badgeType_qualifier: { badgeType: row.badgeType, qualifier: row.qualifier } },
      create: {
        badgeType: row.badgeType,
        qualifier: row.qualifier,
        sybilWeight: row.sybilWeight,
        recoveryWeight: row.recoveryWeight,
        category: row.category,
        allowSoloRecovery: row.allowSoloRecovery,
      },
      // Insert-only: never reset operator-tuned weights / category / solo flag /
      // pending-apply window.
      update: {},
    });
    if (before) existing++;
    else created++;
  }

  {
    const before = await prisma.sybilBucketConfig.findUnique({
      where: { id: SYBIL_BUCKET_CONFIG_SEED.id },
    });
    await prisma.sybilBucketConfig.upsert({
      where: { id: SYBIL_BUCKET_CONFIG_SEED.id },
      create: {
        id: SYBIL_BUCKET_CONFIG_SEED.id,
        bucket1Raw: SYBIL_BUCKET_CONFIG_SEED.bucket1Raw,
        bucket2Raw: SYBIL_BUCKET_CONFIG_SEED.bucket2Raw,
        bucket3Raw: SYBIL_BUCKET_CONFIG_SEED.bucket3Raw,
        bucket4Raw: SYBIL_BUCKET_CONFIG_SEED.bucket4Raw,
        bucket3MinCats: SYBIL_BUCKET_CONFIG_SEED.bucket3MinCats,
        bucket4MinCats: SYBIL_BUCKET_CONFIG_SEED.bucket4MinCats,
      },
      update: {},
    });
    if (before) existing++;
    else created++;
  }

  {
    const before = await prisma.recoveryConfig.findUnique({
      where: { id: RECOVERY_CONFIG_SEED.id },
    });
    await prisma.recoveryConfig.upsert({
      where: { id: RECOVERY_CONFIG_SEED.id },
      create: { id: RECOVERY_CONFIG_SEED.id, threshold: RECOVERY_CONFIG_SEED.threshold },
      update: {},
    });
    if (before) existing++;
    else created++;
  }

  console.log(
    `[seed-sybil-config] done. inserted ${created} row(s), left ${existing} existing row(s) untouched.`,
  );
}

main()
  .catch((err: unknown) => {
    console.error("[seed-sybil-config] failed:", err);
    process.exit(1);
  })
  .finally(() => {
    void prisma.$disconnect();
  });
