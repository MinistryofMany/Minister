import { randomBytes } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Prisma } from "@/generated/prisma";
import { prisma } from "@/lib/prisma";
import { recomputeAllStats } from "@/lib/stats-recompute";
import { __clearSybilConfigCache } from "@/lib/sybil-config";
import {
  SYBIL_BADGE_WEIGHT_SEED,
  SYBIL_BUCKET_CONFIG_SEED,
  SYBIL_CATEGORY_SEED,
} from "@/lib/sybil-config";
import { BUILTIN_COHORT_DEFS } from "@/lib/cohort-filter";
import { getIssuer } from "@/lib/issuer";

// LIVE real-Postgres suite for the stats recompute (anti-sybil phase 2, §4).
// Runs ONLY when MINISTER_STATS_DB_TEST=1 with a reachable DATABASE_URL whose
// schema has been pushed. `pnpm test` skips it silently otherwise, so the
// offline gate stays green (mirrors merge.db.test.ts).
//
//   MINISTER_STATS_DB_TEST=1 OIDC_PAIRWISE_SECRET=$(head -c 32 /dev/zero|base64) \
//     DATABASE_URL=postgresql://minister:minister@localhost:5433/minister_p2u0?schema=public \
//     pnpm --filter @minister/app exec vitest run src/lib/stats-recompute.db.test.ts

const LIVE = process.env.MINISTER_STATS_DB_TEST === "1";

function rid(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

const createdUserIds: string[] = [];
let native = "";

async function makeUser(
  badges: Array<{ type: string; attributes: Record<string, unknown> }>,
): Promise<void> {
  const id = rid("u");
  createdUserIds.push(id);
  await prisma.user.create({ data: { id } });
  for (const b of badges) {
    await prisma.badge.create({
      data: {
        userId: id,
        type: b.type,
        attributes: b.attributes as Prisma.InputJsonValue,
        vcJwt: rid("vc"),
        issuer: native,
      },
    });
  }
}

describe.runIf(LIVE)("recomputeAllStats (live DB)", () => {
  beforeAll(async () => {
    native = (await getIssuer()).did;

    // Seed the scorer config so bucket scoring is meaningful.
    await prisma.sybilCategory.createMany({ data: [...SYBIL_CATEGORY_SEED], skipDuplicates: true });
    await prisma.badgeWeight.createMany({
      data: SYBIL_BADGE_WEIGHT_SEED.map((r) => ({
        badgeType: r.badgeType,
        qualifier: r.qualifier,
        sybilWeight: r.sybilWeight,
        recoveryWeight: r.recoveryWeight,
        category: r.category,
        allowSoloRecovery: r.allowSoloRecovery,
      })),
      skipDuplicates: true,
    });
    await prisma.sybilBucketConfig.upsert({
      where: { id: "singleton" },
      create: { ...SYBIL_BUCKET_CONFIG_SEED },
      update: {},
    });
    __clearSybilConfigCache();

    // A github cohort def.
    const def = BUILTIN_COHORT_DEFS[0]!;
    const existing = await prisma.cohortStatDef.findFirst({ where: { label: def.label } });
    if (!existing) {
      await prisma.cohortStatDef.create({
        data: {
          label: def.label,
          numeratorFilter: def.numeratorFilter,
          denominatorFilter: def.denominatorFilter,
        },
      });
    }

    // A handful of holders: two aged github accounts, one fresh, one email-only.
    await makeUser([
      { type: "oauth-account", attributes: { provider: "github" } },
      { type: "account-age", attributes: { provider: "github", olderThanMonths: 36 } },
    ]);
    await makeUser([
      { type: "oauth-account", attributes: { provider: "github" } },
      { type: "account-age", attributes: { provider: "github", olderThanMonths: 24 } },
    ]);
    await makeUser([{ type: "oauth-account", attributes: { provider: "github" } }]);
    await makeUser([{ type: "email-domain", attributes: { domain: "example.com" } }]);
  }, 60_000);

  afterAll(async () => {
    if (!LIVE) return;
    await prisma.badge.deleteMany({ where: { userId: { in: createdUserIds } } });
    await prisma.user.deleteMany({ where: { id: { in: createdUserIds } } });
  });

  it("is idempotent: two runs produce identical materialized rows", async () => {
    await recomputeAllStats();
    const first = {
      badge: await prisma.badgeStat.findMany({
        orderBy: [{ badgeType: "asc" }, { attributeKey: "asc" }, { attributeValue: "asc" }],
      }),
      bucket: await prisma.bucketStat.findMany({ orderBy: { bucket: "asc" } }),
      cohort: await prisma.cohortStat.findMany({ orderBy: { defId: "asc" } }),
    };

    await recomputeAllStats();
    const second = {
      badge: await prisma.badgeStat.findMany({
        orderBy: [{ badgeType: "asc" }, { attributeKey: "asc" }, { attributeValue: "asc" }],
      }),
      bucket: await prisma.bucketStat.findMany({ orderBy: { bucket: "asc" } }),
      cohort: await prisma.cohortStat.findMany({ orderBy: { defId: "asc" } }),
    };

    // Compare the materialized DATA, not volatile surrogate keys: delete-and-
    // rewrite mints a fresh cuid `id` per BadgeStat row each run, and `computedAt`
    // moves — neither bears on idempotency of the stats themselves.
    const strip = <T extends { computedAt: Date }>(rows: T[]) =>
      rows.map(({ computedAt: _c, ...rest }) => {
        const r = rest as Record<string, unknown>;
        delete r.id;
        return r;
      });

    expect(strip(second.badge)).toEqual(strip(first.badge));
    expect(strip(second.bucket)).toEqual(strip(first.bucket));
    expect(strip(second.cohort)).toEqual(strip(first.cohort));
  });

  it("materializes the expected github distribution + cohort + all 5 buckets", async () => {
    await recomputeAllStats();

    // oauth-account{provider=github}: 3 distinct holders.
    const oauth = await prisma.badgeStat.findUnique({
      where: {
        badgeType_attributeKey_attributeValue: {
          badgeType: "oauth-account",
          attributeKey: "provider",
          attributeValue: "github",
        },
      },
    });
    expect(oauth?.count).toBe(3);

    // No PII key ever materialized (email-domain publishes only its type total).
    const leaked = await prisma.badgeStat.findMany({
      where: {
        attributeKey: { in: ["domain", "email", "handle", "fingerprint", "state", "city"] },
      },
    });
    expect(leaked).toHaveLength(0);

    // Cohort: aged (>=24mo) github accounts = 2, of 3 github accounts.
    const cohort = await prisma.cohortStat.findFirst();
    expect(cohort?.numerator).toBe(2);
    expect(cohort?.denominator).toBe(3);

    // All five bucket rows exist.
    const buckets = await prisma.bucketStat.findMany();
    expect(buckets.map((b) => b.bucket).sort()).toEqual([0, 1, 2, 3, 4]);
  });
});
