import { randomBytes } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import type { PrismaClient } from "@/generated/prisma";
import { mergeAccounts, reverseMerge } from "@/lib/merge";
import { derivePairwiseSubForPersistence } from "@/lib/pairwise-backend";

// LIVE real-Postgres integration suite for the account-merge core (slice 5).
//
// Runs ONLY when MINISTER_MERGE_DB_TEST=1 with a reachable DATABASE_URL whose
// schema has been pushed (see the compose Postgres in docker-compose.yml, and
// `prisma db push`). `pnpm test` skips it silently otherwise, so the offline,
// prisma-mocking unit suite in the main CI job stays green.
//
// What it proves that the mocked unit tests cannot: mergeAccounts + reverseMerge
// against a REAL relational store — the userId-FK re-points, the SubjectOverride
// per-RP pairwise preservation, the shared-RP stranding, and reversal — all move
// exactly the rows they should and leave NO row stranded on the tombstoned donor.
//
// To run:
//   pnpm compose:up                       # or any Postgres on DATABASE_URL
//   pnpm --filter @minister/app exec prisma db push
//   MINISTER_MERGE_DB_TEST=1 OIDC_PAIRWISE_SECRET=... DATABASE_URL=... \
//     pnpm --filter @minister/app exec vitest run src/lib/merge.db.test.ts

const LIVE = process.env.MINISTER_MERGE_DB_TEST === "1";

// A donor-ONLY relying party (survivor never used it → the merge writes a
// SubjectOverride so the survivor keeps presenting the donor's identity there)
// and a SHARED one (both used it → the donor's sub is irreducibly stranded).
const DONOR_ONLY_CLIENT = "mc_merge_it_donor_only";
const SHARED_CLIENT = "mc_merge_it_shared";

let prisma: PrismaClient;
const createdUserIds: string[] = [];
const createdMergeRecordIds: string[] = [];

function rid(prefix: string): string {
  return `${prefix}_${randomBytes(8).toString("hex")}`;
}

async function makeToken(userId: string, clientId: string): Promise<void> {
  await prisma.oidcAccessToken.create({
    data: {
      jti: rid("jti"),
      userId,
      clientId,
      scopes: ["openid"],
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    },
  });
}

beforeAll(async () => {
  if (!LIVE) return;
  // The persistence seam derives the frozen donor sub under this secret; set a
  // deterministic default only if the environment did not already provide one,
  // so the merge's internal derivation and this test's expectation agree.
  process.env.OIDC_PAIRWISE_SECRET ??= "merge-db-test-pairwise-secret-32chars!!";
  ({ prisma } = await import("@/lib/prisma"));
});

afterAll(async () => {
  if (!LIVE) return;
  if (createdMergeRecordIds.length > 0) {
    await prisma.mergeRecord.deleteMany({ where: { id: { in: createdMergeRecordIds } } });
  }
  if (createdUserIds.length > 0) {
    // User cascades to Badge / ShareLink / OidcAccessToken / SubjectOverride.
    await prisma.user.deleteMany({ where: { id: { in: createdUserIds } } });
  }
  await prisma.$disconnect();
});

describe.skipIf(!LIVE)("mergeAccounts (real Postgres)", () => {
  it("re-points donor rows, writes the per-RP override, strands the shared RP, and leaves nothing behind", async () => {
    const survivor = await prisma.user.create({ data: {} });
    const donor = await prisma.user.create({ data: {} });
    createdUserIds.push(survivor.id, donor.id);

    // Donor-owned domain rows that must move to the survivor.
    const badge = await prisma.badge.create({
      data: {
        userId: donor.id,
        type: "email-domain",
        attributes: {},
        vcJwt: "merge-db-fixture",
        issuer: "did:web:fixture.test",
      },
    });
    const shareLink = await prisma.shareLink.create({
      data: {
        userId: donor.id,
        token: rid("share"),
        badgeIds: [badge.id],
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      },
    });

    // Token history: donor used both RPs; survivor used only the shared one.
    await makeToken(donor.id, DONOR_ONLY_CLIENT);
    await makeToken(donor.id, SHARED_CLIENT);
    await makeToken(survivor.id, SHARED_CLIENT);

    // The sub the survivor must keep presenting to the donor-only RP.
    const expectedDonorOnlySub = await derivePairwiseSubForPersistence(donor.id, DONOR_ONLY_CLIENT);

    const summary = await mergeAccounts(survivor.id, donor.id);
    createdMergeRecordIds.push(summary.mergeRecordId);

    // Shared RP is stranded; donor-only RP gets exactly one override.
    expect(summary.strandedClients).toEqual([SHARED_CLIENT]);
    expect(summary.overridesCreated).toBe(1);
    expect(summary.moved.badge).toBe(1);
    expect(summary.moved.shareLink).toBe(1);
    expect(summary.moved.oidcAccessToken).toBe(2);

    // Donor is tombstoned into the survivor; both gens bumped.
    const donorAfter = await prisma.user.findUniqueOrThrow({ where: { id: donor.id } });
    expect(donorAfter.mergedIntoUserId).toBe(survivor.id);
    expect(donorAfter.mergedAt).not.toBeNull();
    expect(donorAfter.sessionGeneration).toBe(donor.sessionGeneration + 1);
    const survivorAfter = await prisma.user.findUniqueOrThrow({ where: { id: survivor.id } });
    expect(survivorAfter.sessionGeneration).toBe(survivor.sessionGeneration + 1);

    // Every moved row now belongs to the survivor; NONE is stranded on the donor.
    expect((await prisma.badge.findUniqueOrThrow({ where: { id: badge.id } })).userId).toBe(
      survivor.id,
    );
    expect((await prisma.shareLink.findUniqueOrThrow({ where: { id: shareLink.id } })).userId).toBe(
      survivor.id,
    );
    expect(await prisma.badge.count({ where: { userId: donor.id } })).toBe(0);
    expect(await prisma.shareLink.count({ where: { userId: donor.id } })).toBe(0);
    expect(await prisma.oidcAccessToken.count({ where: { userId: donor.id } })).toBe(0);

    // Per-RP pairwise preservation: the donor-only override carries the donor's
    // exact historical sub; the shared RP got NO override (its sub is stranded).
    const donorOnlyOverride = await prisma.subjectOverride.findUnique({
      where: { userId_clientId: { userId: survivor.id, clientId: DONOR_ONLY_CLIENT } },
    });
    expect(donorOnlyOverride?.sub).toBe(expectedDonorOnlySub);
    const sharedOverride = await prisma.subjectOverride.findUnique({
      where: { userId_clientId: { userId: survivor.id, clientId: SHARED_CLIENT } },
    });
    expect(sharedOverride).toBeNull();

    // A reversible MergeRecord was written with a usable snapshot.
    const record = await prisma.mergeRecord.findUniqueOrThrow({
      where: { id: summary.mergeRecordId },
    });
    expect(record.survivorUserId).toBe(survivor.id);
    expect(record.donorUserId).toBe(donor.id);
    expect(record.reversedAt).toBeNull();
  });

  it("reverseMerge moves the rows back, un-tombstones the donor, and drops the created override", async () => {
    const survivor = await prisma.user.create({ data: {} });
    const donor = await prisma.user.create({ data: {} });
    createdUserIds.push(survivor.id, donor.id);

    const badge = await prisma.badge.create({
      data: {
        userId: donor.id,
        type: "email-domain",
        attributes: {},
        vcJwt: "merge-db-fixture-reverse",
        issuer: "did:web:fixture.test",
      },
    });
    await makeToken(donor.id, DONOR_ONLY_CLIENT);

    const summary = await mergeAccounts(survivor.id, donor.id);
    createdMergeRecordIds.push(summary.mergeRecordId);
    expect(summary.overridesCreated).toBe(1);
    // Sanity: the badge really moved before we reverse.
    expect((await prisma.badge.findUniqueOrThrow({ where: { id: badge.id } })).userId).toBe(
      survivor.id,
    );

    const reversed = await reverseMerge(summary.mergeRecordId);
    expect(reversed.ok).toBe(true);

    // Badge is back on the donor; the donor is live again.
    expect((await prisma.badge.findUniqueOrThrow({ where: { id: badge.id } })).userId).toBe(
      donor.id,
    );
    const donorAfter = await prisma.user.findUniqueOrThrow({ where: { id: donor.id } });
    expect(donorAfter.mergedIntoUserId).toBeNull();
    expect(donorAfter.mergedAt).toBeNull();

    // The merge-created override for the donor-only RP is gone.
    const override = await prisma.subjectOverride.findUnique({
      where: { userId_clientId: { userId: survivor.id, clientId: DONOR_ONLY_CLIENT } },
    });
    expect(override).toBeNull();

    // The record is marked reversed (idempotency guard).
    const record = await prisma.mergeRecord.findUniqueOrThrow({
      where: { id: summary.mergeRecordId },
    });
    expect(record.reversedAt).not.toBeNull();
  });
});
