import { beforeEach, describe, expect, it, vi } from "vitest";

// Unit tests for the badge-gate predicate (spec §6.4). @/env and @/lib/prisma
// are mocked (the real env module parses process.env at import; prisma needs no
// DB here). Focus: only PENDING_BACKUP gates — none/active and a disabled flag
// never do, so the gate can't bite a user without an in-progress enrollment.

const h = vi.hoisted(() => ({
  env: { ANON_IDENTITY_ENABLED: true as boolean },
  db: { anonSeedEnrollment: { findUnique: vi.fn() } },
}));

vi.mock("@/env", () => ({ env: h.env }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));

import { isAnonBackupPending } from "@/lib/anon-seed/backup-gate";

beforeEach(() => {
  vi.clearAllMocks();
  h.env.ANON_IDENTITY_ENABLED = true;
});

describe("isAnonBackupPending", () => {
  it("returns false and never queries when the flag is off", async () => {
    h.env.ANON_IDENTITY_ENABLED = false;
    expect(await isAnonBackupPending("user-1")).toBe(false);
    expect(h.db.anonSeedEnrollment.findUnique).not.toHaveBeenCalled();
  });

  it("returns false for `none` (no enrollment row)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(null);
    expect(await isAnonBackupPending("user-1")).toBe(false);
  });

  it("returns false for `none` (row with seedGeneratedAt null)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      seedGeneratedAt: null,
      backupConfirmedAt: null,
    });
    expect(await isAnonBackupPending("user-1")).toBe(false);
  });

  it("returns true for PENDING_BACKUP (seed generated, backup not confirmed)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      seedGeneratedAt: new Date(),
      backupConfirmedAt: null,
    });
    expect(await isAnonBackupPending("user-1")).toBe(true);
    expect(h.db.anonSeedEnrollment.findUnique).toHaveBeenCalledWith({
      where: { userId: "user-1" },
      select: { seedGeneratedAt: true, backupConfirmedAt: true },
    });
  });

  it("returns false for ACTIVE (both timestamps set)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      seedGeneratedAt: new Date(),
      backupConfirmedAt: new Date(),
    });
    expect(await isAnonBackupPending("user-1")).toBe(false);
  });
});
