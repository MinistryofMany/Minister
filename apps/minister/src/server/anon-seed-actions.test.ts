import { beforeEach, describe, expect, it, vi } from "vitest";

// Unit tests for the anonymous-identity server actions. @/env, @/lib/session,
// @/lib/prisma, and @/lib/audit are mocked (importing the real session module
// pulls in @/auth, which can't load under vitest; the real env module parses
// process.env at import). No live DB, no network. Focus: the governing
// invariant (only ciphertext is stored — the server never sees a plaintext
// seed), owner-gating, the feature-flag inertness, and the state machine.

const h = vi.hoisted(() => ({
  env: { ANON_IDENTITY_ENABLED: false as boolean },
  session: { user: { id: "user-123" } } as { user: { id: string } },
  audit: vi.fn((..._args: unknown[]) => Promise.resolve()),
  // Mocked rate limiter: allowed by default (set in beforeEach), flipped to
  // denied in the rate-limit describe. Keeps the real process-local limiter's
  // accumulated state out of these deterministic unit tests.
  rateLimit: {
    check: vi.fn(() => ({ allowed: true, retryAfterSeconds: 0 })),
  },
  db: {
    anonSeedEnrollment: {
      findUnique: vi.fn(),
      upsert: vi.fn(),
      update: vi.fn(),
    },
    anonSeedBlob: {
      findUnique: vi.fn(),
      findMany: vi.fn(),
      count: vi.fn(),
      upsert: vi.fn(),
      deleteMany: vi.fn(),
    },
    // $transaction(array) resolves each op (the calls already ran).
    $transaction: vi.fn(async (ops: Promise<unknown>[]) => Promise.all(ops)),
  },
}));

vi.mock("@/env", () => ({ env: h.env }));
vi.mock("@/lib/audit", () => ({ audit: h.audit }));
vi.mock("@/lib/prisma", () => ({ prisma: h.db }));
vi.mock("@/lib/rate-limit", () => ({ anonSeedActionLimiter: h.rateLimit }));
vi.mock("@/lib/session", () => ({
  requireSession: vi.fn(async () => h.session),
}));

import {
  beginAnonSeedEnrollment,
  confirmSeedBackup,
  deleteSeedBlob,
  getAnonSeedState,
  getSeedBlobs,
  putSeedBlob,
  resetAnonSeed,
} from "@/server/anon-seed-actions";

const CT = Buffer.alloc(32, 7).toString("base64url"); // valid 32-byte ciphertext
const IV = Buffer.alloc(12, 3).toString("base64url"); // valid 12-byte IV
const CRED = "cred-abc_123";

function activeEnrollment(epoch = 1) {
  return {
    userId: "user-123",
    enrollmentEpoch: epoch,
    seedGeneratedAt: new Date(),
    backupConfirmedAt: new Date(),
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  h.env.ANON_IDENTITY_ENABLED = true;
  h.session = { user: { id: "user-123" } };
  h.rateLimit.check.mockReturnValue({ allowed: true, retryAfterSeconds: 0 });
});

describe("feature-flag inertness (flag off → every action is a no-op error)", () => {
  beforeEach(() => {
    h.env.ANON_IDENTITY_ENABLED = false;
  });

  it("all actions return an error and touch no table", async () => {
    const results = await Promise.all([
      getAnonSeedState(),
      beginAnonSeedEnrollment(),
      confirmSeedBackup(),
      putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 }),
      getSeedBlobs(),
      deleteSeedBlob({ credentialId: CRED }),
      resetAnonSeed({}),
    ]);
    for (const r of results) expect(r.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.findUnique).not.toHaveBeenCalled();
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
    expect(h.db.anonSeedBlob.findMany).not.toHaveBeenCalled();
    expect(h.audit).not.toHaveBeenCalled();
  });
});

describe("putSeedBlob — stores CIPHERTEXT ONLY, owner-scoped", () => {
  beforeEach(() => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(3));
    h.db.anonSeedBlob.findUnique.mockResolvedValue(null);
    h.db.anonSeedBlob.count.mockResolvedValue(0);
    h.db.anonSeedBlob.upsert.mockResolvedValue({});
  });

  it("persists exactly {userId, credentialId, ciphertext, iv, wrapVersion} — no plaintext field", async () => {
    const res = await putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 });
    expect(res.ok).toBe(true);

    const call = h.db.anonSeedBlob.upsert.mock.calls[0]![0] as {
      where: { userId_credentialId: { userId: string; credentialId: string } };
      create: Record<string, unknown>;
    };
    // Owner-gated by the session user id, never client-supplied.
    expect(call.where.userId_credentialId.userId).toBe("user-123");
    // Only these keys are ever written — no seed/secret/KEK field can exist.
    expect(Object.keys(call.create).sort()).toEqual(
      ["ciphertext", "credentialId", "iv", "userId", "wrapVersion"].sort(),
    );
    // The stored ciphertext is exactly the decoded input bytes (opaque to us).
    expect(Buffer.from(call.create.ciphertext as Uint8Array)).toEqual(Buffer.alloc(32, 7));
    expect(Buffer.from(call.create.iv as Uint8Array)).toEqual(Buffer.alloc(12, 3));
    // Audit metadata carries no secret material.
    const auditMeta = h.audit.mock.calls[0]![2] as Record<string, unknown>;
    expect(auditMeta).toEqual({ credentialId: CRED, wrapVersion: 1, enrollmentEpoch: 3 });
  });

  it("rejects a ciphertext that is not exactly 32 bytes", async () => {
    const short = Buffer.alloc(16, 1).toString("base64url");
    const res = await putSeedBlob({
      credentialId: CRED,
      ciphertext: short,
      iv: IV,
      wrapVersion: 1,
    });
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
  });

  it("rejects an IV that is not exactly 12 bytes", async () => {
    const badIv = Buffer.alloc(16, 1).toString("base64url");
    const res = await putSeedBlob({
      credentialId: CRED,
      ciphertext: CT,
      iv: badIv,
      wrapVersion: 1,
    });
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
  });

  it("refuses to write before enrollment is ACTIVE (invariant I3)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 1,
      seedGeneratedAt: new Date(),
      backupConfirmedAt: null, // PENDING_BACKUP
    });
    const res = await putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 });
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
  });

  it("enforces the 5-blob-per-user cap for a NEW credential", async () => {
    h.db.anonSeedBlob.findUnique.mockResolvedValue(null); // new credential
    h.db.anonSeedBlob.count.mockResolvedValue(5);
    const res = await putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 });
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
  });

  it("a re-wrap of an EXISTING credential updates in place, exempt from the cap", async () => {
    h.db.anonSeedBlob.findUnique.mockResolvedValue({ id: "blob-1" }); // existing
    const res = await putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 });
    expect(res.ok).toBe(true);
    expect(h.db.anonSeedBlob.count).not.toHaveBeenCalled();
    expect(h.db.anonSeedBlob.upsert).toHaveBeenCalledOnce();
  });
});

describe("getSeedBlobs — owner-scoped, returns ciphertext + epoch", () => {
  it("returns the owner's blobs as base64url with the current epoch", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(4));
    h.db.anonSeedBlob.findMany.mockResolvedValue([
      {
        credentialId: CRED,
        ciphertext: Buffer.alloc(32, 7),
        iv: Buffer.alloc(12, 3),
        wrapVersion: 1,
      },
    ]);
    const res = await getSeedBlobs();
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(h.db.anonSeedBlob.findMany.mock.calls[0]![0].where).toEqual({ userId: "user-123" });
    expect(res.blobs).toEqual([
      { credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1, enrollmentEpoch: 4 },
    ]);
  });
});

describe("state machine", () => {
  it("beginAnonSeedEnrollment: none → PENDING_BACKUP, epoch preserved", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(null);
    h.db.anonSeedEnrollment.upsert.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 1,
      seedGeneratedAt: new Date(),
      backupConfirmedAt: null,
    });
    const res = await getStateFrom(beginAnonSeedEnrollment());
    expect(res).toEqual({ status: "pending_backup", enrollmentEpoch: 1 });
  });

  it("beginAnonSeedEnrollment refuses when a seed already exists (reset first)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(1));
    const res = await beginAnonSeedEnrollment();
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.upsert).not.toHaveBeenCalled();
  });

  it("confirmSeedBackup: PENDING_BACKUP → ACTIVE", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 1,
      seedGeneratedAt: new Date(),
      backupConfirmedAt: null,
    });
    h.db.anonSeedEnrollment.update.mockResolvedValue(activeEnrollment(1));
    const res = await getStateFrom(confirmSeedBackup());
    expect(res).toEqual({ status: "active", enrollmentEpoch: 1 });
  });

  it("confirmSeedBackup refuses when no seed was generated", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(null);
    const res = await confirmSeedBackup();
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.update).not.toHaveBeenCalled();
  });
});

describe("resetAnonSeed — epoch bump + blob wipe (anti-rollback I12)", () => {
  it("PENDING reset is free: bumps epoch, nulls timestamps, deletes blobs", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 1,
      seedGeneratedAt: new Date(),
      backupConfirmedAt: null,
    });
    h.db.anonSeedEnrollment.update.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 2,
      seedGeneratedAt: null,
      backupConfirmedAt: null,
    });
    h.db.anonSeedBlob.deleteMany.mockResolvedValue({ count: 0 });
    const res = await getStateFrom(resetAnonSeed({}));
    expect(res).toEqual({ status: "none", enrollmentEpoch: 2 });
    const updateData = h.db.anonSeedEnrollment.update.mock.calls[0]![0].data;
    expect(updateData.enrollmentEpoch).toEqual({ increment: 1 });
    expect(updateData.seedGeneratedAt).toBeNull();
    expect(updateData.backupConfirmedAt).toBeNull();
    expect(h.db.anonSeedBlob.deleteMany).toHaveBeenCalledWith({ where: { userId: "user-123" } });
  });

  it("ACTIVE reset requires the exact typed confirmation phrase", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(1));
    const missing = await resetAnonSeed({});
    expect(missing.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.update).not.toHaveBeenCalled();

    h.db.anonSeedEnrollment.update.mockResolvedValue({
      userId: "user-123",
      enrollmentEpoch: 2,
      seedGeneratedAt: null,
      backupConfirmedAt: null,
    });
    h.db.anonSeedBlob.deleteMany.mockResolvedValue({ count: 2 });
    const ok = await resetAnonSeed({ confirmPhrase: "reset my anonymous key" });
    expect(ok.ok).toBe(true);
  });
});

describe("rate limiting (spec §13) — per-user, fail closed on the write actions", () => {
  beforeEach(() => {
    // Limiter denies: the guard must bail before any DB write.
    h.rateLimit.check.mockReturnValue({ allowed: false, retryAfterSeconds: 42 });
  });

  it("putSeedBlob is refused with clear copy and touches no table", async () => {
    const res = await putSeedBlob({ credentialId: CRED, ciphertext: CT, iv: IV, wrapVersion: 1 });
    expect(res.ok).toBe(false);
    if (res.ok) return;
    expect(res.error).toMatch(/too many requests/i);
    expect(res.error).toContain("42");
    // Keyed on the session user id, not an IP.
    expect(h.rateLimit.check).toHaveBeenCalledWith("user-123");
    expect(h.db.anonSeedEnrollment.findUnique).not.toHaveBeenCalled();
    expect(h.db.anonSeedBlob.upsert).not.toHaveBeenCalled();
    expect(h.audit).not.toHaveBeenCalled();
  });

  it("beginAnonSeedEnrollment is refused and touches no table", async () => {
    const res = await beginAnonSeedEnrollment();
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.findUnique).not.toHaveBeenCalled();
    expect(h.db.anonSeedEnrollment.upsert).not.toHaveBeenCalled();
    expect(h.audit).not.toHaveBeenCalled();
  });

  it("resetAnonSeed is refused and touches no table", async () => {
    const res = await resetAnonSeed({ confirmPhrase: "reset my anonymous key" });
    expect(res.ok).toBe(false);
    expect(h.db.anonSeedEnrollment.findUnique).not.toHaveBeenCalled();
    expect(h.db.anonSeedEnrollment.update).not.toHaveBeenCalled();
    expect(h.audit).not.toHaveBeenCalled();
  });

  it("read actions are NOT rate limited (getAnonSeedState ignores the limiter)", async () => {
    h.db.anonSeedEnrollment.findUnique.mockResolvedValue(activeEnrollment(1));
    const res = await getAnonSeedState();
    expect(res.ok).toBe(true);
    expect(h.rateLimit.check).not.toHaveBeenCalled();
  });
});

// Helper: unwrap the { ok, state } result to just the state (or fail).
async function getStateFrom(
  p: Promise<{ ok: true; state: unknown } | { ok: false; error: string }>,
): Promise<unknown> {
  const r = await p;
  if (!r.ok) throw new Error(`expected ok, got: ${r.error}`);
  return r.state;
}
