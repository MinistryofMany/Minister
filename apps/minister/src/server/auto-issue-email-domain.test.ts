import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  findFirst: vi.fn(),
  issueBadge: vi.fn(),
  audit: vi.fn(),
  ensureDedupHandle: vi.fn(),
  registerDedup: vi.fn(),
  release: vi.fn(),
  runPostCommit: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: { badge: { findFirst: mocks.findFirst } },
}));
vi.mock("@/server/issue-badge", () => ({ issueBadge: mocks.issueBadge }));
vi.mock("@/lib/audit", () => ({ audit: mocks.audit }));
// The real normalizer (@/lib/nullifier/normalize) is pure and left UNMOCKED so
// the anchor is genuinely derived; only the ledger service is stubbed.
vi.mock("@/lib/nullifier", () => ({
  ensureDedupHandle: mocks.ensureDedupHandle,
  nullifierService: { registerDedup: mocks.registerDedup, release: mocks.release },
  runPostCommit: mocks.runPostCommit,
}));

import { autoIssueEmailDomainBadge } from "./auto-issue-email-domain";

const USER = "user_1";

beforeEach(() => {
  mocks.findFirst.mockReset();
  mocks.issueBadge.mockReset();
  mocks.audit.mockReset();
  mocks.ensureDedupHandle.mockReset();
  mocks.registerDedup.mockReset();
  mocks.release.mockReset();
  mocks.runPostCommit.mockReset();
  mocks.findFirst.mockResolvedValue(null);
  mocks.issueBadge.mockResolvedValue("badge_new");
  mocks.audit.mockResolvedValue(undefined);
  mocks.ensureDedupHandle.mockResolvedValue("handle_1");
  mocks.registerDedup.mockResolvedValue({ status: "registered", entryRef: "ref_1" });
  mocks.release.mockResolvedValue(undefined);
  // Faithful to runPostCommit's contract: invoke the op (idempotent retry
  // wrapper), swallowing on failure so a release error never surfaces.
  mocks.runPostCommit.mockImplementation(async (op: () => Promise<unknown>) => {
    try {
      await op();
    } catch {
      /* swallowed, as the real wrapper does */
    }
  });
});

describe("autoIssueEmailDomainBadge", () => {
  it("registers the Sybil anchor and mints an email-domain badge carrying the nullifierRef", async () => {
    await autoIssueEmailDomainBadge(USER, "Alice@Acme.COM");

    // The anchor is the NORMALIZED full address; only it (not the badge) sees
    // the local part.
    expect(mocks.registerDedup).toHaveBeenCalledWith({
      anchor: "alice@acme.com",
      badgeType: "email-domain",
      ownerHandle: "handle_1",
    });
    expect(mocks.issueBadge).toHaveBeenCalledTimes(1);
    expect(mocks.issueBadge).toHaveBeenCalledWith({
      userId: USER,
      pluginId: "email-domain",
      badge: {
        type: "email-domain",
        attributes: { domain: "acme.com" },
        claims: { domain: "acme.com" },
      },
      dedupeKey: "email-domain:user_1:acme.com",
      nullifierRef: "ref_1",
    });
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issued", {
      domain: "acme.com",
      badgeId: "badge_new",
    });
  });

  it("skips issuance (fail-open) when the mailbox credential is TAKEN by another account", async () => {
    mocks.registerDedup.mockResolvedValue({ status: "taken" });
    await autoIssueEmailDomainBadge(USER, "alice@acme.com");
    expect(mocks.issueBadge).not.toHaveBeenCalled();
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_skipped", {
      reason: "taken",
    });
  });

  it("skips freemail hosts and issues nothing (no anchor registered)", async () => {
    await autoIssueEmailDomainBadge(USER, "someone@gmail.com");
    expect(mocks.registerDedup).not.toHaveBeenCalled();
    expect(mocks.issueBadge).not.toHaveBeenCalled();
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_skipped", {
      reason: "freemail",
    });
  });

  it("is idempotent: skips when a badge for that domain already exists", async () => {
    mocks.findFirst.mockResolvedValue({ id: "badge_existing" });
    await autoIssueEmailDomainBadge(USER, "bob@acme.com");
    expect(mocks.issueBadge).not.toHaveBeenCalled();
  });

  it("checks idempotency on the exact domain attribute", async () => {
    await autoIssueEmailDomainBadge(USER, "bob@acme.com");
    expect(mocks.findFirst).toHaveBeenCalledWith({
      where: {
        userId: USER,
        type: "email-domain",
        attributes: { path: ["domain"], equals: "acme.com" },
      },
      select: { id: true },
    });
  });

  it("does nothing for an address with no usable domain", async () => {
    await autoIssueEmailDomainBadge(USER, "no-domain");
    expect(mocks.issueBadge).not.toHaveBeenCalled();
    expect(mocks.audit).not.toHaveBeenCalled();
  });

  it("treats a concurrent duplicate (P2002 on dedupeKey) as benign, not a failure", async () => {
    // A second near-simultaneous sign-in loses the unique-constraint race.
    mocks.issueBadge.mockRejectedValue(Object.assign(new Error("unique"), { code: "P2002" }));
    await expect(autoIssueEmailDomainBadge(USER, "dave@acme.com")).resolves.toBeUndefined();
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_skipped", {
      reason: "duplicate",
    });
    // Not audited as a failure.
    expect(mocks.audit).not.toHaveBeenCalledWith(
      USER,
      "badge.email_domain.auto_issue_failed",
      expect.anything(),
    );
  });

  it("fails open on a genuine mint failure AND releases the fresh anchor (no strand)", async () => {
    mocks.issueBadge.mockRejectedValue(new Error("db down"));
    await expect(autoIssueEmailDomainBadge(USER, "carol@acme.com")).resolves.toBeUndefined();
    // The freshly-registered ledger entry is released so a signing error never
    // strands the credential.
    expect(mocks.release).toHaveBeenCalledWith({ entryRef: "ref_1", ownerHandle: "handle_1" });
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_failed", {
      domain: "acme.com",
      error: "db down",
    });
  });

  it("does NOT release the entry on an already_yours re-issue that then fails", async () => {
    // already_yours means the entry predates this attempt; releasing it could
    // strand a sibling badge, so a mint failure here must not free it.
    mocks.registerDedup.mockResolvedValue({ status: "already_yours", entryRef: "ref_pre" });
    mocks.issueBadge.mockRejectedValue(new Error("db down"));
    await expect(autoIssueEmailDomainBadge(USER, "carol@acme.com")).resolves.toBeUndefined();
    expect(mocks.release).not.toHaveBeenCalled();
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_failed", {
      domain: "acme.com",
      error: "db down",
    });
  });
});
