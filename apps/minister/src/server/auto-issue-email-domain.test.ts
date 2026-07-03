import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  findFirst: vi.fn(),
  issueBadge: vi.fn(),
  audit: vi.fn(),
}));

vi.mock("@/lib/prisma", () => ({
  prisma: { badge: { findFirst: mocks.findFirst } },
}));
vi.mock("@/server/issue-badge", () => ({ issueBadge: mocks.issueBadge }));
vi.mock("@/lib/audit", () => ({ audit: mocks.audit }));

import { autoIssueEmailDomainBadge } from "./auto-issue-email-domain";

const USER = "user_1";

beforeEach(() => {
  mocks.findFirst.mockReset();
  mocks.issueBadge.mockReset();
  mocks.audit.mockReset();
  mocks.findFirst.mockResolvedValue(null);
  mocks.issueBadge.mockResolvedValue("badge_new");
  mocks.audit.mockResolvedValue(undefined);
});

describe("autoIssueEmailDomainBadge", () => {
  it("mints an email-domain badge for a non-freemail domain (only the domain)", async () => {
    await autoIssueEmailDomainBadge(USER, "Alice@Acme.COM");

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
    });
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issued", {
      domain: "acme.com",
      badgeId: "badge_new",
    });
  });

  it("skips freemail hosts and issues nothing", async () => {
    await autoIssueEmailDomainBadge(USER, "someone@gmail.com");
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

  it("fails open: a mint failure is audited, not thrown", async () => {
    mocks.issueBadge.mockRejectedValue(new Error("db down"));
    await expect(autoIssueEmailDomainBadge(USER, "carol@acme.com")).resolves.toBeUndefined();
    expect(mocks.audit).toHaveBeenCalledWith(USER, "badge.email_domain.auto_issue_failed", {
      domain: "acme.com",
      error: "db down",
    });
  });
});
