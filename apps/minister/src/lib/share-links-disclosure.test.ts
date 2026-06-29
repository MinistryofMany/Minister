import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeJwt } from "jose";
import {
  _resetIssuerCache,
  buildPairwiseUserDid,
  buildUserDid,
  issueVc,
  loadIssuer,
  verifyVc,
  type Issuer,
} from "@minister/vc";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A holder of the issuer + prisma so the mocks below can resolve the same
// instance the test built.
let testIssuer: Issuer;

vi.mock("./issuer", () => ({
  getIssuer: () => Promise.resolve(testIssuer),
}));
vi.mock("./prisma", () => ({
  prisma: {
    shareLink: { findUnique: vi.fn() },
    badge: { findMany: vi.fn() },
  },
}));

import { loadShareLinkByToken, shareLinkSubjectSub } from "./share-links";
import { prisma } from "./prisma";

const shareFindUnique = vi.mocked(prisma.shareLink.findUnique);
const badgeFindMany = vi.mocked(prisma.badge.findMany);

const RAW_USER_ID = "ckSHARE_internal_99";
const SECRET = "test-share-link-secret-aaaaaaaaaaaaaaaa";

describe("shareLinkSubjectSub", () => {
  const prev = process.env.OIDC_PAIRWISE_SECRET;
  beforeEach(() => {
    process.env.OIDC_PAIRWISE_SECRET = SECRET;
  });
  afterEach(() => {
    if (prev === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
    else process.env.OIDC_PAIRWISE_SECRET = prev;
  });

  it("is stable for the same user and reveals no raw userId", () => {
    const a = shareLinkSubjectSub(RAW_USER_ID);
    const b = shareLinkSubjectSub(RAW_USER_ID);
    expect(a).toBe(b);
    expect(a).not.toContain(RAW_USER_ID);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("differs across users", () => {
    expect(shareLinkSubjectSub("user_a")).not.toBe(shareLinkSubjectSub("user_b"));
  });

  it("is domain-separated from the OIDC pairwise sub space", async () => {
    // The OIDC pairwise sub hashes `${userId}:${clientId}`; the share-link
    // sub hashes `sharelink:${userId}`. Even if a clientId happened to be
    // empty, the prefix keeps the two HMAC inputs distinct.
    const { pairwiseSub } = await import("./oidc-tokens");
    expect(shareLinkSubjectSub(RAW_USER_ID)).not.toBe(pairwiseSub(RAW_USER_ID, ""));
  });

  it("throws when no secret is configured", () => {
    const savedPair = process.env.OIDC_PAIRWISE_SECRET;
    const savedAuth = process.env.AUTH_SECRET;
    delete process.env.OIDC_PAIRWISE_SECRET;
    delete process.env.AUTH_SECRET;
    try {
      expect(() => shareLinkSubjectSub(RAW_USER_ID)).toThrow();
    } finally {
      if (savedPair !== undefined) process.env.OIDC_PAIRWISE_SECRET = savedPair;
      if (savedAuth !== undefined) process.env.AUTH_SECRET = savedAuth;
    }
  });
});

describe("loadShareLinkByToken disclosure re-mint", () => {
  let tmpDir: string;
  let storedVcJwt: string;
  const prev = process.env.OIDC_PAIRWISE_SECRET;

  beforeEach(async () => {
    process.env.OIDC_PAIRWISE_SECRET = SECRET;
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-share-disclosure-"));
    testIssuer = await loadIssuer({
      domain: "minister.local",
      devKeyPath: join(tmpDir, "issuer.jwk"),
    });

    storedVcJwt = await issueVc(
      testIssuer,
      "email-domain",
      buildUserDid(testIssuer.domain, RAW_USER_ID),
      { domain: "example.com" },
      { jti: "badge_share_1", expiresIn: 120 },
    );

    shareFindUnique.mockReset();
    badgeFindMany.mockReset();
    shareFindUnique.mockResolvedValue({
      id: "share_1",
      userId: RAW_USER_ID,
      requiresAccount: false,
      expiresAt: new Date(Date.now() + 86_400_000),
      createdAt: new Date(),
      revokedAt: null,
      badgeIds: ["badge_share_1"],
    } as never);
    badgeFindMany.mockResolvedValue([
      {
        id: "badge_share_1",
        type: "email-domain",
        attributes: { domain: "example.com" },
        vcJwt: storedVcJwt,
      },
    ] as never);
  });

  afterEach(async () => {
    if (prev === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
    else process.env.OIDC_PAIRWISE_SECRET = prev;
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("serves a VC whose subject carries no raw userId and verifies", async () => {
    const link = await loadShareLinkByToken("tok");
    expect(link).not.toBeNull();
    const served = link!.badges[0]!.vcJwt;

    expect(served).not.toBe(storedVcJwt);
    expect(served).not.toContain(RAW_USER_ID);

    const payload = decodeJwt(served);
    expect(JSON.stringify(payload)).not.toContain(RAW_USER_ID);
    expect(JSON.stringify(payload)).not.toContain(":users:");

    const expectedSubject = buildPairwiseUserDid(
      testIssuer.domain,
      shareLinkSubjectSub(RAW_USER_ID),
    );
    expect(payload.sub).toBe(expectedSubject);

    // Still a valid, verifiable credential with intact claims + exp.
    const verified = await verifyVc(testIssuer, served);
    expect(verified.vc.credentialSubject.domain).toBe("example.com");
    expect(verified.exp).toBe(decodeJwt(storedVcJwt).exp);
  });
});
