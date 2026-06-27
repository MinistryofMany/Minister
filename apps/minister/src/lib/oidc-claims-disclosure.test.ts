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

// Mock the DB client: the unit under test is the disclosure re-mint, not
// Prisma. findMany returns the stored (global-DID) VC rows; the re-mint
// happens in-process via @minister/vc.
vi.mock("./prisma", () => ({
  prisma: { badge: { findMany: vi.fn() } },
}));

import { loadApprovedBadgeJwts } from "./oidc-claims";
import { prisma } from "./prisma";

const findMany = vi.mocked(prisma.badge.findMany);

// A raw internal userId that MUST never reach a relying party.
const RAW_USER_ID = "ckUSER_internal_42";

describe("loadApprovedBadgeJwts disclosure re-mint", () => {
  let tmpDir: string;
  let issuer: Issuer;
  let storedVcJwt: string;

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-disclosure-"));
    issuer = await loadIssuer({ domain: "minister.local", devKeyPath: join(tmpDir, "issuer.jwk") });

    // The stored badge VC, signed ONCE at issuance with the global holder
    // DID embedding the raw userId - exactly what wizard.ts produces.
    storedVcJwt = await issueVc(
      issuer,
      "email-domain",
      buildUserDid(issuer.domain, RAW_USER_ID),
      { domain: "example.com" },
      { jti: "badge_email_1", expiresIn: 60 },
    );

    findMany.mockReset();
    findMany.mockResolvedValue([{ vcJwt: storedVcJwt }] as never);
  });

  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  // (a) Disclosed subject contains NO raw userId and equals the pairwise DID.
  it("re-mints with a pairwise subject that embeds no raw userId", async () => {
    const sub = "PAIRWISE_SUB_for_client_A";
    const [disclosed] = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub,
      issuer,
    });

    const payload = decodeJwt(disclosed!);
    const expectedSubject = buildPairwiseUserDid(issuer.domain, sub);
    expect(payload.sub).toBe(expectedSubject);
    const vc = payload.vc as { credentialSubject: { id: string } };
    expect(vc.credentialSubject.id).toBe(expectedSubject);

    // No raw id, no global-DID namespace anywhere in the artifact.
    expect(disclosed).not.toContain(RAW_USER_ID);
    expect(JSON.stringify(payload)).not.toContain(RAW_USER_ID);
    expect(JSON.stringify(payload)).not.toContain(":users:");
  });

  // (b) The re-minted VC still verifies (signature + claims) under @minister/vc.
  it("re-mints a VC that still verifies under the issuer key with claims intact", async () => {
    const [disclosed] = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: "s",
      issuer,
    });

    const verified = await verifyVc(issuer, disclosed!);
    expect(verified.iss).toBe(issuer.did);
    expect(verified.vc.credentialSubject.domain).toBe("example.com");
    expect(verified.vc.type).toContain("MinisterEmailDomainCredential");
    expect(verified.jti).toBe("badge_email_1");
  });

  // (c) exp is unchanged from the stored VC.
  it("preserves the stored VC's exp exactly (no validity extension)", async () => {
    const storedExp = decodeJwt(storedVcJwt).exp;
    const [disclosed] = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: "s",
      issuer,
    });
    expect(decodeJwt(disclosed!).exp).toBe(storedExp);
  });

  // (d) Two different clients yield two different subjects for the same user.
  it("yields different subjects for different relying-party subs", async () => {
    // resolveSub gives a different `sub` per (userId, clientId); the function
    // takes the already-resolved value, so distinct subs => distinct subjects.
    const [forA] = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: "sub_for_client_A",
      issuer,
    });
    const [forB] = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: "sub_for_client_B",
      issuer,
    });
    const subjectA = (decodeJwt(forA!) as { sub: string }).sub;
    const subjectB = (decodeJwt(forB!) as { sub: string }).sub;
    expect(subjectA).not.toBe(subjectB);
    expect(subjectA).toBe(buildPairwiseUserDid(issuer.domain, "sub_for_client_A"));
    expect(subjectB).toBe(buildPairwiseUserDid(issuer.domain, "sub_for_client_B"));
  });

  // (e) Merged-account path: resolveSub returns the donor's historical sub via
  // SubjectOverride. Feeding that same sub here produces a consistent subject
  // (same input sub => same subject, regardless of how it was resolved).
  it("is consistent for a merged-account override sub", async () => {
    const overrideSub = "donor_historical_sub_xyz"; // what SubjectOverride would yield
    const first = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: overrideSub,
      issuer,
    });
    const second = await loadApprovedBadgeJwts(RAW_USER_ID, ["badge_email_1"], {
      sub: overrideSub,
      issuer,
    });
    const subjectFirst = (decodeJwt(first[0]!) as { sub: string }).sub;
    const subjectSecond = (decodeJwt(second[0]!) as { sub: string }).sub;
    expect(subjectFirst).toBe(subjectSecond);
    expect(subjectFirst).toBe(buildPairwiseUserDid(issuer.domain, overrideSub));
  });

  it("returns an empty array when no badges were approved (no DB call)", async () => {
    const result = await loadApprovedBadgeJwts(RAW_USER_ID, [], { sub: "s", issuer });
    expect(result).toEqual([]);
    expect(findMany).not.toHaveBeenCalled();
  });
});
