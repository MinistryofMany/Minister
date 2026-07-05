import { createHmac } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildPairwiseUserDid,
  buildUserDid,
  DEFAULT_DISCLOSURE_TTL_SECONDS,
  issuanceMonthOf,
  issueVc,
  loadIssuer,
  verifyVc,
  _resetIssuerCache,
  type Issuer,
} from "@minister/vc";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Mock only the IO seams (issuer singleton + Prisma). buildPairwiseUserDid,
// reMintVc, and the pairwise derivations are the REAL code path, so these
// tests exercise the exact artifact a share-link viewer receives.
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn() }));
vi.mock("@/lib/prisma", () => ({
  prisma: {
    shareLink: { findUnique: vi.fn() },
    badge: { findMany: vi.fn() },
    // The disclosure paths audit-log a per-badge omission (fail-closed omit,
    // ADR M5) instead of failing the whole request.
    auditLog: { create: vi.fn().mockResolvedValue(undefined) },
  },
}));

import { getIssuer } from "@/lib/issuer";
import type { SignetResponse, SignetTransport } from "@/lib/nullifier/signet-backend";
import { loadApprovedBadgeJwts } from "@/lib/oidc-claims";
import { pairwiseJti, pairwiseSub } from "@/lib/oidc-tokens";
import { _setPairwiseTransportForTests, shareLinkPairwiseJtiInput } from "@/lib/pairwise-backend";
import { prisma } from "@/lib/prisma";
import {
  loadShareLinkByToken,
  shareLinkPairwiseJti,
  shareLinkPairwiseSub,
} from "@/lib/share-links";

const USER = "internal_user_777";
const LINK_A = "sharelink_cuid_alpha";
const LINK_B = "sharelink_cuid_bravo";
const BADGE_ID = "badge_cuid_share_0001";
const CLIENT = "mc_some_relying_party";

const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;

let tmpDir: string;
let issuer: Issuer;
let storedVcJwt: string;

const shareFindUnique = vi.mocked(prisma.shareLink.findUnique);
const badgeFindMany = vi.mocked(prisma.badge.findMany);
const auditCreate = vi.mocked(prisma.auditLog.create);

function linkRow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: LINK_A,
    userId: USER,
    requiresAccount: false,
    expiresAt: new Date(Date.now() + 7 * 86_400_000),
    createdAt: new Date(),
    revokedAt: null,
    badgeIds: [BADGE_ID],
    ...overrides,
  };
}

function badgeRow(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: BADGE_ID,
    type: "email-domain",
    attributes: { domain: "example.com" },
    vcJwt: storedVcJwt,
    expiresAt: null,
    ...overrides,
  };
}

// Fetch the share link with the given rows mocked in, returning the single
// disclosed badge's VC JWT (most tests share this shape).
async function viewLink(
  link: ReturnType<typeof linkRow> = linkRow(),
  badges: Array<ReturnType<typeof badgeRow>> = [badgeRow()],
) {
  shareFindUnique.mockResolvedValueOnce(link as never);
  badgeFindMany.mockResolvedValueOnce(badges as never);
  const result = await loadShareLinkByToken("tok_opaque");
  return result;
}

beforeAll(async () => {
  process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  tmpDir = await mkdtemp(join(tmpdir(), "minister-share-disclosure-"));
  _resetIssuerCache();
  issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
  vi.mocked(getIssuer).mockResolvedValue(issuer);

  // The stored badge VC, signed ONCE at issuance with the global :users:
  // holder DID and jti = badge.id — the internal record that must never
  // leave Minister verbatim.
  storedVcJwt = await issueVc(
    issuer,
    "email-domain",
    buildUserDid(issuer.domain, USER),
    { domain: "example.com" },
    { jti: BADGE_ID, expiresIn: "1y" },
  );
});

afterAll(async () => {
  _resetIssuerCache();
  await rm(tmpDir, { recursive: true, force: true });
  if (ORIGINAL_PAIRWISE === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
  else process.env.OIDC_PAIRWISE_SECRET = ORIGINAL_PAIRWISE;
});

beforeEach(() => {
  shareFindUnique.mockReset();
  badgeFindMany.mockReset();
  auditCreate.mockClear();
});

describe("shareLinkPairwiseSub / shareLinkPairwiseJti", () => {
  it("derives per-LINK subjects: same user, different links → different subs", () => {
    expect(shareLinkPairwiseSub(USER, LINK_A)).not.toBe(shareLinkPairwiseSub(USER, LINK_B));
  });

  it("is deterministic per (user, link) and reveals no raw userId", () => {
    const a1 = shareLinkPairwiseSub(USER, LINK_A);
    const a2 = shareLinkPairwiseSub(USER, LINK_A);
    expect(a1).toBe(a2);
    expect(a1).not.toContain(USER);
    expect(a1).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("is domain-separated from the OIDC pairwise sub/jti spaces on identical inputs", () => {
    // Same (userId, secondComponent) strings through both HMACs must differ:
    // a share link id can never alias an OIDC clientId into the same pseudonym.
    expect(shareLinkPairwiseSub(USER, LINK_A)).not.toBe(pairwiseSub(USER, LINK_A));
    expect(shareLinkPairwiseJti(BADGE_ID, LINK_A)).not.toBe(pairwiseJti(BADGE_ID, LINK_A));
    // And the sub/jti spaces don't collide with each other either.
    expect(shareLinkPairwiseSub(USER, LINK_A)).not.toBe(shareLinkPairwiseJti(USER, LINK_A));
  });

  it("throws when no pairwise secret is configured", () => {
    const savedAuth = process.env.AUTH_SECRET;
    delete process.env.OIDC_PAIRWISE_SECRET;
    delete process.env.AUTH_SECRET;
    try {
      expect(() => shareLinkPairwiseSub(USER, LINK_A)).toThrow(/OIDC_PAIRWISE_SECRET/);
      expect(() => shareLinkPairwiseJti(BADGE_ID, LINK_A)).toThrow(/OIDC_PAIRWISE_SECRET/);
    } finally {
      process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
      if (savedAuth !== undefined) process.env.AUTH_SECRET = savedAuth;
    }
  });
});

describe("loadShareLinkByToken — pairwise disclosure re-mint (MIN-1)", () => {
  // Property 1 — the disclosed subject is the per-link pairwise :u: DID;
  // the stored :users: DID and the raw userId appear NOWHERE in the artifact.
  it("discloses a pairwise :u: subject, never the stored :users: DID or raw userId", async () => {
    const link = await viewLink();
    expect(link).not.toBeNull();
    const served = link!.badges[0]!.vcJwt;
    expect(served).not.toBe(storedVcJwt);
    expect(served).not.toContain(USER);

    const payload = decodeJwt(served);
    const expectedSubject = buildPairwiseUserDid(issuer.domain, shareLinkPairwiseSub(USER, LINK_A));
    expect(payload.sub).toBe(expectedSubject);
    const vc = payload.vc as { credentialSubject: { id: string } };
    expect(vc.credentialSubject.id).toBe(expectedSubject);
    expect(JSON.stringify(payload)).not.toContain(":users:");
    expect(JSON.stringify(payload)).not.toContain(USER);
  });

  // Property 2 — the re-minted VC still verifies under the issuer key with
  // the claim values (the disclosed fact) intact. This is what the SDK's
  // standalone verifyMinisterBadge path checks: signature, iss, and
  // credentialSubject.id === sub — all satisfied here.
  it("serves a VC that verifies under the issuer key with claims intact", async () => {
    const link = await viewLink();
    const verified = await verifyVc(issuer, link!.badges[0]!.vcJwt);
    expect(verified.iss).toBe(issuer.did);
    expect(verified.sub).toBe(verified.vc.credentialSubject.id);
    expect(verified.vc.type).toContain("MinisterEmailDomainCredential");
    expect(verified.vc.credentialSubject.domain).toBe("example.com");
  });

  // Property 3 — per-LINK unlinkability: two links from the same user over
  // the SAME stored badge disclose different subjects and different jtis.
  it("discloses DIFFERENT subjects and jtis via two different share links", async () => {
    const a = await viewLink(linkRow({ id: LINK_A }));
    const b = await viewLink(linkRow({ id: LINK_B }));
    const pa = decodeJwt(a!.badges[0]!.vcJwt);
    const pb = decodeJwt(b!.badges[0]!.vcJwt);
    expect(pa.sub).not.toBe(pb.sub);
    expect(pa.jti).not.toBe(pb.jti);
    const vcA = pa.vc as { credentialSubject: { id: string } };
    const vcB = pb.vc as { credentialSubject: { id: string } };
    expect(vcA.credentialSubject.id).not.toBe(vcB.credentialSubject.id);
  });

  // ...while ONE link stays self-consistent: every viewer (and re-fetch) of
  // the same link sees the same holder subject.
  it("discloses the SAME subject on repeated views of one link", async () => {
    const first = await viewLink();
    const second = await viewLink();
    expect(decodeJwt(first!.badges[0]!.vcJwt).sub).toBe(decodeJwt(second!.badges[0]!.vcJwt).sub);
  });

  // Property 4 — the colluding-adversary setup across DISCLOSURE SURFACES:
  // an OIDC relying party and a share-link viewer pool their VCs for the
  // same user's same badge. No join key (sub, credentialSubject.id, jti)
  // matches, and the internal user id is in neither.
  it("is unlinkable from the same user's OIDC disclosure to any RP", async () => {
    badgeFindMany.mockResolvedValueOnce([
      { id: BADGE_ID, vcJwt: storedVcJwt, expiresAt: null },
    ] as never);
    const [oidcJwt] = await loadApprovedBadgeJwts(USER, CLIENT, pairwiseSub(USER, CLIENT), [
      BADGE_ID,
    ]);
    const shared = await viewLink();
    const shareJwt = shared!.badges[0]!.vcJwt;

    const po = decodeJwt(oidcJwt!);
    const ps = decodeJwt(shareJwt);
    const vcO = po.vc as { credentialSubject: { id: string } };
    const vcS = ps.vc as { credentialSubject: { id: string } };
    const oidcKeys = [po.sub, vcO.credentialSubject.id, po.jti];
    const shareKeys = [ps.sub, vcS.credentialSubject.id, ps.jti];
    for (const ko of oidcKeys) {
      for (const ks of shareKeys) {
        expect(ko).not.toBe(ks);
      }
    }
    expect(oidcJwt).not.toContain(USER);
    expect(shareJwt).not.toContain(USER);
  });

  // Property 5 — pairwise jti + presentation-shaped exp + coarse
  // issuanceMonth: the same hardening OIDC disclosure got.
  it("carries a per-link pairwise jti, presentation exp, and issuanceMonth", async () => {
    const link = await viewLink();
    const served = link!.badges[0]!.vcJwt;
    const payload = decodeJwt(served);

    // jti: per (badge, link), never the raw badge id — and the raw id
    // appears nowhere in the artifact.
    expect(payload.jti).toBe(shareLinkPairwiseJti(BADGE_ID, LINK_A));
    expect(payload.jti).not.toBe(BADGE_ID);
    expect(served).not.toContain(BADGE_ID);

    // exp: disclosure time + the constant TTL — zero issuance information,
    // never the stored issuance-derived exp.
    const nowSec = Math.floor(Date.now() / 1000);
    expect(Math.abs(payload.iat! - nowSec)).toBeLessThan(120);
    expect(payload.exp).toBe(payload.iat! + DEFAULT_DISCLOSURE_TTL_SECONDS);
    expect(payload.exp).not.toBe(decodeJwt(storedVcJwt).exp);

    // issuanceMonth: the coarse "YYYY-MM" bucket of the TRUE issuance
    // instant, taken from the signed original.
    const vc = payload.vc as { credentialSubject: Record<string, unknown> };
    expect(vc.credentialSubject.issuanceMonth).toBe(
      issuanceMonthOf(decodeJwt(storedVcJwt).iat as number),
    );
    expect(vc.credentialSubject.issuanceMonth).toMatch(/^\d{4}-(0[1-9]|1[0-2])$/);
  });

  // Property 6 — lifetime clamps: the disclosed exp never outlives the
  // share link itself, nor the badge row's own expiry.
  it("clamps the disclosed exp to the share link's expiry", async () => {
    const linkExpiry = new Date(Date.now() + 120_000); // link dies in 2 min
    const link = await viewLink(linkRow({ expiresAt: linkExpiry }));
    const payload = decodeJwt(link!.badges[0]!.vcJwt);
    expect(payload.exp!).toBeLessThanOrEqual(Math.floor(linkExpiry.getTime() / 1000));
  });

  it("clamps the disclosed exp to Badge.expiresAt", async () => {
    const badgeExpiry = new Date(Date.now() + 60_000);
    const link = await viewLink(linkRow(), [badgeRow({ expiresAt: badgeExpiry })]);
    const payload = decodeJwt(link!.badges[0]!.vcJwt);
    expect(payload.exp!).toBeLessThanOrEqual(Math.floor(badgeExpiry.getTime() / 1000));
  });

  // Link-state gates stay ahead of any signing work.
  it("returns null for a missing, revoked, or expired link", async () => {
    shareFindUnique.mockResolvedValueOnce(null as never);
    expect(await loadShareLinkByToken("nope")).toBeNull();

    shareFindUnique.mockResolvedValueOnce(linkRow({ revokedAt: new Date() }) as never);
    expect(await loadShareLinkByToken("tok")).toBeNull();

    shareFindUnique.mockResolvedValueOnce(
      linkRow({ expiresAt: new Date(Date.now() - 1000) }) as never,
    );
    expect(await loadShareLinkByToken("tok")).toBeNull();
    expect(badgeFindMany).not.toHaveBeenCalled();
  });

  it("scopes the badge query to the owning user AND Minister's own issuer DID", async () => {
    // Same posture as the OIDC path: a foreign-issuer row (future badge
    // import) is excluded at the query — silently not disclosed rather than
    // failing the whole page — and can never reach reMintVc.
    await viewLink();
    expect(badgeFindMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ userId: USER, issuer: issuer.did }),
      }),
    );
  });

  // Signing-oracle defense, same as the OIDC path: a stored row whose vcJwt
  // Minister's key did not sign (DB-write forgery with the issuer column
  // spoofed to Minister's DID) must never be laundered into a fresh
  // Minister-signed credential. reMintVc throws on the signature check; the
  // share page OMITS that badge (fail-closed) and audit-logs — it does NOT
  // serve the forged badge, and it does NOT 500 the whole page (Finding 2).
  it("omits (never re-signs) a stored row whose vcJwt is not signed by Minister's key", async () => {
    const forgedTmp = await mkdtemp(join(tmpdir(), "minister-share-forged-"));
    try {
      _resetIssuerCache();
      const attackerIssuer = await loadIssuer({
        domain: "ministry.test", // same domain/DID — only the key differs
        devKeyPath: join(forgedTmp, "attacker.jwk"),
      });
      _resetIssuerCache();
      const forgedVcJwt = await issueVc(
        attackerIssuer,
        "email-domain",
        buildUserDid("ministry.test", USER),
        { domain: "forged.example" },
        { jti: BADGE_ID, expiresIn: "1y" },
      );
      shareFindUnique.mockResolvedValueOnce(linkRow() as never);
      badgeFindMany.mockResolvedValueOnce([badgeRow({ vcJwt: forgedVcJwt })] as never);
      const result = await loadShareLinkByToken("tok");
      // The forged badge is omitted, not served — and the page still renders.
      expect(result).not.toBeNull();
      expect(result!.badges).toEqual([]);
      // The omission is alerted, not silently swallowed.
      expect(auditCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({ action: "sharelink.badge_disclosure_omitted" }),
        }),
      );
    } finally {
      await rm(forgedTmp, { recursive: true, force: true });
    }
  });

  // Fail-closed OMIT is PER BADGE: one un-re-mintable badge on a link must not
  // take the other badges (or the page) down with it.
  it("omits only the failing badge and still discloses the healthy ones", async () => {
    const forgedTmp = await mkdtemp(join(tmpdir(), "minister-share-mixed-"));
    try {
      _resetIssuerCache();
      const attackerIssuer = await loadIssuer({
        domain: "ministry.test",
        devKeyPath: join(forgedTmp, "attacker.jwk"),
      });
      _resetIssuerCache();
      const BAD_ID = "badge_cuid_share_bad00";
      const forgedVcJwt = await issueVc(
        attackerIssuer,
        "email-domain",
        buildUserDid("ministry.test", USER),
        { domain: "forged.example" },
        { jti: BAD_ID, expiresIn: "1y" },
      );
      const link = await viewLink(linkRow({ badgeIds: [BADGE_ID, BAD_ID] }), [
        badgeRow(),
        badgeRow({ id: BAD_ID, vcJwt: forgedVcJwt }),
      ]);
      expect(link).not.toBeNull();
      // Exactly the healthy badge survives; the forged one is omitted.
      expect(link!.badges).toHaveLength(1);
      expect(link!.badges[0]!.type).toBe("email-domain");
      const verified = await verifyVc(issuer, link!.badges[0]!.vcJwt);
      expect(verified.vc.credentialSubject.domain).toBe("example.com");
      expect(auditCreate).toHaveBeenCalledTimes(1);
    } finally {
      await rm(forgedTmp, { recursive: true, force: true });
    }
  });

  it("skips (and does not re-sign) badges with an unknown type", async () => {
    const link = await viewLink(linkRow(), [badgeRow({ type: "not-a-real-type" })]);
    expect(link).not.toBeNull();
    expect(link!.badges).toEqual([]);
  });

  // ADR §2.5 decision: SHARE LINKS GET NO NULLIFIER. The link is a
  // human-audience bearer artifact, not a Sybil-gated RP — injecting a
  // persistent per-RP tracking tag into a URL-borne disclosure widens the leak
  // surface for zero gating value. loadShareLinkByToken passes no `nullifier`
  // option to reMintVc, and reMintVc strips any same-named STORED claim. This
  // pins BOTH at the share-link call site (mirroring remint.test.ts's strip
  // assertions) so a future edit copy-pasting the oidc-claims disclose block —
  // and thereby threading a nullifier into a share link — fails loudly here.
  it("never discloses a `nullifier` claim, even when the stored VC smuggles one", async () => {
    // A stored VC whose credentialSubject carries a `nullifier` claim (issueVc
    // spreads claims verbatim, so this simulates a smuggled/legacy value).
    const smuggledVcJwt = await issueVc(
      issuer,
      "email-domain",
      buildUserDid(issuer.domain, USER),
      { domain: "example.com", nullifier: "mnv1:SMUGGLED_tracking_tag" },
      { jti: BADGE_ID, expiresIn: "1y" },
    );

    const link = await viewLink(linkRow(), [badgeRow({ vcJwt: smuggledVcJwt })]);
    expect(link).not.toBeNull();
    const served = link!.badges[0]!.vcJwt;
    const payload = decodeJwt(served);
    const vc = payload.vc as { credentialSubject: Record<string, unknown> };
    expect("nullifier" in vc.credentialSubject).toBe(false);
    // And the smuggled value appears nowhere in the served artifact.
    expect(served).not.toContain("SMUGGLED_tracking_tag");
    expect(JSON.stringify(payload)).not.toContain("mnv1:");
  });
});

// A per-badge jti-derivation failure (once the pairwise seam is on Signet, a
// transient per-badge Signet error) must omit ONLY that badge and audit it —
// never reject the whole Promise.all and 500 the entire share page. This pins
// the fix that moved deriveShareLinkPairwiseJti INSIDE the per-badge try.
describe("loadShareLinkByToken — per-badge jti-derivation failure omits only that badge", () => {
  const BAD_ID = "badge_cuid_share_jtierr";

  // A signet transport that HMACs every input EXCEPT the bad badge's jti input,
  // for which it returns a malformed output so signetPairwise throws. The
  // pre-loop share-link SUB derivation and the healthy badge's jti must succeed.
  function jtiFailingTransport(badJtiInput: string): SignetTransport {
    return (_method, _path, body): Promise<SignetResponse> => {
      const input = (body as { input: string }).input;
      if (input === badJtiInput) {
        return Promise.resolve({ status: 200, json: { output: "too-short" } });
      }
      const output = createHmac("sha256", process.env.OIDC_PAIRWISE_SECRET as string)
        .update(input)
        .digest("base64url");
      return Promise.resolve({ status: 200, json: { output } });
    };
  }

  afterAll(() => {
    delete process.env.MINISTER_SUB_BACKEND;
    _setPairwiseTransportForTests(null);
  });

  it("omits only the badge whose jti derivation throws, discloses the rest, never throws the page", async () => {
    process.env.MINISTER_SUB_BACKEND = "signet";
    _setPairwiseTransportForTests(jtiFailingTransport(shareLinkPairwiseJtiInput(BAD_ID, LINK_A)));
    try {
      const badVc = await issueVc(
        issuer,
        "email-domain",
        buildUserDid(issuer.domain, USER),
        { domain: "other.example" },
        { jti: BAD_ID, expiresIn: "1y" },
      );
      const link = await viewLink(linkRow({ badgeIds: [BADGE_ID, BAD_ID] }), [
        badgeRow(),
        badgeRow({ id: BAD_ID, vcJwt: badVc }),
      ]);
      expect(link).not.toBeNull();
      // The page rendered; exactly the healthy badge survives.
      expect(link!.badges).toHaveLength(1);
      expect(link!.badges[0]!.type).toBe("email-domain");
      // The jti-failed badge is audit-logged as an omission (not silently lost).
      expect(auditCreate).toHaveBeenCalledWith(
        expect.objectContaining({
          data: expect.objectContaining({
            action: "sharelink.badge_disclosure_omitted",
            metadata: expect.objectContaining({ badgeId: BAD_ID }),
          }),
        }),
      );
    } finally {
      delete process.env.MINISTER_SUB_BACKEND;
      _setPairwiseTransportForTests(null);
    }
  });
});

describe("loadApprovedBadgeJwts — per-badge fail-closed omit (Finding 2)", () => {
  const BAD_ID = "badge_cuid_oidc_bad001";

  // A stored account-age VC whose claim the CURRENT schema rejects
  // (olderThanMonths must be one of 12|24|36|60). sanitizeDisclosedClaims
  // re-parses through that schema at disclosure, so re-mint THROWS on this one.
  async function staleAccountAgeVc(): Promise<string> {
    return issueVc(
      issuer,
      "account-age",
      buildUserDid(issuer.domain, USER),
      { provider: "github", olderThanMonths: 7 },
      { jti: BAD_ID, expiresIn: "1y" },
    );
  }

  it("omits the one badge whose sanitize throws, discloses the rest, never throws", async () => {
    const badVc = await staleAccountAgeVc();
    // Two approved badges: a healthy email-domain VC and the un-sanitizable one.
    badgeFindMany.mockResolvedValueOnce([
      { id: BADGE_ID, vcJwt: storedVcJwt, expiresAt: null },
      { id: BAD_ID, vcJwt: badVc, expiresAt: null },
    ] as never);

    const jwts = await loadApprovedBadgeJwts(USER, CLIENT, pairwiseSub(USER, CLIENT), [
      BADGE_ID,
      BAD_ID,
    ]);

    // The whole request survived (login is unaffected): exactly the healthy
    // badge is disclosed, the un-sanitizable one omitted.
    expect(jwts).toHaveLength(1);
    const verified = await verifyVc(issuer, jwts[0]!);
    expect(verified.vc.type).toContain("MinisterEmailDomainCredential");
    expect(verified.vc.credentialSubject.domain).toBe("example.com");

    // The omission is alerted for the one bad badge only.
    expect(auditCreate).toHaveBeenCalledTimes(1);
    expect(auditCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          action: "oidc.badge_disclosure_omitted",
          metadata: expect.objectContaining({ badgeId: BAD_ID, clientId: CLIENT }),
        }),
      }),
    );
  });
});
