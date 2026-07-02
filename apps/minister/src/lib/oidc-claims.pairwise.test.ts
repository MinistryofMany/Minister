import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildPairwiseUserDid,
  buildUserDid,
  issueVc,
  loadIssuer,
  verifyVc,
  _resetIssuerCache,
  type Issuer,
} from "@minister/vc";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Mock the two IO seams loadApprovedBadgeJwts touches. Everything else
// (buildPairwiseUserDid, reMintVc, pairwiseJti) is the REAL code path, so this
// exercises the actual disclosure transformation an RP receives.
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn() }));
vi.mock("@/lib/prisma", () => ({ prisma: { badge: { findMany: vi.fn() } } }));

import { getIssuer } from "@/lib/issuer";
import { loadApprovedBadgeJwts } from "@/lib/oidc-claims";
import { ACCESS_TOKEN_TTL, pairwiseSub } from "@/lib/oidc-tokens";
import { prisma } from "@/lib/prisma";

const USER = "internal_user_42";
const CLIENT_A = "rp_alpha";
const CLIENT_B = "rp_bravo";
const BADGE_ID = "badge_cuid_stable_0001";

const ORIGINAL_PAIRWISE = process.env.OIDC_PAIRWISE_SECRET;

let tmpDir: string;
let issuer: Issuer;

// A single stored badge for USER, with the stable :users: subject and
// jti = badge.id — the pre-MIN-1 shape the disclosure path must sweep away.
async function storedBadge(opts: { expiresAt?: Date | null } = {}) {
  const subjectDid = buildUserDid(issuer.domain, USER);
  const vcJwt = await issueVc(
    issuer,
    "email-domain",
    subjectDid,
    { domain: "example.com" },
    { jti: BADGE_ID, expiresIn: "1y" },
  );
  return { id: BADGE_ID, vcJwt, expiresAt: opts.expiresAt ?? null };
}

function trailingSub(subjectDid: string): string {
  const marker = ":u:";
  return subjectDid.slice(subjectDid.lastIndexOf(marker) + marker.length);
}

beforeAll(async () => {
  process.env.OIDC_PAIRWISE_SECRET = "test-pairwise-secret-32-chars-min!!";
  tmpDir = await mkdtemp(join(tmpdir(), "minister-pairwise-test-"));
  _resetIssuerCache();
  issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
  vi.mocked(getIssuer).mockResolvedValue(issuer);
});

afterAll(async () => {
  _resetIssuerCache();
  await rm(tmpDir, { recursive: true, force: true });
  if (ORIGINAL_PAIRWISE === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
  else process.env.OIDC_PAIRWISE_SECRET = ORIGINAL_PAIRWISE;
});

beforeEach(() => {
  vi.mocked(prisma.badge.findMany).mockReset();
});

// Disclose the same stored badge to a given RP with the sub Minister would
// stamp into that RP's id_token (pairwiseSub, absent a merge override). Pass
// a shared `row` to disclose the SAME stored artifact to several RPs — the
// colluding-adversary setup.
async function discloseTo(clientId: string, row?: Awaited<ReturnType<typeof storedBadge>>) {
  const badgeRow = row ?? (await storedBadge());
  vi.mocked(prisma.badge.findMany).mockResolvedValue([badgeRow] as never);
  const sub = pairwiseSub(USER, clientId);
  const [jwt] = await loadApprovedBadgeJwts(USER, clientId, sub, [BADGE_ID]);
  const verified = await verifyVc(issuer, jwt!);
  return { jwt: jwt!, verified, sub, row: badgeRow };
}

describe("loadApprovedBadgeJwts — pairwise disclosure (MIN-1)", () => {
  it("returns [] for an empty badge id list without touching the DB", async () => {
    const out = await loadApprovedBadgeJwts(USER, CLIENT_A, "sub", []);
    expect(out).toEqual([]);
    expect(prisma.badge.findMany).not.toHaveBeenCalled();
  });

  // Property 1 — cross-RP subject unlinkability.
  it("discloses a DIFFERENT badge subject to two relying parties for one user", async () => {
    const a = await discloseTo(CLIENT_A);
    const b = await discloseTo(CLIENT_B);
    expect(a.verified.vc.credentialSubject.id).not.toBe(b.verified.vc.credentialSubject.id);
    expect(a.verified.sub).not.toBe(b.verified.sub);
    // Neither disclosed subject leaks the stable internal user id.
    expect(a.jwt).not.toContain(USER);
    expect(b.jwt).not.toContain(USER);
  });

  // Property 2 — holder bindability: the subject's trailing component equals
  // the id_token sub minted for that same (user, client).
  it("binds the badge subject's trailing component to the id_token sub", async () => {
    const a = await discloseTo(CLIENT_A);
    expect(a.verified.sub).toBe(buildPairwiseUserDid(issuer.domain, a.sub));
    expect(trailingSub(a.verified.sub)).toBe(a.sub);
    expect(a.sub).toBe(pairwiseSub(USER, CLIENT_A)); // == the id_token sub
  });

  // Property 3 — cross-RP jti unlinkability, and jti != badge.id.
  it("gives the badge a different jti per RP, never the raw badge id", async () => {
    const a = await discloseTo(CLIENT_A);
    const b = await discloseTo(CLIENT_B);
    expect(a.verified.jti).not.toBe(b.verified.jti);
    expect(a.verified.jti).not.toBe(BADGE_ID);
    expect(b.verified.jti).not.toBe(BADGE_ID);
    expect(a.jwt).not.toContain(BADGE_ID);
  });

  // Property 4 — no residual shared correlator: only iss/kid + claim values
  // are equal across the two disclosures; sub, credentialSubject.id, jti, iat,
  // and exp are all re-derived/re-stamped from DISCLOSURE state.
  it("shares only iss, kid and the claim values across two RP disclosures", async () => {
    // One stored row disclosed to both RPs — the exact colluding-RP input.
    const row = await storedBadge();
    const a = await discloseTo(CLIENT_A, row);
    const b = await discloseTo(CLIENT_B, row);
    // Equal by design:
    expect(a.verified.iss).toBe(b.verified.iss);
    expect(decodeProtectedHeader(a.jwt).kid).toBe(decodeProtectedHeader(b.jwt).kid);
    const { id: _ida, ...claimsA } = a.verified.vc.credentialSubject;
    const { id: _idb, ...claimsB } = b.verified.vc.credentialSubject;
    expect(claimsA).toEqual(claimsB);
    // Differ (the correlators):
    expect(a.verified.sub).not.toBe(b.verified.sub);
    expect(a.verified.vc.credentialSubject.id).not.toBe(b.verified.vc.credentialSubject.id);
    expect(a.verified.jti).not.toBe(b.verified.jti);
    // iat is re-stamped to disclosure time, not the stored issuance time — it
    // is a fresh, present-day timestamp on both.
    const nowSec = Math.floor(Date.now() / 1000);
    expect(Math.abs(a.verified.iat - nowSec)).toBeLessThan(120);
    expect(Math.abs(b.verified.iat - nowSec)).toBeLessThan(120);
    // exp must carry ZERO issuance information. The stored VC's exp is
    // issuance + 1y at second granularity — a stable ~25-bit value identical
    // at every RP; two colluding RPs could join on (type, claims, exp) and
    // re-link the user, defeating the pairwise sub/jti next to it. The
    // disclosed exp is pinned to a NON-ISSUANCE value: exactly iat (disclosure
    // time) + the constant disclosure TTL, and never the stored exp.
    const storedExp = decodeJwt(row.vcJwt).exp!;
    expect(a.verified.exp).toBe(a.verified.iat + ACCESS_TOKEN_TTL);
    expect(b.verified.exp).toBe(b.verified.iat + ACCESS_TOKEN_TTL);
    expect(a.verified.exp).not.toBe(storedExp);
    expect(b.verified.exp).not.toBe(storedExp);
  });

  // Property 5 — the colluding-RP adversary. Two RPs pool their disclosed VCs
  // and try to derive a common identifier for the user. Frame it as the attack:
  // enumerate every value the attacker sees and assert none of the
  // user-identifying ones match, and the internal id is nowhere.
  it("defeats two colluding RPs: no pooled value yields a common user identifier", async () => {
    const row = await storedBadge();
    const a = await discloseTo(CLIENT_A, row);
    const b = await discloseTo(CLIENT_B, row);

    // The attacker's join keys: subject, credentialSubject.id, jti.
    const joinKeysA = [a.verified.sub, a.verified.vc.credentialSubject.id, a.verified.jti];
    const joinKeysB = [b.verified.sub, b.verified.vc.credentialSubject.id, b.verified.jti];
    for (const ka of joinKeysA) {
      for (const kb of joinKeysB) {
        expect(ka).not.toBe(kb);
      }
    }
    // Timestamp channel: neither RP's copy carries the badge's stable
    // issuance-derived exp (the value both would share), so joining on
    // (type, claims, exp) yields disclosure times, not a user identifier.
    const storedExp = decodeJwt(row.vcJwt).exp!;
    expect(a.verified.exp).not.toBe(storedExp);
    expect(b.verified.exp).not.toBe(storedExp);
    // The stable internal user id is present in neither raw VC.
    expect(a.jwt.includes(USER)).toBe(false);
    expect(b.jwt.includes(USER)).toBe(false);
  });

  // Property 8 — lifetime not extended: exp clamped to Badge.expiresAt.
  it("clamps the disclosed VC exp to Badge.expiresAt (never extends lifetime)", async () => {
    const badgeExpiresAt = new Date((Math.floor(Date.now() / 1000) + 3 * 86_400) * 1000);
    const row = await storedBadge({ expiresAt: badgeExpiresAt });
    vi.mocked(prisma.badge.findMany).mockResolvedValue([row] as never);
    const [jwt] = await loadApprovedBadgeJwts(USER, CLIENT_A, pairwiseSub(USER, CLIENT_A), [
      BADGE_ID,
    ]);
    const v = await verifyVc(issuer, jwt!);
    expect(v.exp!).toBeLessThanOrEqual(Math.floor(badgeExpiresAt.getTime() / 1000));
  });

  // Property 9 — signature integrity: the re-minted VC verifies against the
  // issuer's live key with the correct iss/kid.
  it("re-minted VCs verify against the issuer key with correct iss/kid", async () => {
    const a = await discloseTo(CLIENT_A);
    expect(a.verified.iss).toBe(issuer.did);
    expect(decodeProtectedHeader(a.jwt).kid).toBe(issuer.kid);
    await expect(verifyVc(issuer, a.jwt)).resolves.toBeTruthy();
  });

  // Merge seam: when the id_token sub is a SubjectOverride value (not the pure
  // pairwiseSub), the disclosed badge subject still binds to THAT sub — so a
  // merged account's badges remain bindable at the RP.
  it("binds the subject to the caller-supplied resolved sub (account-merge override)", async () => {
    const row = await storedBadge();
    vi.mocked(prisma.badge.findMany).mockResolvedValue([row] as never);
    const overrideSub = "donor_historical_pairwise_sub_value";
    const [jwt] = await loadApprovedBadgeJwts(USER, CLIENT_A, overrideSub, [BADGE_ID]);
    const v = await verifyVc(issuer, jwt!);
    expect(v.sub).toBe(buildPairwiseUserDid(issuer.domain, overrideSub));
    expect(trailingSub(v.sub)).toBe(overrideSub);
  });

  it("scopes the DB query to the owning user AND Minister's own issuer DID", async () => {
    // userId: a stale approved id can't surface another user's badge.
    // issuer: a foreign-issuer row (future badge import) can never reach
    // reMintVc — it is excluded at the query, so it is silently not disclosed
    // instead of failing the whole grant.
    vi.mocked(prisma.badge.findMany).mockResolvedValue([] as never);
    await loadApprovedBadgeJwts(USER, CLIENT_A, "sub", [BADGE_ID]);
    expect(prisma.badge.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { userId: USER, id: { in: [BADGE_ID] }, issuer: issuer.did },
      }),
    );
  });

  // Signing-oracle defense (defense-in-depth behind the issuer scoping): a row
  // whose vcJwt Minister's key did not sign — a DB-write attacker's forgery —
  // must never be laundered through disclosure into a Minister-signed VC.
  it("refuses to disclose a stored row whose vcJwt is not signed by Minister's key", async () => {
    const forgedTmp = await mkdtemp(join(tmpdir(), "minister-forged-key-"));
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
      vi.mocked(prisma.badge.findMany).mockResolvedValue([
        { id: BADGE_ID, vcJwt: forgedVcJwt, expiresAt: null },
      ] as never);
      await expect(
        loadApprovedBadgeJwts(USER, CLIENT_A, pairwiseSub(USER, CLIENT_A), [BADGE_ID]),
      ).rejects.toThrow(/refusing to re-sign/);
    } finally {
      await rm(forgedTmp, { recursive: true, force: true });
    }
  });
});
