import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeJwt, decodeProtectedHeader, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildPairwiseUserDid, buildUserDid } from "./did";
import { DEFAULT_DISCLOSURE_TTL_SECONDS, reMintVc } from "./issue";
import { _resetIssuerCache, loadIssuer } from "./key";
import { verifyVc } from "./verify";
import type { Issuer } from "./types";

// Mint an "original" stored VC directly (mirrors issueVc's output) with full
// control over iat/exp/jti so the re-mint transformation can be asserted
// against known inputs.
async function signOriginal(
  issuer: Issuer,
  opts: {
    userId?: string;
    jti?: string;
    iatSec?: number;
    expSec?: number;
    claims?: Record<string, unknown>;
    credentialType?: string;
  } = {},
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const iat = opts.iatSec ?? nowSec;
  const subjectDid = buildUserDid(issuer.domain, opts.userId ?? "user_1");
  const claims = opts.claims ?? { domain: "example.com" };
  return new SignJWT({
    vc: {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      type: ["VerifiableCredential", opts.credentialType ?? "MinisterEmailDomainCredential"],
      credentialSubject: { id: subjectDid, ...claims },
    },
  })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
    .setIssuer(issuer.did)
    .setSubject(subjectDid)
    .setIssuedAt(iat)
    .setJti(opts.jti ?? "badge_original_id")
    .setExpirationTime(opts.expSec ?? nowSec + 31_536_000)
    .sign(issuer.privateKey);
}

describe("reMintVc", () => {
  let tmpDir: string;
  let issuer: Issuer;

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-remint-test-"));
    issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
  });
  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("swaps the subject to the pairwise DID (sub and credentialSubject.id) and drops the stored user id", async () => {
    const original = await signOriginal(issuer, { userId: "internal_user_42" });
    const pairwise = buildPairwiseUserDid(issuer.domain, "PAIRWISE_SUB_A");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "jti-a" });
    const v = await verifyVc(issuer, jwt);

    expect(v.sub).toBe(pairwise);
    expect(v.vc.credentialSubject.id).toBe(pairwise);
    // The stable internal user id must not survive anywhere in the disclosed VC.
    expect(jwt).not.toContain("internal_user_42");
    expect(v.sub).not.toContain(":users:");
  });

  it("preserves iss, kid, VC type, @context and every claim value", async () => {
    const original = await signOriginal(issuer, {
      claims: { provider: "github", accountId: "gh_123", handle: "octocat" },
      credentialType: "MinisterOauthAccountCredential",
    });
    const pairwise = buildPairwiseUserDid(issuer.domain, "PAIRWISE_SUB_B");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "jti-b" });
    const v = await verifyVc(issuer, jwt);
    const header = decodeProtectedHeader(jwt);

    expect(v.iss).toBe(issuer.did);
    expect(header.kid).toBe(issuer.kid);
    expect(v.vc.type).toEqual(["VerifiableCredential", "MinisterOauthAccountCredential"]);
    expect(v.vc["@context"]).toEqual(["https://www.w3.org/ns/credentials/v2"]);
    // Claim values (the disclosed facts) are unchanged; only `id` is swapped.
    const { id, ...claims } = v.vc.credentialSubject;
    expect(id).toBe(pairwise);
    expect(claims).toEqual({ provider: "github", accountId: "gh_123", handle: "octocat" });
  });

  it("sets the provided per-RP jti and never carries the raw badge id through", async () => {
    const original = await signOriginal(issuer, { jti: "badge_cuid_original" });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "per-rp-jti-xyz" });
    const v = await verifyVc(issuer, jwt);

    expect(v.jti).toBe("per-rp-jti-xyz");
    expect(v.jti).not.toBe("badge_cuid_original");
    expect(jwt).not.toContain("badge_cuid_original");
  });

  it("re-stamps iat to now (does not carry the original issuance timestamp)", async () => {
    const originalIat = Math.floor(Date.now() / 1000) - 90 * 86_400; // 90 days ago
    const original = await signOriginal(issuer, { iatSec: originalIat });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const before = Math.floor(Date.now() / 1000);
    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    const v = await verifyVc(issuer, jwt);

    expect(v.iat).not.toBe(originalIat);
    expect(v.iat).toBeGreaterThanOrEqual(before - 1);
    expect(v.nbf).toBeGreaterThanOrEqual(before - 1);
  });

  // The issuance-derived exp (issuance + fixed duration, second granularity)
  // was a stable ~25-bit cross-RP correlator that survived the pairwise
  // sub/jti sweep. The disclosed exp must be PRESENTATION-shaped: a pure
  // function of disclosure time (exp = iat + TTL), carrying zero issuance
  // information.
  it("stamps a presentation-shaped exp (iat + TTL), never the issuance-derived original exp", async () => {
    const originalExp = Math.floor(Date.now() / 1000) + 10 * 86_400; // 10 days out
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    const v = await verifyVc(issuer, jwt);

    // exp is exactly iat + the disclosure TTL — determined by disclosure time
    // plus a constant, so it can never leak the issuance instant.
    expect(v.exp).toBe(v.iat + DEFAULT_DISCLOSURE_TTL_SECONDS);
    expect(v.exp).not.toBe(originalExp);
    expect(v.exp!).toBeLessThan(originalExp);
  });

  it("honors a custom disclosureTtlSeconds and rejects a non-positive one", async () => {
    const original = await signOriginal(issuer);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const jwt = await reMintVc(issuer, original, {
      subjectId: pairwise,
      jti: "j",
      disclosureTtlSeconds: 300,
    });
    const v = await verifyVc(issuer, jwt);
    expect(v.exp).toBe(v.iat + 300);

    for (const bad of [0, -60, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      await expect(
        reMintVc(issuer, original, { subjectId: pairwise, jti: "j", disclosureTtlSeconds: bad }),
      ).rejects.toThrow(/disclosureTtlSeconds/);
    }
  });

  it("clamps exp to the original VC exp when the badge is inside its final TTL window", async () => {
    // A badge 30 minutes from real expiry: now + TTL (1h) would EXTEND its
    // lifetime, so the clamp to the original exp must win.
    const originalExp = Math.floor(Date.now() / 1000) + 30 * 60;
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    const v = await verifyVc(issuer, jwt);

    expect(v.exp).toBe(originalExp);
  });

  it("clamps exp to Badge.expiresAt when that is earlier than now + TTL", async () => {
    const originalExp = Math.floor(Date.now() / 1000) + 365 * 86_400;
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    // 10 minutes out — earlier than both the original exp and now + TTL (1h).
    const badgeExpiresAt = new Date((Math.floor(Date.now() / 1000) + 10 * 60) * 1000);

    const jwt = await reMintVc(issuer, original, {
      subjectId: pairwise,
      jti: "j",
      maxExpiresAt: badgeExpiresAt,
    });
    const v = await verifyVc(issuer, jwt);

    expect(v.exp).toBe(Math.floor(badgeExpiresAt.getTime() / 1000));
    expect(v.exp!).toBeLessThan(originalExp);
  });

  it("never extends past the original exp even when Badge.expiresAt is later", async () => {
    // Original exp 20 minutes out (inside the TTL window, so it is the min);
    // Badge.expiresAt far later must not widen it.
    const originalExp = Math.floor(Date.now() / 1000) + 20 * 60;
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const laterExpiresAt = new Date((Math.floor(Date.now() / 1000) + 999 * 86_400) * 1000);

    const jwt = await reMintVc(issuer, original, {
      subjectId: pairwise,
      jti: "j",
      maxExpiresAt: laterExpiresAt,
    });
    const v = await verifyVc(issuer, jwt);

    expect(v.exp).toBe(originalExp);
  });

  it("never emits an exp past min(now + TTL, original exp, Badge.expiresAt) for any ordering", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    // (originalExp offset, badge expiresAt offset or null) — every ordering of
    // the three bounds relative to the 1h TTL.
    const cases: Array<[number, number | null]> = [
      [365 * 86_400, null], // TTL wins
      [365 * 86_400, 10 * 60], // cap wins
      [20 * 60, 999 * 86_400], // original wins
      [10 * 60, 5 * 60], // cap wins below original
      [5 * 60, 10 * 60], // original wins below cap
    ];
    for (const [expOffset, capOffset] of cases) {
      const original = await signOriginal(issuer, { expSec: nowSec + expOffset });
      const jwt = await reMintVc(issuer, original, {
        subjectId: pairwise,
        jti: "j",
        maxExpiresAt: capOffset === null ? null : new Date((nowSec + capOffset) * 1000),
      });
      const v = await verifyVc(issuer, jwt);
      const bound = Math.min(
        v.iat + DEFAULT_DISCLOSURE_TTL_SECONDS,
        nowSec + expOffset,
        capOffset === null ? Number.POSITIVE_INFINITY : nowSec + capOffset,
      );
      expect(v.exp).toBe(bound);
    }
  });

  it("produces a VC that verifies against the issuer's live key (signature integrity)", async () => {
    const original = await signOriginal(issuer);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    // verifyVc enforces iss + alg EdDSA + typ vc+jwt against issuer.publicKey.
    await expect(verifyVc(issuer, jwt)).resolves.toMatchObject({ iss: issuer.did, sub: pairwise });
  });

  // Signing-oracle defense: reMintVc re-signs database contents under the
  // issuer key, so it must refuse any original that the issuer's own key did
  // not sign. Otherwise a DB-write attacker (or a future badge-import row)
  // gets arbitrary claims laundered into a fresh Minister-signed credential.
  it("refuses to re-sign a VC that was not signed by the issuer's own key (no signing oracle)", async () => {
    // `original` is signed by `issuer`; `other` shares the domain/DID but has
    // a different key — exactly a row smuggled in from outside the trust root.
    const original = await signOriginal(issuer);
    _resetIssuerCache();
    const other = await loadIssuer({
      domain: "ministry.test",
      devKeyPath: join(tmpDir, "other.jwk"),
    });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    await expect(reMintVc(other, original, { subjectId: pairwise, jti: "j" })).rejects.toThrow(
      /refusing to re-sign/,
    );
  });

  it("refuses to re-sign a stored VC whose payload was tampered after signing", async () => {
    const original = await signOriginal(issuer, { claims: { domain: "example.com" } });
    // Splice a modified payload (claims upgraded to a different domain) onto
    // the authentic header + signature — the classic stored-row tamper.
    const [header, payloadSeg, sig] = original.split(".");
    const payload = JSON.parse(Buffer.from(payloadSeg!, "base64url").toString("utf8")) as {
      vc: { credentialSubject: Record<string, unknown> };
    };
    payload.vc.credentialSubject.domain = "evil.example";
    const tampered = [header, Buffer.from(JSON.stringify(payload)).toString("base64url"), sig].join(
      ".",
    );
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    await expect(reMintVc(issuer, tampered, { subjectId: pairwise, jti: "j" })).rejects.toThrow(
      /refusing to re-sign/,
    );
  });

  it("refuses to re-sign a VC stamped with a foreign iss even when the signature verifies", async () => {
    // Signed with the issuer's key (signature passes) but carrying a foreign
    // `iss` — an imported credential must never be re-issued as Minister's own.
    const foreign = await new SignJWT({
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
        credentialSubject: { id: "did:web:elsewhere.example:u:x", domain: "example.com" },
      },
    })
      .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
      .setIssuer("did:web:elsewhere.example")
      .setSubject("did:web:elsewhere.example:u:x")
      .setIssuedAt()
      .setExpirationTime("1y")
      .sign(issuer.privateKey);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    await expect(reMintVc(issuer, foreign, { subjectId: pairwise, jti: "j" })).rejects.toThrow(
      /refusing to re-sign/,
    );
  });

  it("re-mints an authentic but already-EXPIRED stored VC (temporal claims are re-derived, not gated)", async () => {
    // The integrity gate checks the signature, not exp: an expired-but-real
    // badge still re-mints to an already-expired disclosure (clamped to the
    // original exp), which the RP then rejects — same fail-closed behavior as
    // before, with no 500 in the disclosure path.
    const pastExp = Math.floor(Date.now() / 1000) - 86_400;
    const original = await signOriginal(issuer, { expSec: pastExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    const decoded = decodeJwt(jwt);
    expect(decoded.exp).toBe(pastExp);
    // And the RP-side/own verify rejects it as expired — fails closed.
    await expect(verifyVc(issuer, jwt)).rejects.toBeTruthy();
  });

  it("throws (fails loud) when the original VC has no exp and no maxExpiresAt cap", async () => {
    // Craft an original with the exp claim deliberately absent.
    const subjectDid = buildUserDid(issuer.domain, "u");
    const noExp = await new SignJWT({
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
        credentialSubject: { id: subjectDid, domain: "example.com" },
      },
    })
      .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
      .setIssuer(issuer.did)
      .setSubject(subjectDid)
      .setIssuedAt()
      .sign(issuer.privateKey);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    await expect(reMintVc(issuer, noExp, { subjectId: pairwise, jti: "j" })).rejects.toThrow(/exp/);
  });

  it("rejects a malformed original VC missing its `vc` claim", async () => {
    const notAVc = await new SignJWT({ hello: "world" })
      .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
      .setIssuer(issuer.did)
      .setSubject("x")
      .setIssuedAt()
      .setExpirationTime("1y")
      .sign(issuer.privateKey);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    await expect(reMintVc(issuer, notAVc, { subjectId: pairwise, jti: "j" })).rejects.toThrow(/vc/);
  });

  // Property (cross-RP unlinkability at the primitive level): the SAME original
  // badge re-minted for two relying parties shares only iss/kid and the claim
  // values — sub, credentialSubject.id, and jti all differ.
  it("two disclosures of one badge to different RPs share no cross-RP correlator", async () => {
    const original = await signOriginal(issuer, {
      userId: "internal_user_42",
      jti: "badge_original_id",
      claims: { domain: "example.com" },
    });
    const subA = buildPairwiseUserDid(issuer.domain, "PAIRWISE_A");
    const subB = buildPairwiseUserDid(issuer.domain, "PAIRWISE_B");

    const jwtA = await reMintVc(issuer, original, { subjectId: subA, jti: "jti-A" });
    const jwtB = await reMintVc(issuer, original, { subjectId: subB, jti: "jti-B" });
    const a = await verifyVc(issuer, jwtA);
    const b = await verifyVc(issuer, jwtB);
    const hA = decodeProtectedHeader(jwtA);
    const hB = decodeProtectedHeader(jwtB);

    // Differ across RPs (correlators the audit flagged):
    expect(a.sub).not.toBe(b.sub);
    expect(a.vc.credentialSubject.id).not.toBe(b.vc.credentialSubject.id);
    expect(a.jti).not.toBe(b.jti);
    // exp is presentation-shaped on both: iat + TTL, never the stored VC's
    // issuance-derived exp — so (type, claims, exp) is not a cross-RP join key.
    const storedExp = decodeJwt(original).exp!;
    expect(a.exp).toBe(a.iat + DEFAULT_DISCLOSURE_TTL_SECONDS);
    expect(b.exp).toBe(b.iat + DEFAULT_DISCLOSURE_TTL_SECONDS);
    expect(a.exp).not.toBe(storedExp);
    expect(b.exp).not.toBe(storedExp);
    // Shared by design (Minister's own identity + the disclosed fact):
    expect(a.iss).toBe(b.iss);
    expect(hA.kid).toBe(hB.kid);
    const { id: _ida, ...claimsA } = a.vc.credentialSubject;
    const { id: _idb, ...claimsB } = b.vc.credentialSubject;
    expect(claimsA).toEqual(claimsB);
  });
});
