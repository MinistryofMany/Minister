import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeJwt, decodeProtectedHeader, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildPairwiseUserDid, buildUserDid } from "./did";
import { issueVc, reMintVc } from "./issue";
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

  it("clamps exp to the original VC exp — re-minting never extends lifetime (no cap)", async () => {
    const originalExp = Math.floor(Date.now() / 1000) + 10 * 86_400; // 10 days out
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");

    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    const v = await verifyVc(issuer, jwt);

    expect(v.exp).toBe(originalExp);
  });

  it("clamps exp to Badge.expiresAt when that is earlier than the original VC exp", async () => {
    const originalExp = Math.floor(Date.now() / 1000) + 365 * 86_400;
    const original = await signOriginal(issuer, { expSec: originalExp });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const badgeExpiresAt = new Date((Math.floor(Date.now() / 1000) + 5 * 86_400) * 1000);

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
    const originalExp = Math.floor(Date.now() / 1000) + 5 * 86_400;
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

  it("produces a VC that verifies against the issuer's live key (signature integrity)", async () => {
    const original = await signOriginal(issuer);
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const jwt = await reMintVc(issuer, original, { subjectId: pairwise, jti: "j" });
    // verifyVc enforces iss + alg EdDSA + typ vc+jwt against issuer.publicKey.
    await expect(verifyVc(issuer, jwt)).resolves.toMatchObject({ iss: issuer.did, sub: pairwise });
  });

  it("re-issued VC produced by a DIFFERENT issuer key does not verify (forgery resistance)", async () => {
    const original = await signOriginal(issuer);
    _resetIssuerCache();
    const other = await loadIssuer({
      domain: "ministry.test",
      devKeyPath: join(tmpDir, "other.jwk"),
    });
    const pairwise = buildPairwiseUserDid(issuer.domain, "S");
    const jwt = await reMintVc(other, original, { subjectId: pairwise, jti: "j" });
    // Signed by `other`, verified against the original `issuer` key → reject.
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
    // Shared by design (Minister's own identity + the disclosed fact):
    expect(a.iss).toBe(b.iss);
    expect(hA.kid).toBe(hB.kid);
    const { id: _ida, ...claimsA } = a.vc.credentialSubject;
    const { id: _idb, ...claimsB } = b.vc.credentialSubject;
    expect(claimsA).toEqual(claimsB);
  });
});
