import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { decodeJwt, decodeProtectedHeader } from "jose";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { buildPairwiseUserDid, buildUserDid } from "./did";
import { issueVc } from "./issue";
import { _resetIssuerCache, loadIssuer } from "./key";
import { reissueVcWithSubject, VcReissueError } from "./reissue";
import { verifyVc } from "./verify";

// reissueVcWithSubject is the disclosure-time re-mint: it takes an
// already-issued (global-DID) VC and re-signs it under a pairwise subject,
// preserving every other claim. Test it against the real issue/verify path
// so any drift in signing or claim handling is caught.
describe("reissueVcWithSubject", () => {
  let tmpDir: string;
  let keyPath: string;

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-vc-reissue-"));
    keyPath = join(tmpDir, "issuer.jwk");
  });

  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  async function makeIssuer() {
    return loadIssuer({ domain: "minister.local", devKeyPath: keyPath });
  }

  it("swaps the subject (sub AND credentialSubject.id) while preserving claims", async () => {
    const issuer = await makeIssuer();
    const globalDid = buildUserDid(issuer.domain, "raw_user_42");
    const original = await issueVc(
      issuer,
      "email-domain",
      globalDid,
      { domain: "example.com" },
      { jti: "badge_abc", expiresIn: "1y" },
    );

    const pairwiseDid = buildPairwiseUserDid(issuer.domain, "PAIRWISE_SUB");
    const reminted = await reissueVcWithSubject(issuer, original, pairwiseDid);

    const verified = await verifyVc(issuer, reminted);
    expect(verified.sub).toBe(pairwiseDid);
    expect(verified.vc.credentialSubject.id).toBe(pairwiseDid);
    // Non-id claims carry over verbatim.
    expect(verified.vc.credentialSubject.domain).toBe("example.com");
    expect(verified.vc.type).toEqual(["VerifiableCredential", "MinisterEmailDomainCredential"]);
  });

  it("re-minted VC contains NO raw userId anywhere", async () => {
    const issuer = await makeIssuer();
    const rawUserId = "raw_user_SECRET_123";
    const globalDid = buildUserDid(issuer.domain, rawUserId);
    const original = await issueVc(issuer, "email-domain", globalDid, { domain: "example.com" });

    const pairwiseDid = buildPairwiseUserDid(issuer.domain, "opaque_sub");
    const reminted = await reissueVcWithSubject(issuer, original, pairwiseDid);

    // The raw userId must not survive in the disclosed artifact, in any form.
    expect(reminted).not.toContain(rawUserId);
    const payload = JSON.stringify(decodeJwt(reminted));
    expect(payload).not.toContain(rawUserId);
    expect(payload).not.toContain(":users:");
  });

  it("preserves exp EXACTLY (re-minting never extends validity)", async () => {
    const issuer = await makeIssuer();
    const globalDid = buildUserDid(issuer.domain, "u_exp");
    // 60s validity at issuance.
    const original = await issueVc(
      issuer,
      "email-domain",
      globalDid,
      { domain: "example.com" },
      { expiresIn: 60 },
    );
    const originalExp = decodeJwt(original).exp;

    const reminted = await reissueVcWithSubject(
      issuer,
      original,
      buildPairwiseUserDid(issuer.domain, "s"),
    );
    expect(decodeJwt(reminted).exp).toBe(originalExp);
  });

  it("preserves jti, nbf and iat exactly", async () => {
    const issuer = await makeIssuer();
    const nbf = new Date(Date.now() - 5_000);
    const original = await issueVc(
      issuer,
      "email-domain",
      buildUserDid(issuer.domain, "u_meta"),
      { domain: "example.com" },
      { jti: "badge_meta_1", notBefore: nbf, expiresIn: "1y" },
    );
    const before = decodeJwt(original);

    const reminted = await reissueVcWithSubject(
      issuer,
      original,
      buildPairwiseUserDid(issuer.domain, "s"),
    );
    const after = decodeJwt(reminted);
    expect(after.jti).toBe(before.jti);
    expect(after.jti).toBe("badge_meta_1");
    expect(after.nbf).toBe(before.nbf);
    expect(after.iat).toBe(before.iat);
  });

  it("preserves the protected header (alg, kid, typ)", async () => {
    const issuer = await makeIssuer();
    const original = await issueVc(issuer, "email-domain", buildUserDid(issuer.domain, "u_h"), {
      domain: "example.com",
    });
    const beforeHeader = decodeProtectedHeader(original);
    const reminted = await reissueVcWithSubject(
      issuer,
      original,
      buildPairwiseUserDid(issuer.domain, "s"),
    );
    const afterHeader = decodeProtectedHeader(reminted);
    expect(afterHeader.alg).toBe(beforeHeader.alg);
    expect(afterHeader.kid).toBe(beforeHeader.kid);
    expect(afterHeader.typ).toBe(beforeHeader.typ);
    expect(afterHeader.typ).toBe("vc+jwt");
  });

  it("re-minted VC still verifies under the issuer key", async () => {
    const issuer = await makeIssuer();
    const original = await issueVc(issuer, "email-domain", buildUserDid(issuer.domain, "u_v"), {
      domain: "example.com",
    });
    const reminted = await reissueVcWithSubject(
      issuer,
      original,
      buildPairwiseUserDid(issuer.domain, "s"),
    );
    await expect(verifyVc(issuer, reminted)).resolves.toMatchObject({ iss: issuer.did });
  });

  it("rejects a non-JWT input", async () => {
    const issuer = await makeIssuer();
    await expect(
      reissueVcWithSubject(issuer, "not.a.jwt", buildPairwiseUserDid(issuer.domain, "s")),
    ).rejects.toBeInstanceOf(VcReissueError);
  });

  it("rejects a VC missing an exp (cannot guarantee no validity extension)", async () => {
    const issuer = await makeIssuer();
    // Hand-build a VC-shaped JWT with no exp by signing directly is awkward;
    // instead decode-and-strip is exercised via a payload with no exp. Use a
    // minimal JWT the decoder accepts but that lacks exp.
    const { SignJWT } = await import("jose");
    const noExp = await new SignJWT({
      vc: {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        type: ["VerifiableCredential", "MinisterEmailDomainCredential"],
        credentialSubject: { id: buildUserDid(issuer.domain, "u_noexp"), domain: "example.com" },
      },
    })
      .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
      .setIssuer(issuer.did)
      .setSubject(buildUserDid(issuer.domain, "u_noexp"))
      .setIssuedAt()
      .sign(issuer.privateKey);

    await expect(
      reissueVcWithSubject(issuer, noExp, buildPairwiseUserDid(issuer.domain, "s")),
    ).rejects.toBeInstanceOf(VcReissueError);
  });
});
