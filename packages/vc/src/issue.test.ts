import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { _resetIssuerCache, loadIssuer } from "./key";
import { issueVc, tesseraCredentialType } from "./issue";
import { verifyVc, VcVerificationError } from "./verify";
import { buildUserDid } from "./did";

describe("tesseraCredentialType", () => {
  it("converts kebab slugs to PascalCase credential types", () => {
    expect(tesseraCredentialType("email-domain")).toBe(
      "TesseraEmailDomainCredential",
    );
    expect(tesseraCredentialType("oauth-account")).toBe(
      "TesseraOauthAccountCredential",
    );
    expect(tesseraCredentialType("age-over-21")).toBe(
      "TesseraAgeOver21Credential",
    );
  });

  it("handles single-word slugs", () => {
    expect(tesseraCredentialType("residency")).toBe(
      "TesseraResidencyCredential",
    );
  });
});

// loadIssuer + issueVc + verifyVc form a round-trip system. Test them
// together: anything that breaks signing will break verification, and
// vice versa. Reset the module cache between tests so each gets a fresh
// key.
describe("VC issue/verify round trip", () => {
  let tmpDir: string;
  let keyPath: string;

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "tessera-vc-test-"));
    keyPath = join(tmpDir, "issuer.jwk");
  });

  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("issues a valid JWT-VC that verifies against the issuer's own key", async () => {
    const issuer = await loadIssuer({
      domain: "tessera.local",
      devKeyPath: keyPath,
    });
    const subjectDid = buildUserDid(issuer.domain, "u_test_123");

    const jwt = await issueVc(issuer, "email-domain", subjectDid, {
      domain: "example.com",
    });

    const verified = await verifyVc(issuer, jwt);
    expect(verified.iss).toBe(issuer.did);
    expect(verified.sub).toBe(subjectDid);
    expect(verified.vc.type).toContain("VerifiableCredential");
    expect(verified.vc.type).toContain("TesseraEmailDomainCredential");
    expect(verified.vc.credentialSubject).toEqual({
      id: subjectDid,
      domain: "example.com",
    });
  });

  it("stamps a jti when one is provided", async () => {
    const issuer = await loadIssuer({
      domain: "tessera.local",
      devKeyPath: keyPath,
    });
    const subjectDid = buildUserDid(issuer.domain, "u_jti");
    const jwt = await issueVc(
      issuer,
      "email-domain",
      subjectDid,
      { domain: "example.com" },
      { jti: "badge_jti_123" },
    );
    const verified = await verifyVc(issuer, jwt);
    expect(verified.jti).toBe("badge_jti_123");
  });

  it("populates iat by default and exp from `expiresIn`", async () => {
    const issuer = await loadIssuer({
      domain: "tessera.local",
      devKeyPath: keyPath,
    });
    const subjectDid = buildUserDid(issuer.domain, "u_exp");
    const before = Math.floor(Date.now() / 1000);
    const jwt = await issueVc(
      issuer,
      "email-domain",
      subjectDid,
      { domain: "example.com" },
      { expiresIn: 60 },
    );
    const verified = await verifyVc(issuer, jwt);
    expect(verified.iat).toBeGreaterThanOrEqual(before);
    expect(verified.exp).toBeGreaterThan(verified.iat);
    // Allow 5s slack for "now" jitter between issuance and assert.
    expect(verified.exp! - verified.iat).toBeGreaterThanOrEqual(55);
    expect(verified.exp! - verified.iat).toBeLessThanOrEqual(65);
  });

  it("rejects a VC whose signature was made by a different issuer", async () => {
    const alpha = await loadIssuer({
      domain: "alpha.local",
      devKeyPath: keyPath,
    });
    _resetIssuerCache();
    const beta = await loadIssuer({
      domain: "beta.local",
      devKeyPath: join(tmpDir, "other.jwk"),
    });

    const jwt = await issueVc(
      alpha,
      "email-domain",
      buildUserDid(alpha.domain, "u_x"),
      { domain: "example.com" },
    );

    await expect(verifyVc(beta, jwt)).rejects.toBeInstanceOf(VcVerificationError);
  });

  it("rejects a VC whose iss claim has been tampered (issuer mismatch)", async () => {
    const issuer = await loadIssuer({
      domain: "tessera.local",
      devKeyPath: keyPath,
    });
    const jwt = await issueVc(
      issuer,
      "email-domain",
      buildUserDid(issuer.domain, "u_iss"),
      { domain: "example.com" },
    );

    // Re-import the same key under a different domain so the DID is wrong.
    _resetIssuerCache();
    const wrongDomainIssuer = await loadIssuer({
      domain: "wrong.local",
      // Reuse the same key file so the signature would verify on key
      // material, but the `iss` claim has the original domain — jose's
      // verifier should reject because the expected iss differs.
      devKeyPath: keyPath,
    });
    await expect(verifyVc(wrongDomainIssuer, jwt)).rejects.toBeInstanceOf(
      VcVerificationError,
    );
  });

  it("rejects a non-JWT input gracefully (no thrown noise)", async () => {
    const issuer = await loadIssuer({
      domain: "tessera.local",
      devKeyPath: keyPath,
    });
    await expect(verifyVc(issuer, "not.a.jwt")).rejects.toBeInstanceOf(
      VcVerificationError,
    );
    await expect(verifyVc(issuer, "")).rejects.toBeInstanceOf(
      VcVerificationError,
    );
  });
});
