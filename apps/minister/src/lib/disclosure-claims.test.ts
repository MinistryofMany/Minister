import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildPairwiseUserDid,
  buildUserDid,
  issueVc,
  loadIssuer,
  reMintVc,
  _resetIssuerCache,
  type Issuer,
} from "@minister/vc";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { sanitizeDisclosedClaims } from "@/lib/disclosure-claims";

// Anchor-retroactivity pin (Finding 3 / S-1). A pre-Phase-1 oauth-account VC was
// signed with the raw github `accountId` (the Sybil anchor) in its
// credentialSubject. reMintVc spreads stored claims verbatim, so WITHOUT the
// sanitizer the re-minted disclosure would keep leaking accountId to every RP.
// These tests run a legacy accountId-bearing VC through the REAL
// sanitizeDisclosedClaims (via reMintVc) and assert the decoded re-minted
// payload no longer carries accountId — making the retroactivity CODE-enforced.

const USER = "internal_user_legacy_oauth";

let tmpDir: string;
let issuer: Issuer;

beforeAll(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "minister-disclosure-claims-"));
  _resetIssuerCache();
  issuer = await loadIssuer({ domain: "ministry.test", devKeyPath: join(tmpDir, "issuer.jwk") });
});

afterAll(async () => {
  _resetIssuerCache();
  await rm(tmpDir, { recursive: true, force: true });
});

describe("sanitizeDisclosedClaims (unit)", () => {
  it("drops a legacy accountId from an oauth-account claim set (non-strict schema)", () => {
    const out = sanitizeDisclosedClaims(
      { provider: "github", accountId: "998877665544", handle: "octocat" },
      ["VerifiableCredential", "MinisterOauthAccountCredential"],
    );
    expect(out).not.toHaveProperty("accountId");
    expect(out).toEqual({ provider: "github", handle: "octocat" });
  });

  it("passes an UNKNOWN credential type through unchanged (map lookup fails OPEN)", () => {
    const claims = { anything: "goes", n: 3 };
    const out = sanitizeDisclosedClaims(claims, [
      "VerifiableCredential",
      "MinisterSomeFutureCredential",
    ]);
    // No schema for this type this deploy: never silently mangled.
    expect(out).toEqual(claims);
  });
});

describe("reMintVc + sanitizeDisclosedClaims (end to end)", () => {
  it("re-mints a legacy accountId-bearing oauth-account VC with NO accountId", async () => {
    // A legacy stored VC: issueVc does no schema validation, so this faithfully
    // reproduces a pre-Phase-1 row that carries the raw anchor.
    const legacyVcJwt = await issueVc(
      issuer,
      "oauth-account",
      buildUserDid(issuer.domain, USER),
      { provider: "github", accountId: "998877665544", handle: "octocat" },
      { jti: "badge_legacy_oauth_0001", expiresIn: "1y" },
    );
    // Sanity: the stored form really does carry the anchor.
    const storedSubject = (
      decodeJwt(legacyVcJwt).vc as { credentialSubject: Record<string, unknown> }
    ).credentialSubject;
    expect(storedSubject.accountId).toBe("998877665544");

    const reminted = await reMintVc(issuer, legacyVcJwt, {
      subjectId: buildPairwiseUserDid(issuer.domain, "pairwise_sub_value"),
      jti: "per_rp_jti",
      sanitizeClaims: sanitizeDisclosedClaims,
    });

    const subject = (decodeJwt(reminted).vc as { credentialSubject: Record<string, unknown> })
      .credentialSubject;
    // The re-minted disclosure carries only the CURRENT oauth-account shape.
    expect(subject).not.toHaveProperty("accountId");
    expect(subject.provider).toBe("github");
    expect(subject.handle).toBe("octocat");
    // And the raw anchor is nowhere in the signed payload.
    expect(JSON.stringify(decodeJwt(reminted))).not.toContain("998877665544");
  });
});
