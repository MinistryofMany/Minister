import { decodeJwt, SignJWT } from "jose";

import type { CredentialSubject, IssueOptions, Issuer, VerifiableCredentialClaim } from "./types";

const VC_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const VC_BASE_TYPE = "VerifiableCredential";

// Build the credentialType string used inside vc.type[] from a Minister
// badge type slug. "email-domain" → "MinisterEmailDomainCredential".
export function ministerCredentialType(badgeType: string): string {
  const pascal = badgeType
    .split("-")
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join("");
  return `Minister${pascal}Credential`;
}

// Issue a Minister-native VC. `subjectId` is the user's did:web URL —
// callers build it with buildUserDid().
export async function issueVc<TClaims extends Record<string, unknown>>(
  issuer: Issuer,
  badgeType: string,
  subjectId: string,
  claims: TClaims,
  options: IssueOptions = {},
): Promise<string> {
  const credentialSubject: CredentialSubject = {
    id: subjectId,
    ...claims,
  };

  const vc: VerifiableCredentialClaim = {
    "@context": [VC_CONTEXT, ...(options.extraContexts ?? [])],
    type: [VC_BASE_TYPE, ministerCredentialType(badgeType)],
    credentialSubject,
  };

  let builder = new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
    .setIssuer(issuer.did)
    .setSubject(subjectId)
    .setIssuedAt();

  if (options.jti) builder = builder.setJti(options.jti);
  if (options.notBefore) builder = builder.setNotBefore(options.notBefore);
  builder = builder.setExpirationTime(coerceExpiresIn(options.expiresIn));

  return builder.sign(issuer.privateKey);
}

export interface ReMintOptions {
  // New PAIRWISE subject DID — becomes both the JWT `sub` and
  // `credentialSubject.id`. Build with `buildPairwiseUserDid`.
  subjectId: string;
  // Per-RP `jti` (unlinkable across relying parties). Never the raw badge id.
  jti: string;
  // Upper bound on the new `exp`, taken from the badge row (`Badge.expiresAt`).
  // The effective `exp` is min(original VC `exp`, maxExpiresAt), so re-minting
  // can NEVER extend the credential's lifetime past what was originally issued.
  // `null`/omitted means "no extra cap" — the original VC `exp` is the ceiling.
  maxExpiresAt?: Date | null;
  // `nbf`; defaults to now. `iat` is always re-stamped to now.
  notBefore?: Date;
}

// Re-mint a stored Minister VC as a fresh, per-relying-party credential at
// DISCLOSURE time. The disclosed VC must not carry any cross-RP-stable
// correlator: this swaps `sub` / `credentialSubject.id` for the pairwise
// subject, replaces `jti` with a per-RP value, and re-stamps `iat`/`nbf` to
// now — while preserving `iss`, `kid`, the VC `@context`/`type`, and every
// claim value (the disclosed fact itself).
//
// The original VC is Minister's own trusted artifact, so it is decoded (not
// re-verified) — a single Ed25519 signing op per disclosure. The lifetime
// clamp is enforced HERE, next to the signature, so no caller can widen it.
export async function reMintVc(
  issuer: Issuer,
  originalVcJwt: string,
  options: ReMintOptions,
): Promise<string> {
  const decoded = decodeJwt(originalVcJwt);

  const rawVc = decoded.vc;
  if (!rawVc || typeof rawVc !== "object" || Array.isArray(rawVc)) {
    throw new Error("reMintVc: original VC is missing its `vc` claim");
  }
  const original = rawVc as Partial<VerifiableCredentialClaim>;
  if (!Array.isArray(original.type) || original.type.length === 0) {
    throw new Error("reMintVc: original VC `type` is not a non-empty array");
  }
  if (
    !original.credentialSubject ||
    typeof original.credentialSubject !== "object" ||
    Array.isArray(original.credentialSubject)
  ) {
    throw new Error("reMintVc: original VC is missing `credentialSubject`");
  }

  // Preserve every claim value; swap ONLY the subject id.
  const { id: _originalId, ...claims } = original.credentialSubject;
  const credentialSubject: CredentialSubject = {
    id: options.subjectId,
    ...claims,
  };
  const vc: VerifiableCredentialClaim = {
    "@context": original["@context"] ?? [VC_CONTEXT],
    type: original.type,
    credentialSubject,
  };

  // Never extend lifetime: cap the new exp at the original VC's exp, and
  // further at Badge.expiresAt when that is earlier.
  const originalExp = typeof decoded.exp === "number" ? decoded.exp : undefined;
  const cap =
    options.maxExpiresAt != null ? Math.floor(options.maxExpiresAt.getTime() / 1000) : undefined;
  let expSec: number;
  if (originalExp !== undefined && cap !== undefined) expSec = Math.min(originalExp, cap);
  else if (originalExp !== undefined) expSec = originalExp;
  else if (cap !== undefined) expSec = cap;
  else {
    // Unreachable in practice: issueVc always stamps an exp. Fail loud rather
    // than silently minting a credential with an unbounded lifetime.
    throw new Error(
      "reMintVc: cannot determine exp (original VC has no `exp` and no maxExpiresAt)",
    );
  }

  const nbfSec = Math.floor((options.notBefore ?? new Date()).getTime() / 1000);

  return new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
    .setIssuer(issuer.did)
    .setSubject(options.subjectId)
    .setIssuedAt()
    .setNotBefore(nbfSec)
    .setJti(options.jti)
    .setExpirationTime(expSec)
    .sign(issuer.privateKey);
}

// jose's setExpirationTime treats bare numbers as *absolute* epoch
// seconds (1970-relative), which is almost never what callers want.
// `IssueOptions.expiresIn` is documented as "duration from now" — when
// we get a number, hand jose a "<n>s" string so it does the right
// thing. Strings are passed through (jose supports "1y", "30d", etc.).
function coerceExpiresIn(value: IssueOptions["expiresIn"]): string {
  if (value === undefined) return "1y";
  if (typeof value === "number") return `${value}s`;
  return value;
}
