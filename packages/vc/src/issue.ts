import { compactVerify, SignJWT } from "jose";

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

// Default presentation lifetime for a disclosed (re-minted) VC. One hour =
// Minister's access-token TTL, the longest-lived artifact of a single OIDC
// grant: it comfortably covers the id_token TTL (10 min + the SDK's 30s clock
// tolerance) so a badge never expires before the token that carried it, and
// badges fetched via /oidc/userinfo are re-minted at call time so they too get
// a full hour from disclosure.
export const DEFAULT_DISCLOSURE_TTL_SECONDS = 60 * 60;

export interface ReMintOptions {
  // New PAIRWISE subject DID — becomes both the JWT `sub` and
  // `credentialSubject.id`. Build with `buildPairwiseUserDid`.
  subjectId: string;
  // Per-RP `jti` (unlinkable across relying parties). Never the raw badge id.
  jti: string;
  // Upper bound on the new `exp`, taken from the badge row (`Badge.expiresAt`).
  // The effective `exp` is min(now + disclosureTtlSeconds, original VC `exp`,
  // maxExpiresAt), so re-minting can NEVER extend the credential's lifetime
  // past what was originally issued. `null`/omitted means "no extra cap".
  maxExpiresAt?: Date | null;
  // `nbf`; defaults to now. `iat` is always re-stamped to now.
  notBefore?: Date;
  // Presentation lifetime (seconds from now) of the disclosed copy. The
  // disclosed `exp` is PRESENTATION-SHAPED: it reflects disclosure time (which
  // already varies per disclosure, like `iat`), never the issuance instant.
  // Rationale: the original `exp` is issuance + a fixed duration at second
  // granularity — a stable ~25-bit value identical at every RP. Preserving it
  // through re-mint was a residual cross-RP correlator: two colluding RPs
  // could join on (vc.type, claims, exp) and re-link the user despite the
  // pairwise sub/jti. Defaults to DEFAULT_DISCLOSURE_TTL_SECONDS.
  disclosureTtlSeconds?: number;
}

// Re-mint a stored Minister VC as a fresh, per-relying-party credential at
// DISCLOSURE time. The disclosed VC must not carry any cross-RP-stable
// correlator: this swaps `sub` / `credentialSubject.id` for the pairwise
// subject, replaces `jti` with a per-RP value, and re-stamps `iat`/`nbf`/`exp`
// to disclosure time — while preserving `iss`, `kid`, the VC `@context`/`type`,
// and every claim value (the disclosed fact itself).
//
// The original VC's SIGNATURE IS VERIFIED against the issuer's own public key
// before any of its content is re-signed. Without that check, reMintVc is a
// signing oracle over database contents: a DB-write attacker (or a future
// badge-import path storing foreign-issuer rows) could get arbitrary claims
// re-signed under Minister's key with fresh validity. Temporal claims are
// deliberately NOT validated here — `exp`/`nbf` are re-derived and clamped
// below, so an expired-but-authentic stored VC still re-mints (to an already
// expired disclosure the RP rejects), exactly as before. Both the integrity
// check and the lifetime clamp live HERE, next to the signature, so no caller
// can skip or widen them.
export async function reMintVc(
  issuer: Issuer,
  originalVcJwt: string,
  options: ReMintOptions,
): Promise<string> {
  // Integrity gate: signature (pinned to EdDSA), typ, and our own iss. A
  // payload that was not signed by this issuer's key never reaches SignJWT.
  let decoded: Record<string, unknown>;
  try {
    const verified = await compactVerify(originalVcJwt, issuer.publicKey, {
      algorithms: ["EdDSA"],
    });
    if (verified.protectedHeader.typ !== "vc+jwt") {
      throw new Error(`unexpected typ ${String(verified.protectedHeader.typ)}`);
    }
    const payload: unknown = JSON.parse(new TextDecoder().decode(verified.payload));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("payload is not a JSON object");
    }
    decoded = payload as Record<string, unknown>;
    if (decoded.iss !== issuer.did) {
      throw new Error(`iss ${String(decoded.iss)} is not this issuer`);
    }
  } catch (cause) {
    throw new Error(
      "reMintVc: original VC failed verification against the issuer key — refusing to re-sign unverified content",
      { cause },
    );
  }

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

  // Presentation-shaped exp, never extending lifetime:
  //   exp = min(now + TTL, original VC exp, Badge.expiresAt)
  // `now + TTL` is a pure function of DISCLOSURE time (iat + a constant), so
  // the disclosed exp carries zero issuance information — the issuance-derived
  // original exp was a stable cross-RP correlator. Residual (accepted): within
  // the final TTL window of a badge's real lifetime the clamp re-exposes the
  // original exp; that is forced by "never extend lifetime" and is bounded to
  // TTL out of the badge's whole life (1 hour out of a year by default).
  const ttl = options.disclosureTtlSeconds ?? DEFAULT_DISCLOSURE_TTL_SECONDS;
  if (!Number.isInteger(ttl) || ttl <= 0) {
    throw new Error("reMintVc: disclosureTtlSeconds must be a positive integer");
  }
  const originalExp = typeof decoded.exp === "number" ? decoded.exp : undefined;
  const cap =
    options.maxExpiresAt != null ? Math.floor(options.maxExpiresAt.getTime() / 1000) : undefined;
  if (originalExp === undefined && cap === undefined) {
    // issueVc always stamps an exp, so an authentic Minister VC without one is
    // anomalous. Fail loud (integrity posture) rather than invent a lifetime.
    throw new Error(
      "reMintVc: cannot determine exp (original VC has no `exp` and no maxExpiresAt)",
    );
  }
  // One clock read feeds iat, nbf, and the exp base, so `exp - iat` is exactly
  // the TTL constant (no residual entropy) and every stamp is whole-second,
  // disclosure-time only — nothing sub-second or issuance-derived.
  const nowSec = Math.floor(Date.now() / 1000);
  let expSec = nowSec + ttl;
  if (originalExp !== undefined) expSec = Math.min(expSec, originalExp);
  if (cap !== undefined) expSec = Math.min(expSec, cap);

  const nbfSec =
    options.notBefore !== undefined ? Math.floor(options.notBefore.getTime() / 1000) : nowSec;

  return new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
    .setIssuer(issuer.did)
    .setSubject(options.subjectId)
    .setIssuedAt(nowSec)
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
