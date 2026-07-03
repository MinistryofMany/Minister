import { compactVerify } from "jose";

import { signCompactJwt } from "./signer";
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

  // One clock read stamps iat and the exp base (whole seconds), mirroring
  // jose's SignJWT so the VC shape is unchanged aside from the signing seam.
  const nowSec = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    vc,
    iss: issuer.did,
    sub: subjectId,
    iat: nowSec,
  };
  if (options.jti) payload.jti = options.jti;
  if (options.notBefore) payload.nbf = Math.floor(options.notBefore.getTime() / 1000);
  payload.exp = nowSec + durationToSeconds(options.expiresIn);

  const header = { alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" };
  return signCompactJwt(header, payload, issuer.signer);
}

// Reserved credentialSubject key carrying the COARSE issuance bucket of a
// disclosed badge: the UTC calendar month ("YYYY-MM") containing the badge's
// true issuance instant. Restores the RP-side `maxAgeDays` freshness check
// that MIN-1's disclosure-time re-stamping made vacuous, WITHOUT re-opening
// the timestamp-correlation channel:
//
//   - Correlation bound: badges live 1 year by default, so at any moment the
//     live population spans ≤ ~13 month-buckets → the claim adds at most
//     log2(13) ≈ 3.7 bits to a cross-RP join key (≈ 5.6 bits over a 4-year
//     platform history) — versus the ~25-bit second-granularity iat/exp MIN-1
//     removed. Every badge of a type issued in the same month carries the
//     identical value, so the field is shared-by-many, not a fingerprint.
//   - Freshness utility: RPs evaluate `maxAgeDays` against the bucket START,
//     so the computed age is always ≥ the true age — a stale badge can never
//     pass, and precision is intentionally month-scale (a maxAgeDays of N
//     months works; sub-month gates are out of contract).
//
// Reserved like `id`: it is issuer metadata stamped at disclosure, never a
// per-badge-type claim, and a same-named stored claim is overridden.
export const ISSUANCE_MONTH_CLAIM = "issuanceMonth";

// The UTC calendar month containing `instant` (unix seconds or Date), as
// "YYYY-MM". The bucket function for ISSUANCE_MONTH_CLAIM.
export function issuanceMonthOf(instant: number | Date): string {
  const date = instant instanceof Date ? instant : new Date(instant * 1000);
  if (Number.isNaN(date.getTime())) {
    throw new Error("issuanceMonthOf: invalid instant");
  }
  return date.toISOString().slice(0, 7);
}

// Unix seconds of the first instant of the UTC month containing `instant`.
// Minister's consent-side policy evaluation feeds THIS (not the exact
// issuance time) into `maxAgeDays` leaves so consent and the relying party
// (which can only see the coarse claim and maps it to the bucket start)
// reach the SAME freshness decision — otherwise minimization could disclose
// a badge the RP's coarse gate then rejects while suppressing a passing
// alternative.
export function issuanceMonthStartSeconds(instant: number | Date): number {
  const date = instant instanceof Date ? instant : new Date(instant * 1000);
  if (Number.isNaN(date.getTime())) {
    throw new Error("issuanceMonthStartSeconds: invalid instant");
  }
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1) / 1000;
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
// DISCLOSURE time. The disclosed VC must not carry any FINE-grained
// cross-RP-stable correlator: this swaps `sub` / `credentialSubject.id` for
// the pairwise subject, replaces `jti` with a per-RP value, and re-stamps
// `iat`/`nbf`/`exp` to disclosure time — while preserving `iss`, `kid`, the
// VC `@context`/`type`, and every claim value (the disclosed fact itself).
// One deliberately COARSE issuance signal is added: the reserved
// `credentialSubject.issuanceMonth` bucket (see ISSUANCE_MONTH_CLAIM),
// derived from the signed original's `iat`, so relying parties can enforce
// `maxAgeDays` at month granularity without gaining a re-identifier.
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

  // The badge's true issuance instant, taken from the SIGNED original (just
  // verified above) — never from an unsigned input like the Badge row. A
  // DB-write attacker who can edit columns but cannot forge Minister's
  // signature therefore cannot freshen a stale badge's disclosed issuance
  // bucket. issueVc always stamps iat, so an authentic VC without one is
  // anomalous — fail loud, same posture as the missing-exp case below.
  if (typeof decoded.iat !== "number") {
    throw new Error(
      "reMintVc: original VC has no numeric `iat` — cannot derive an honest issuance bucket",
    );
  }

  // Preserve every claim value; swap ONLY the subject id, and stamp the
  // reserved coarse-issuance bucket (overriding a same-named stored claim —
  // the disclosed value is issuer-derived metadata, never a pass-through).
  const {
    id: _originalId,
    [ISSUANCE_MONTH_CLAIM]: _storedIssuanceMonth,
    ...claims
  } = original.credentialSubject;
  const credentialSubject: CredentialSubject = {
    id: options.subjectId,
    ...claims,
    [ISSUANCE_MONTH_CLAIM]: issuanceMonthOf(decoded.iat),
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

  const payload: Record<string, unknown> = {
    vc,
    iss: issuer.did,
    sub: options.subjectId,
    iat: nowSec,
    nbf: nbfSec,
    jti: options.jti,
    exp: expSec,
  };
  const header = { alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" };
  return signCompactJwt(header, payload, issuer.signer);
}

// Seconds per duration unit. Mirrors jose's `secs` table (day * 365.25 for a
// year) so the compact-JWS path we build by hand matches the exp jose's
// SignJWT would have stamped from the same `expiresIn` string.
const UNIT_SECONDS: Record<string, number> = {
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  d: 86_400,
  day: 86_400,
  days: 86_400,
  w: 604_800,
  week: 604_800,
  weeks: 604_800,
  y: 31_557_600,
  yr: 31_557_600,
  yrs: 31_557_600,
  year: 31_557_600,
  years: 31_557_600,
};

// `IssueOptions.expiresIn` is a duration FROM NOW: a number of seconds, or a
// "<n><unit>" string (e.g. "1y", "30d"). Returns whole seconds. jose's
// SignJWT.setExpirationTime accepted these forms; we resolve them ourselves
// because the KMS signer builds the JWS by hand (no jose SignJWT).
const DEFAULT_EXPIRY_SECONDS = 31_557_600; // 1 year (day * 365.25), jose parity

function durationToSeconds(value: IssueOptions["expiresIn"]): number {
  if (value === undefined) return DEFAULT_EXPIRY_SECONDS;
  if (typeof value === "number") return Math.floor(value);
  const match = /^\s*(\d+)\s*([a-z]+)\s*$/i.exec(value);
  const count = match?.[1];
  const rawUnit = match?.[2];
  if (count === undefined || rawUnit === undefined) {
    throw new Error(`issueVc: unparseable expiresIn "${value}"`);
  }
  const unit = UNIT_SECONDS[rawUnit.toLowerCase()];
  if (unit === undefined) {
    throw new Error(`issueVc: unknown duration unit in expiresIn "${value}"`);
  }
  return Number(count) * unit;
}
