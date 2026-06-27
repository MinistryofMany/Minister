import { SignJWT, decodeJwt, decodeProtectedHeader } from "jose";

import type { Issuer, VerifiableCredentialClaim } from "./types";

export class VcReissueError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VcReissueError";
  }
}

// Re-mint an already-issued Minister VC under a new subject DID, preserving
// every other claim verbatim.
//
// Why this exists: a badge VC is signed ONCE at issuance with a stable
// global holder DID and stored in `Badge.vcJwt`. Handing that artifact to a
// relying party would leak a cross-RP-correlatable identifier (and the raw
// internal userId embedded in it). At disclosure time we instead re-sign the
// stored VC with a per-RP pairwise subject, so each RP sees a different,
// opaque holder DID. The stored global-DID VC remains Minister's internal
// record and is never disclosed.
//
// Invariants:
//   - `sub` AND `vc.credentialSubject.id` are both swapped to `newSubjectId`
//     (they move together; the SDK verifier asserts they are equal).
//   - `exp`, `nbf`, `iat`, and `jti` are preserved EXACTLY. Re-minting must
//     never extend a credential's validity, and `jti` stays equal to the
//     badge id so the credential keeps its identity.
//   - The signature header (alg / kid / typ) and the `vc` envelope (context,
//     type array, other claims) are preserved, so the re-minted VC verifies
//     under the same issuer key and maps to the same badge type.
//
// `vcJwt` must be a VC this same issuer signed (a stored `Badge.vcJwt`); the
// caller is responsible for that. We decode rather than verify here because
// the stored artifact is already trusted Minister-internal state.
export async function reissueVcWithSubject(
  issuer: Issuer,
  vcJwt: string,
  newSubjectId: string,
): Promise<string> {
  let payload: ReturnType<typeof decodeJwt>;
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    payload = decodeJwt(vcJwt);
    header = decodeProtectedHeader(vcJwt);
  } catch (cause) {
    throw new VcReissueError(
      `Cannot decode stored VC for re-mint: ${cause instanceof Error ? cause.message : String(cause)}`,
    );
  }

  const vc = payload.vc as VerifiableCredentialClaim | undefined;
  if (!vc || typeof vc !== "object" || !vc.credentialSubject) {
    throw new VcReissueError("Stored VC payload is missing its `vc` envelope");
  }
  if (typeof payload.exp !== "number") {
    // Every Minister VC is stamped with an exp at issuance; refusing here
    // guarantees re-minting can never silently drop the expiry.
    throw new VcReissueError("Stored VC has no numeric `exp` to preserve");
  }

  // Rebuild the vc envelope with only the subject id swapped. Spread the
  // existing credentialSubject so all non-id claims (domain, threshold, ...)
  // carry over verbatim.
  const reissuedVc: VerifiableCredentialClaim = {
    ...vc,
    credentialSubject: {
      ...vc.credentialSubject,
      id: newSubjectId,
    },
  };

  // Build the new payload by copying every claim, then overriding the two
  // subject-bearing fields and the (re-signed) vc envelope. iat/nbf/exp/jti
  // are copied as-is; because we never call jose's set* helpers for them,
  // their absolute values are preserved exactly.
  const newPayload: Record<string, unknown> = {
    ...payload,
    sub: newSubjectId,
    vc: reissuedVc,
  };

  // Re-sign with the same issuer key and the SAME protected header the VC was
  // issued under (alg/kid/typ), so it verifies identically to a freshly
  // issued credential. Fall back to the issuer's own kid only if the stored
  // header somehow lacks one.
  const protectedHeader = {
    alg: "EdDSA" as const,
    kid: typeof header.kid === "string" ? header.kid : issuer.kid,
    typ: typeof header.typ === "string" ? header.typ : "vc+jwt",
  };

  return new SignJWT(newPayload).setProtectedHeader(protectedHeader).sign(issuer.privateKey);
}
