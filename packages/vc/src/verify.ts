import { jwtVerify } from "jose";

import type { Issuer, VerifiedCredential } from "./types";

export class VcVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VcVerificationError";
  }
}

// Verify a Tessera-issued VC against our own signing key. For VCs issued
// by other DIDs we'd resolve their DID document and verify with that
// key; that's deferred until we actually import external VCs.
export async function verifyVc(
  issuer: Issuer,
  vcJwt: string,
): Promise<VerifiedCredential> {
  let payload;
  try {
    const result = await jwtVerify(vcJwt, issuer.publicKey, {
      issuer: issuer.did,
      algorithms: ["EdDSA"],
      typ: "vc+jwt",
    });
    payload = result.payload;
  } catch (cause) {
    throw new VcVerificationError(
      cause instanceof Error ? cause.message : String(cause),
    );
  }

  if (typeof payload.sub !== "string") {
    throw new VcVerificationError("VC payload missing string `sub`");
  }
  const vc = payload.vc as VerifiedCredential["vc"] | undefined;
  if (!vc || !Array.isArray(vc.type) || !vc.credentialSubject) {
    throw new VcVerificationError("VC payload missing `vc` envelope");
  }

  return {
    iss: issuer.did,
    sub: payload.sub,
    jti: payload.jti,
    iat: payload.iat ?? 0,
    nbf: payload.nbf,
    exp: payload.exp,
    vc,
  };
}
