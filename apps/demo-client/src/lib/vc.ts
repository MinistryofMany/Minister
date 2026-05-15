import { jwtVerify, createRemoteJWKSet } from "jose";

// Tessera-issued VC JWTs carry these claims. We verify the signature
// against Tessera's JWKS, but we don't trust the embedded `vc` shape
// blindly — RPs should pull out only the credentialSubject fields
// they care about.
export interface VerifiedTesseraVc {
  iss: string;
  sub: string;
  jti?: string;
  iat?: number;
  exp?: number;
  vc: {
    type: string[];
    credentialSubject: Record<string, unknown> & { id: string };
  };
}

// JWKS for the Tessera issuer. did:web's JWKS lives at
// /.well-known/jwks.json on the issuer's HTTP origin.
function tesseraJwks() {
  const base =
    process.env.TESSERA_ISSUER_URL?.replace(/\/$/, "") ??
    "http://localhost:3000";
  return createRemoteJWKSet(new URL(`${base}/.well-known/jwks.json`));
}

export async function verifyTesseraVc(jwt: string): Promise<VerifiedTesseraVc> {
  const { payload } = await jwtVerify(jwt, tesseraJwks(), {
    algorithms: ["EdDSA"],
    typ: "vc+jwt",
  });
  const vc = payload.vc as VerifiedTesseraVc["vc"] | undefined;
  if (!vc || !Array.isArray(vc.type) || !vc.credentialSubject) {
    throw new Error("Not a Tessera VC: missing `vc` envelope");
  }
  return {
    iss: String(payload.iss ?? ""),
    sub: String(payload.sub ?? ""),
    jti: typeof payload.jti === "string" ? payload.jti : undefined,
    iat: typeof payload.iat === "number" ? payload.iat : undefined,
    exp: typeof payload.exp === "number" ? payload.exp : undefined,
    vc,
  };
}

// Find a VC of a given Tessera badge type in an array of VC JWTs.
// Returns null if none match or none verify.
export async function findVerifiedBadge(
  vcs: string[],
  badgeType: string,
): Promise<VerifiedTesseraVc | null> {
  const expectedType = `Tessera${pascal(badgeType)}Credential`;
  for (const jwt of vcs) {
    try {
      const vc = await verifyTesseraVc(jwt);
      if (vc.vc.type.includes(expectedType)) return vc;
    } catch {
      // Skip unverifiable VCs silently — a malicious or stale one
      // shouldn't make all of them fail.
    }
  }
  return null;
}

function pascal(slug: string): string {
  return slug
    .split("-")
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join("");
}
