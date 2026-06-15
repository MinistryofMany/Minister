import { jwtVerify, createRemoteJWKSet } from "jose";

// Minister-issued VC JWTs carry these claims. We verify the signature
// against Minister's JWKS, but we don't trust the embedded `vc` shape
// blindly — RPs should pull out only the credentialSubject fields
// they care about.
export interface VerifiedMinisterVc {
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

// JWKS for the Minister issuer. did:web's JWKS lives at
// /.well-known/jwks.json on the issuer's HTTP origin.
function ministerJwks() {
  const base = process.env.MINISTER_ISSUER_URL?.replace(/\/$/, "") ?? "http://localhost:3000";
  return createRemoteJWKSet(new URL(`${base}/.well-known/jwks.json`));
}

export async function verifyMinisterVc(jwt: string): Promise<VerifiedMinisterVc> {
  const { payload } = await jwtVerify(jwt, ministerJwks(), {
    algorithms: ["EdDSA"],
    typ: "vc+jwt",
  });
  const vc = payload.vc as VerifiedMinisterVc["vc"] | undefined;
  if (!vc || !Array.isArray(vc.type) || !vc.credentialSubject) {
    throw new Error("Not a Minister VC: missing `vc` envelope");
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

// Find a VC of a given Minister badge type in an array of VC JWTs.
// Returns null if none match or none verify.
export async function findVerifiedBadge(
  vcs: string[],
  badgeType: string,
): Promise<VerifiedMinisterVc | null> {
  const expectedType = `Minister${pascal(badgeType)}Credential`;
  for (const jwt of vcs) {
    try {
      const vc = await verifyMinisterVc(jwt);
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
