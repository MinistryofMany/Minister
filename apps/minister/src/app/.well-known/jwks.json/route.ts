import { NextResponse } from "next/server";

import { getIssuer } from "@/lib/issuer";

// Standard JWKS endpoint — OIDC relying parties and any RFC 7517 client
// will fetch this to verify our signed JWTs. We serve BOTH signing keys,
// kid-distinguished: the badge key (#key-2, KMS-backed in prod) that signs
// badge VCs, and the token key (#key-3, in-process) that signs id/access
// tokens. Only #key-2 appears in the DID document's assertionMethod, so a
// badge verifier that pins to assertionMethod won't accept a token-key sig.
// jose RP caches refetch on an unknown kid, so a new-key token verifies even
// against a warm cache.
export async function GET() {
  const issuer = await getIssuer();
  return NextResponse.json(
    { keys: [issuer.publicJwk, issuer.token.publicJwk] },
    {
      headers: {
        "Cache-Control": "public, max-age=300",
        "Access-Control-Allow-Origin": "*",
      },
    },
  );
}
