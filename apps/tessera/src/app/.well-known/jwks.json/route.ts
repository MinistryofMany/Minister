import { NextResponse } from "next/server";

import { getIssuer } from "@/lib/issuer";

// Standard JWKS endpoint — OIDC relying parties and any RFC 7517 client
// will fetch this to verify our signed JWTs. We expose the same key the
// did:web document uses; in Stage 9 we'll rotate by appending an
// additional key here before flipping the active kid.
export async function GET() {
  const issuer = await getIssuer();
  return NextResponse.json(
    { keys: [issuer.publicJwk] },
    {
      headers: {
        "Cache-Control": "public, max-age=300",
        "Access-Control-Allow-Origin": "*",
      },
    },
  );
}
