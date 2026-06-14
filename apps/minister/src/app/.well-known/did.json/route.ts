import { NextResponse } from "next/server";

import { getDidDocument } from "@minister/vc";

import { getIssuer } from "@/lib/issuer";

// W3C did:web resolution: clients fetch this URL based purely on the
// domain in the DID. Must be public, cacheable, and CORS-permissive.
export async function GET() {
  const issuer = await getIssuer();
  return NextResponse.json(getDidDocument(issuer), {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
