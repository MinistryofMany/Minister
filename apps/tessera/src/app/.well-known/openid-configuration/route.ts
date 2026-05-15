import { NextResponse } from "next/server";

import { getOidcDiscovery } from "@/lib/oidc-config";

// OIDC Discovery — RFC 8414 / OpenID Connect Discovery 1.0 §4.
// Must be at this exact path; RPs fetch it without authentication and
// expect it to be CORS-permissive.
export async function GET() {
  return NextResponse.json(getOidcDiscovery(), {
    headers: {
      "Cache-Control": "public, max-age=300",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
