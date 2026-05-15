import { SignJWT, jwtVerify } from "jose";

import type { ValidAuthorizeRequest } from "@/lib/oidc-authorize";

// The /oidc/authorize page validates the inbound OIDC request, then
// hands it off to a consent form. The form POSTs back to a server
// action which needs to know what request the user was consenting to.
//
// We pass the validated request through the form as a short-TTL signed
// token. Server action verifies the token's signature against
// AUTH_SECRET; once valid, the embedded request is trusted as-was
// without re-hitting the DB to re-validate the client / redirect_uri.
//
// Why not pass it as plain hidden form fields: protects against
// in-flight tampering (e.g. a malicious browser extension modifying
// hidden inputs to escalate scopes or change clientId).
//
// Why not store it server-side keyed by id: avoids a DB write+read in
// the hot path of the consent screen. The signed token is ~300 bytes,
// fits comfortably in a form field.

const ALG = "HS256";
const TTL_SECONDS = 5 * 60; // matches typical consent screen lifetime

function key(): Uint8Array {
  const secret = process.env.AUTH_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SECRET must be set (≥32 chars) for OIDC request tokens");
  }
  return new TextEncoder().encode(secret);
}

export async function signOidcRequest(
  req: ValidAuthorizeRequest,
): Promise<string> {
  return new SignJWT({ req })
    .setProtectedHeader({ alg: ALG, typ: "tessera-oidc-req" })
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(key());
}

export async function verifyOidcRequest(
  token: string,
): Promise<ValidAuthorizeRequest> {
  const { payload } = await jwtVerify(token, key(), {
    algorithms: [ALG],
    typ: "tessera-oidc-req",
  });
  const req = payload.req;
  if (!req || typeof req !== "object") {
    throw new Error("Invalid OIDC request token payload");
  }
  return req as ValidAuthorizeRequest;
}
