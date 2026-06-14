import { SignJWT } from "jose";

import type {
  CredentialSubject,
  IssueOptions,
  Issuer,
  VerifiableCredentialClaim,
} from "./types";

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

  let builder = new SignJWT({ vc })
    .setProtectedHeader({ alg: "EdDSA", kid: issuer.kid, typ: "vc+jwt" })
    .setIssuer(issuer.did)
    .setSubject(subjectId)
    .setIssuedAt();

  if (options.jti) builder = builder.setJti(options.jti);
  if (options.notBefore) builder = builder.setNotBefore(options.notBefore);
  builder = builder.setExpirationTime(coerceExpiresIn(options.expiresIn));

  return builder.sign(issuer.privateKey);
}

// jose's setExpirationTime treats bare numbers as *absolute* epoch
// seconds (1970-relative), which is almost never what callers want.
// `IssueOptions.expiresIn` is documented as "duration from now" — when
// we get a number, hand jose a "<n>s" string so it does the right
// thing. Strings are passed through (jose supports "1y", "30d", etc.).
function coerceExpiresIn(value: IssueOptions["expiresIn"]): string {
  if (value === undefined) return "1y";
  if (typeof value === "number") return `${value}s`;
  return value;
}
