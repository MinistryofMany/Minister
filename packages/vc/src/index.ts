export type {
  Issuer,
  CredentialSubject,
  VerifiableCredentialClaim,
  VerifiedCredential,
  IssueOptions,
  DidDocument,
} from "./types";

export { buildDid, buildKid, buildUserDid, buildPairwiseUserDid, getDidDocument } from "./did";
export { loadIssuer, _resetIssuerCache } from "./key";
export { issueVc, reMintVc, ministerCredentialType, DEFAULT_DISCLOSURE_TTL_SECONDS } from "./issue";
export type { ReMintOptions } from "./issue";
export { verifyVc, VcVerificationError } from "./verify";
