export type {
  Issuer,
  IssuerSigner,
  TokenSigningKey,
  CredentialSubject,
  VerifiableCredentialClaim,
  VerifiedCredential,
  IssueOptions,
  DidDocument,
} from "./types";

export { buildDid, buildKid, buildUserDid, buildPairwiseUserDid, getDidDocument } from "./did";
export { loadIssuer, _resetIssuerCache } from "./key";
export type { KmsIssuerOptions } from "./key";
// Signer seam. The KMS implementation (`./kms`, which pulls in the AWS SDK) is
// intentionally NOT re-exported here so the common path never loads it; it is
// imported lazily by `loadIssuer` and directly by its own tests.
export { localSigner, signCompactJwt } from "./signer";
export {
  issueVc,
  reMintVc,
  ministerCredentialType,
  DEFAULT_DISCLOSURE_TTL_SECONDS,
  ISSUANCE_MONTH_CLAIM,
  issuanceMonthOf,
  issuanceMonthStartSeconds,
} from "./issue";
export type { ReMintOptions } from "./issue";
export { verifyVc, VcVerificationError } from "./verify";
