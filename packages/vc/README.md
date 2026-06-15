# @minister/vc

JWT-VC issuance and verification for the Minister identity platform. Issues Ed25519/EdDSA signed Verifiable Credentials as compact JWTs, bound to a did:web issuer. Provides DID document construction for `/.well-known/did.json` and JWKS helpers. Built on [`jose`](https://github.com/panva/jose).

Part of the **Ministry of Many** project.

## Install

```
pnpm add @minister/vc
```

## Usage

```ts
import {
  loadIssuer,
  issueVc,
  verifyVc,
  VcVerificationError,
  buildUserDid,
  getDidDocument,
} from "@minister/vc";

// Load (or generate) the Ed25519 signing key.
// Pass `privateJwk` (raw JSON string of a private OKP JWK) in production;
// use `devKeyPath` to auto-generate and persist a key for local dev.
const issuer = await loadIssuer({
  domain: "example.com",
  privateJwk: process.env.ISSUER_PRIVATE_JWK,
  // devKeyPath: ".dev/issuer-key.json",  // used if privateJwk is absent
});

// Build the subject DID for the user receiving this credential.
const subjectDid = buildUserDid("example.com", "user-123");
// → "did:web:example.com:users:user-123"

// Issue a VC for badge type "email-domain".
const vcJwt = await issueVc(
  issuer,
  "email-domain",
  subjectDid,
  { domain: "acme.org" }, // credentialSubject claims
  { expiresIn: "1y" }, // optional: jti, expiresIn, notBefore, extraContexts
);

// Verify a VC. Throws VcVerificationError on any failure (bad sig, wrong
// issuer, expired, missing fields).
try {
  const verified = await verifyVc(issuer, vcJwt);
  console.log(verified.sub); // "did:web:example.com:users:user-123"
  console.log(verified.vc.type); // ["VerifiableCredential", "MinisterEmailDomainCredential"]
} catch (err) {
  if (err instanceof VcVerificationError) {
    // handle invalid / untrusted credential
  }
}

// Serve the issuer DID document at GET /.well-known/did.json.
app.get("/.well-known/did.json", (_req, res) => {
  res.json(getDidDocument(issuer));
});
```

## API

### Key management

| Export                | Purpose                                                                                                                                 |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `loadIssuer(options)` | Load or generate an Ed25519 issuer key; returns a cached `Issuer`. Accepts `domain`, `privateJwk` (production), and `devKeyPath` (dev). |
| `_resetIssuerCache()` | Clear the in-process `Issuer` cache. Test seam; not needed in production.                                                               |

### Issuance

| Export                                                    | Purpose                                                                                              |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `issueVc(issuer, badgeType, subjectId, claims, options?)` | Sign and return a compact JWT-VC. `expiresIn` defaults to `"1y"`.                                    |
| `ministerCredentialType(badgeType)`                       | Convert a badge slug to a VC type string, e.g. `"email-domain"` → `"MinisterEmailDomainCredential"`. |

### Verification

| Export                    | Purpose                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------- |
| `verifyVc(issuer, vcJwt)` | Verify signature, issuer, algorithm, and `vc` envelope; returns `VerifiedCredential`. |
| `VcVerificationError`     | Thrown by `verifyVc` for any verification failure.                                    |

### DID helpers

| Export                         | Purpose                                                            |
| ------------------------------ | ------------------------------------------------------------------ |
| `buildDid(domain)`             | `"did:web:<domain>"`                                               |
| `buildKid(did, fragment?)`     | `"<did>#key-1"` (default fragment)                                 |
| `buildUserDid(domain, userId)` | `"did:web:<domain>:users:<userId>"` - subject DID for issued VCs   |
| `getDidDocument(issuer)`       | W3C DID document for the issuer; serve at `/.well-known/did.json`. |

### Types

`Issuer`, `CredentialSubject`, `VerifiableCredentialClaim`, `VerifiedCredential`, `IssueOptions`, `DidDocument`

## License

Copyright (c) 2026 AtHeartEngineering LLC, authored by AtHeartEngineer.

Licensed under either of **MIT** ([LICENSE-MIT](./LICENSE-MIT)) or **Apache License 2.0** ([LICENSE-APACHE](./LICENSE-APACHE)) at your option.
