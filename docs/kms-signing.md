# KMS signing (badge VCs)

Minister signs with **two Ed25519 keys**, distinguished by `kid`:

| kid                      | Material                                                   | Signs                             | Served in                                    |
| ------------------------ | ---------------------------------------------------------- | --------------------------------- | -------------------------------------------- |
| `did:web:<domain>#key-2` | AWS KMS key `alias/minister-issuer` (non-extractable, HSM) | badge VCs (`issueVc`, `reMintVc`) | JWKS **and** the DID doc's `assertionMethod` |
| `did:web:<domain>#key-3` | in-process Ed25519 (env `TOKEN_SIGNING_JWK`)               | id_token + access_token           | JWKS only — **not** in `assertionMethod`     |

Why split: KMS `Sign` with `MessageType=RAW` caps the message at 4096 bytes, and
an id_token crosses that once ~3 badges are embedded (up to ~21 KB at the policy
max). Badge VCs are ≤ ~900 B, so they sign on KMS with headroom; tokens stay on
an in-process key. Only `#key-2` is in `assertionMethod`, so a stolen token key
cannot forge a badge VC that a verifier pinning to `assertionMethod` accepts.

**The split only protects verifiers that pin to `assertionMethod`.** JWKS serves
BOTH keys, and a compact-JWS verifier selects the key by the JWT `kid`; a verifier
that trusts the raw JWKS would therefore accept a badge carrying `kid ...#key-3`
(a forgery signed with a stolen token key). The reference RP SDK
(`@minister/client`, `verifyMinisterBadge`) closes this: it fetches the issuer's
`/.well-known/did.json`, builds its badge-verification key set from the
`assertionMethod` verification methods ONLY (i.e. `#key-2`), and rejects any badge
whose `kid` is not in that set — it never verifies a badge against the raw JWKS.
Any third-party verifier MUST do the same; verifying badge VCs against
`/.well-known/jwks.json` defeats the KMS split.

RAW + `ED25519_SHA_512` produces a pure-Ed25519 (RFC 8032) signature that drops
straight into a compact JWS `EdDSA`. `ED25519_PH_SHA_512` and `MessageType=DIGEST`
are HashEdDSA (do **not** verify as JWS EdDSA) and are unreachable in code — the
signing parameters are constants in `packages/vc/src/kms.ts`, not options.

## Production env

```sh
# Badge key (#key-2) — KMS
MINISTER_KMS_KEY_ID=arn:aws:kms:us-east-2:820761077505:key/ff0ac3ab-e770-4e54-a142-8e0cfb5592d0
ISSUER_KMS_PUBLIC_JWK='{"kty":"OKP","crv":"Ed25519","x":"QC2GiODNhQe5aCx_yZRildhid_QB-qxSSP-pOY4SW7c","alg":"EdDSA","use":"sig"}'
AWS_REGION=us-east-2
AWS_ACCESS_KEY_ID=...        # minister-issuer-signer (below), gitignored .env only
AWS_SECRET_ACCESS_KEY=...

# Token key (#key-3) — in-process
TOKEN_SIGNING_JWK='{"kty":"OKP","crv":"Ed25519","x":"...","d":"...","alg":"EdDSA","use":"sig"}'

# Issuer domain (percent-encoded host:port of the public AUTH_URL, e.g. ministry.id)
MINISTER_ISSUER_DOMAIN=ministry.id
```

- `MINISTER_KMS_KEY_ID` set ⇒ `ISSUER_KMS_PUBLIC_JWK` is **required**; boot calls
  `GetPublicKey` and refuses to start (crashes) if the KMS key's public half does
  not equal the pinned JWK. There is **no local fallback signer** — if KMS is
  unreachable, badge issuance and disclosure fail closed. Login without badge
  scopes still works (the id_token signs in-process).
- Leave `MINISTER_KMS_KEY_ID` unset to keep the old local-key behavior (a local
  `ISSUER_PRIVATE_JWK`, or a generated dev key). Dev/CI never touch KMS.
- `TOKEN_SIGNING_JWK` is required in production; in dev it is generated and
  persisted to `apps/minister/dev-keys/token.jwk` (gitignored). Generate one with:
  ```sh
  node -e 'const c=require("node:crypto");const{privateKey}=c.generateKeyPairSync("ed25519");const jwk=privateKey.export({format:"jwk"});jwk.alg="EdDSA";jwk.use="sig";console.log(JSON.stringify(jwk))'
  ```

## IAM for the box (Tyler runs these)

Lightsail cannot attach IAM roles, so the box uses static credentials for a
dedicated, sign-only IAM user. **`minister-admin` cannot create IAM users** (it
has no `iam:*` permissions — verified), so run these as the account root or an
admin identity that has IAM rights, **not** the `minister-admin` profile.

```sh
# 1. Create the sign-only principal.
aws iam create-user --user-name minister-issuer-signer \
  --tags Key=project,Value=ministry Key=app,Value=minister

aws iam put-user-policy --user-name minister-issuer-signer \
  --policy-name minister-issuer-sign --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "MinisterIssuerSign",
    "Effect": "Allow",
    "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
    "Resource": "arn:aws:kms:us-east-2:820761077505:key/ff0ac3ab-e770-4e54-a142-8e0cfb5592d0"
  }]
}'

# 2. Mint access keys → put in the box's gitignored .env (AWS_ACCESS_KEY_ID /
#    AWS_SECRET_ACCESS_KEY). Never commit. Calendar a 90-day rotation.
aws iam create-access-key --user-name minister-issuer-signer
```

The IAM policy must reference the **key ARN**, not the alias.

## Tighten the key policy (before go-live)

The key was created with a temporary account-wide allow. Replace it so exactly
two principals can touch the key — account root (admin) and the signer user
(sign-only):

```sh
aws kms put-key-policy --key-id alias/minister-issuer --policy-name default --policy '{
  "Version": "2012-10-17",
  "Id": "minister-issuer-key-policy",
  "Statement": [
    {
      "Sid": "EnableRootAccountAdmin",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::820761077505:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "AllowMinisterBoxSign",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::820761077505:user/minister-issuer-signer" },
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
      "Resource": "*"
    }
  ]
}'
```

CloudTrail logs every `kms:Sign` with caller identity; add an alarm on `Sign`
from any principal other than `minister-issuer-signer`.

## Live verification

`packages/vc/src/kms.test.ts` carries a live round trip (KMS-sign a badge VC,
verify it as JWS EdDSA against the served public JWK). It is skipped unless
`MINISTER_KMS_LIVE_TEST=1` and AWS credentials with `kms:Sign`/`kms:GetPublicKey`
are present:

```sh
AWS_PROFILE=<signer> AWS_REGION=us-east-2 MINISTER_KMS_LIVE_TEST=1 \
  pnpm --filter @minister/vc exec vitest run src/kms.test.ts
```
