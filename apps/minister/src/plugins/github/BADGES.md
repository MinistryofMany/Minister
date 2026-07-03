# GitHub plugin — badge catalogue

What we can attest from a single GitHub OAuth token (`read:user` scope,
`GET https://api.github.com/user`) while respecting the no-PII rule and
minimal disclosure: **thresholds and buckets only, never the raw value.**

## Implemented

| Badge slug         | GitHub source field | Claim shape                                              | Bucket / threshold                    | Why                                                                                                                             |
| ------------------ | ------------------- | -------------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `oauth-account`    | `id`, `login`       | `{ provider, accountId, handle? }`                       | n/a (identity)                        | Baseline: proves control of the account.                                                                                        |
| `account-age`      | `created_at`        | `{ provider, olderThanMonths: 12\|24\|36\|60 }`          | highest calendar-month bucket cleared | Anti-sybil. A fresh account can't fake a multi-year lower bound; the exact date never leaves Minister.                          |
| `social-following` | `followers`         | `{ provider, followersAtLeast: 10\|50\|100\|500\|1000 }` | highest bucket cleared                | Reputation / anti-sybil. Followers need social proof, unlike repo count which is `git init`-cheap. Exact count never disclosed. |

All three are provider-generic (the `provider` field is one of
`OAUTH_PROVIDERS`) so a future Google/Discord plugin can reuse the same badge
types.

## Candidates — recommend, but left for a decision

| Candidate                                | Source                                  | Proposed shape                                                  | Recommendation         | Rationale                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------------------- | --------------------------------------- | --------------------------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **public-repos bucket**                  | `public_repos`                          | `{ provider, publicReposAtLeast: 5\|25\|100 }`                  | ★★☆☆☆ hold             | Cheap to game (repos cost nothing to create), so weak anti-sybil. `social-following` already covers "established developer" with a stronger signal. Add only if a specific RP wants a "publishes code" signal rather than reputation.                                                                                                       |
| **organization membership**              | `GET /user/orgs` (needs `read:org`)     | `{ provider, org: "<login>" }` or a _hashed/allowlisted_ org id | ★★★☆☆ strong-if-scoped | Genuinely useful for gated communities ("member of org X"). But: (a) needs a wider scope (`read:org`), (b) the org login is arguably PII-adjacent / correlating, so it should be limited to an admin-configured allowlist of orgs Minister is willing to attest, not free-form. Worth doing as its own follow-up with the allowlist design. |
| **primary-email-verified**               | `GET /user/emails` (needs `user:email`) | `{ provider, emailVerified: true }`                             | ★★☆☆☆ hold             | Low marginal anti-sybil value (GitHub already requires a verified email to do much), needs a broader scope, and risks tempting us toward storing the email. `email-domain`/`email-exact` plugins already cover email attestation properly.                                                                                                  |
| **account-created-before-date** (cohort) | `created_at`                            | `{ provider, before: "2015" }`                                  | ★★☆☆☆ hold             | "Early adopter" cohorts are cute but leak more than `account-age` and have narrower use. Skip unless an RP asks.                                                                                                                                                                                                                            |
| **contribution activity**                | events/GraphQL                          | bucketed activity tier                                          | ★☆☆☆☆ skip             | Requires extra API calls, is noisy, easily farmed, and correlates. Not worth the complexity.                                                                                                                                                                                                                                                |

### Notes for whoever picks

- Anything needing a scope beyond `read:user` (org membership, emails) means
  widening `REQUESTED_SCOPES` in `index.ts`, which changes the GitHub consent
  screen — call it out to users.
- Every new type follows the same contract: threshold/bucket claim only, Zod
  schema in `packages/shared/src/badge-types.ts` **and** mirrored in the SDK
  (`minister-client/src/badges/{schemas,registry}.ts`), derived by a pure
  function in `derive.ts`, unit-tested against the schema.
