import { z } from "zod";

// Validate env at module load. Bad config should crash the server, not
// surface as a 500 deep inside a request handler.

const serverSchema = z
  .object({
    DATABASE_URL: z.string().url(),

    AUTH_SECRET: z.string().min(32, "AUTH_SECRET must be at least 32 chars"),
    AUTH_URL: z.string().url().optional(),
    AUTH_TRUST_HOST: z
      .union([z.literal("true"), z.literal("false")])
      .optional()
      .transform((v) => v === "true"),

    // Issuer identity. In dev: minister.local (symbolic — the DID document is
    // only resolvable once we have real DNS + TLS).
    MINISTER_ISSUER_DOMAIN: z.string().default("minister.local"),

    // Secret used to derive pairwise pseudonymous OIDC `sub` values.
    // Different RPs see different `sub`s for the same user. Required (min
    // length checked in the refine so an unset value surfaces the
    // required-error, not a length-error) until Phase 7 moves the derivation
    // into Signet.
    OIDC_PAIRWISE_SECRET: z.string().optional(),

    // Selects the pairwise-sub derivation backend (crypto-core Phase 7 seam,
    // lib/pairwise-backend.ts). Staged cutover: local → shadow →
    // signet-fallback → signet. Default (unset) is `local` — merging the seam
    // changes NOTHING at runtime. `shadow` serves the local value and compares
    // an async Signet call; `signet-fallback` serves Signet with a
    // byte-identical local fallback; `signet` serves Signet only.
    //
    // OIDC_PAIRWISE_SECRET stays REQUIRED here even under `signet` for now: the
    // secret is only removed from Minister at the SIGN-OFF-gated 7c deploy step,
    // which relaxes the requirement below (conditional-off under `signet`) in
    // its own change. Constraining the enum to these four values means a typo
    // fails at boot instead of silently behaving as unset.
    MINISTER_SUB_BACKEND: z.enum(["local", "shadow", "signet-fallback", "signet"]).optional(),

    // Sybil-dedup nullifier backend (crypto-core Phase 3). `interim` keeps the
    // in-Minister HMAC ledger; `signet` routes stage-1 through Signet's VOPRF
    // surface and requires the full MINISTER_SIGNET_* set below (checked in
    // the refine so a half-configured signet backend fails at boot, never as
    // a 500 inside a wizard step).
    MINISTER_NULLIFIER_BACKEND: z.enum(["interim", "signet"]).default("interim"),
    // Signet base URL, e.g. https://signet:8443. https-only: the transport is
    // hardwired to mTLS, so an http:// value could only ever produce opaque
    // TLS-handshake failures against a plaintext port — fail at boot instead.
    MINISTER_SIGNET_URL: z
      .string()
      .url()
      .refine((v) => v.startsWith("https://"), "must be an https:// URL (mTLS-only)")
      .optional(),
    // mTLS material: inline PEM or a file path (resolved in the backend).
    MINISTER_SIGNET_CLIENT_CERT: z.string().optional(),
    MINISTER_SIGNET_CLIENT_KEY: z.string().optional(),
    MINISTER_SIGNET_CA_CERT: z.string().optional(),
    // The pinned VOPRF public key pkS printed by `signet init-service-keys`
    // (base64url no padding, 43 chars). The backend fetch-and-verifies it
    // against /prf/public-key and DLEQ-verifies every evaluation against it,
    // fail-closed — the ISSUER_KMS_PUBLIC_JWK pattern.
    MINISTER_SIGNET_DEDUP_PUBKEY: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43}$/, "must be base64url(32 bytes), no padding")
      .optional(),
    // Absolute per-request Signet deadline in ms (default 5000). Bounded:
    // 0/garbage would corrupt the transport timers, and anything past 15s
    // breaks the advisory-lock lifetime arithmetic (signet-backend.ts).
    MINISTER_SIGNET_TIMEOUT_MS: z.coerce.number().int().min(100).max(15_000).optional(),
    // Dedicated per-request Signet deadline for the PAIRWISE seam (Phase 7,
    // lib/pairwise-backend.ts), DECOUPLED from MINISTER_SIGNET_TIMEOUT_MS (the
    // nullifier backend's knob, whose 15s cap is sized for the VOPRF
    // advisory-lock arithmetic). The pairwise path is on the hot token-mint /
    // userinfo / share-render path; §4 Step 3 wants a tight budget (default
    // 500ms, bounded 100..2000) so a Signet brownout falls back byte-identically
    // fast instead of stalling every mint — without squeezing the VOPRF path.
    MINISTER_SIGNET_PAIRWISE_TIMEOUT_MS: z.coerce.number().int().min(100).max(2_000).optional(),

    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  })
  .superRefine((val, ctx) => {
    // The signet nullifier backend is unusable half-configured: require the
    // full transport + pin set at boot.
    if (val.MINISTER_NULLIFIER_BACKEND === "signet") {
      for (const key of [
        "MINISTER_SIGNET_URL",
        "MINISTER_SIGNET_CLIENT_CERT",
        "MINISTER_SIGNET_CLIENT_KEY",
        "MINISTER_SIGNET_CA_CERT",
        "MINISTER_SIGNET_DEDUP_PUBKEY",
      ] as const) {
        if (!val[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when MINISTER_NULLIFIER_BACKEND=signet`,
          });
        }
      }
    }
    // The non-local pairwise-sub backends (Phase 7 seam) each perform Signet
    // mTLS I/O per derivation, reading the transport config lazily at request
    // time (pairwise-backend.ts pairwiseTransportConfig throws per call). A
    // half-configured non-local backend therefore boots CLEAN and then fails
    // only in production traffic: under `signet` a total token-mint outage
    // surfacing as 500s deep inside /oidc/token and /oidc/userinfo, under
    // `shadow`/`signet-fallback` a silent degrade to pure shadow-error /
    // fallback noise (a soak whose zero mismatches are vacuous). This is exactly
    // the "500s deep inside token minting" failure the enum constraint and the
    // nullifier-backend precedent below exist to prevent, so mirror that loop.
    // The DEDUP pubkey PIN is NOT needed — /prf/pairwise is a bare keyed-HMAC
    // oracle with no DLEQ/pinned-key analogue.
    if (val.MINISTER_SUB_BACKEND !== undefined && val.MINISTER_SUB_BACKEND !== "local") {
      for (const key of [
        "MINISTER_SIGNET_URL",
        "MINISTER_SIGNET_CLIENT_CERT",
        "MINISTER_SIGNET_CLIENT_KEY",
        "MINISTER_SIGNET_CA_CERT",
      ] as const) {
        if (!val[key]) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: [key],
            message: `${key} is required when MINISTER_SUB_BACKEND=${val.MINISTER_SUB_BACKEND}`,
          });
        }
      }
    }
    // Pre-7c-i safety: a pure `signet` sub-backend serves Signet's /prf/pairwise
    // output with NO crosscheck against the local golden value — unlike `shadow`
    // and `signet-fallback`, which still compute the local HMAC and compare
    // (serving the byte-identical local value on any drift). While
    // OIDC_PAIRWISE_SECRET is still present the local truth is available, so a
    // silently drifted / compromised Signet value would go UNDETECTED only under
    // `signet`. Reject `signet` at boot as long as the secret is set; it becomes
    // legitimate ONLY post-7c-i, once OIDC_PAIRWISE_SECRET has been removed from
    // Minister (pairwise-backend.ts:derivePairwise `signet` branch). THIS CHECK
    // INVERTS AT 7c-i: when the secret is gone, `signet` is the intended mode and
    // the OIDC_PAIRWISE_SECRET required-check below flips to require its ABSENCE.
    if (val.MINISTER_SUB_BACKEND === "signet" && val.OIDC_PAIRWISE_SECRET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["MINISTER_SUB_BACKEND"],
        message:
          "MINISTER_SUB_BACKEND=signet is not allowed while OIDC_PAIRWISE_SECRET is still set " +
          "(pure signet has no local crosscheck; use shadow or signet-fallback until the 7c-i secret removal)",
      });
    }
    // OIDC_PAIRWISE_SECRET is REQUIRED. Boot fails fast here rather than
    // deriving under an absent/wrong key deep inside a token mint. Phase 7
    // (pairwise sub derived inside Signet, which holds the imported secret)
    // relaxes this together with widening MINISTER_SUB_BACKEND above.
    if (!val.OIDC_PAIRWISE_SECRET) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OIDC_PAIRWISE_SECRET"],
        message: "OIDC_PAIRWISE_SECRET is required",
      });
    } else if (val.OIDC_PAIRWISE_SECRET.length < 32) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["OIDC_PAIRWISE_SECRET"],
        message: "OIDC_PAIRWISE_SECRET must be at least 32 chars",
      });
    }
  });

const env = serverSchema.parse(process.env);

export { env };
