// Next.js startup hook (App Router, stable in 15). Runs once per server
// boot, before any request is served. We use it for fail-loud-at-boot
// config checks that we'd otherwise only discover deep inside a request.

export async function register(): Promise<void> {
  // Only meaningful on the Node.js runtime; skip the edge bundle.
  if (process.env.NEXT_RUNTIME !== "nodejs") return;

  // MUST run first: pull SecureString secrets from SSM into process.env before
  // anything reads config — the issuer keys (issuer.ts), Prisma's DATABASE_URL,
  // Auth.js's AUTH_SECRET, and the OIDC pairwise secret. Next awaits register()
  // before serving requests, and the edge middleware sandbox snapshots
  // process.env on its first request (after this), so AUTH_SECRET reaches
  // middleware too. Fail-closed in prod (throws), inert with no SSM path.
  const { loadSecretsFromSsm } = await import("@/lib/secrets");
  await loadSecretsFromSsm();

  // Validate the server env NOW — AFTER the SSM secrets are in process.env and
  // before any request runs. env.ts parses process.env at module load and THROWS
  // on a bad/half-configured deploy: a non-local pairwise backend missing its
  // MINISTER_SIGNET_* transport, a pure `signet` sub-backend while
  // OIDC_PAIRWISE_SECRET is still present, a MINISTER_SUB_BACKEND typo, an
  // http:// (non-mTLS) Signet URL, or a missing/short pairwise secret. Without
  // this a half-configured shadow/signet-fallback/signet deploy boots clean and
  // 500s deep inside token minting instead of failing fast here.
  //
  // Ordering is load-bearing: it MUST run after loadSecretsFromSsm() (the secret,
  // DATABASE_URL, and cert material may all arrive from SSM) and it is a DYNAMIC
  // import so the module is not pulled into the edge/middleware compile and does
  // not parse before the SSM load has populated process.env.
  await import("@/env");

  const { validateTlsnVerifierConfig } = await import("@/lib/tlsn-verifier");
  validateTlsnVerifierConfig();

  // Crypto-core Phase 3: when the signet nullifier backend is selected,
  // fetch-and-verify the pinned VOPRF public key against the live Signet at
  // boot (the build plan's "mirrors the KMS JWK pattern"). Runs after the SSM
  // load above (the pin and cert material may come from SSM).
  //
  // Fail-closed on a FORK, tolerant of an OUTAGE:
  //   * a served-key / suite mismatch (SignetPinMismatchError) is a mis-pin or
  //     fork — rethrow, killing boot, exactly as before;
  //   * a transient failure (Signet unreachable, timeout, non-200) does NOT
  //     kill boot. A box that starts Minister before Signet — or a brief Signet
  //     blip during a reboot — must not crash-loop all of ministry.id. We log
  //     and DEFER pin verification to lazy first-use: ensurePinVerified re-runs
  //     before the first nullifier op (and only a real success memoizes), and
  //     every VOPRF finalize independently DLEQ-verifies against the pin, so no
  //     nullifier op can proceed without a verified pin. Deferring costs no
  //     security — only the boot-time ops signal.
  //
  // The explicit NEXT_RUNTIME guard (redundant with the early return above at
  // runtime) is FOR WEBPACK: instrumentation is compiled for the edge bundle
  // too, where node:https/node:fs cannot resolve — the statically-false
  // branch makes webpack drop this import from the edge compile entirely.
  if (
    process.env.NEXT_RUNTIME === "nodejs" &&
    process.env.MINISTER_NULLIFIER_BACKEND === "signet"
  ) {
    const { signetBackend, SignetPinMismatchError } =
      await import("@/lib/nullifier/signet-backend");
    try {
      await signetBackend.verifyPin();
    } catch (err) {
      if (err instanceof SignetPinMismatchError) throw err;
      console.warn(
        "[instrumentation] Signet pin verification deferred to first use " +
          `(Signet unreachable at boot): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // Anti-sybil config integrity (anti-sybil phase 1, §3/§5). Assert every
  // knownBadgeTypes() has a `*` BadgeWeight row and every referenced category
  // exists — otherwise the scorer silently contributes 0 for a type and
  // recovery would fail closed mid-attempt. Dynamic import so the edge bundle
  // drops it.
  //
  // Resilient to a transient DB outage the same way the Signet check is: a
  // QUERY error (DB briefly unreachable at boot) is logged and skipped rather
  // than crash-looping the box; a SUCCESSFUL query that reveals genuine DRIFT
  // is fail-loud in prod (throw) and a console.warn in dev.
  {
    const { checkSybilConfigDrift } = await import("@/lib/sybil-config");
    try {
      const { missingStarRows, danglingCategories, missingSingletons } =
        await checkSybilConfigDrift();
      if (
        missingStarRows.length > 0 ||
        danglingCategories.length > 0 ||
        missingSingletons.length > 0
      ) {
        const detail =
          `[instrumentation] sybil config drift: ` +
          `${missingStarRows.length} type(s) missing a '*' BadgeWeight row ` +
          `[${missingStarRows.join(", ")}]; ` +
          `${danglingCategories.length} row category(ies) with no SybilCategory ` +
          `[${danglingCategories.join(", ")}]; ` +
          `${missingSingletons.length} missing singleton row(s) ` +
          `[${missingSingletons.join(", ")}]. Run \`sybil:seed\`.`;
        if (process.env.NODE_ENV === "production") throw new Error(detail);
        console.warn(detail);
      }
    } catch (err) {
      // A drift Error we threw above must propagate in prod.
      if (
        process.env.NODE_ENV === "production" &&
        err instanceof Error &&
        err.message.startsWith("[instrumentation] sybil config drift:")
      ) {
        throw err;
      }
      // A MISSING config table/column (the migration was never applied — a deploy
      // error, and CLAUDE.md notes prod migrations are MANUAL) is genuine drift,
      // NOT a transient outage: fail closed in prod. Distinguish by the Prisma /
      // Postgres schema-error CODE, not by catching everything. Only a real
      // connectivity error is tolerated (deferred), matching the Signet pattern.
      if (process.env.NODE_ENV === "production" && isSchemaMissingError(err)) {
        throw new Error(
          "[instrumentation] sybil config tables missing (migration not applied): " +
            (err instanceof Error ? err.message : String(err)),
        );
      }
      console.warn(
        "[instrumentation] sybil config check deferred " +
          `(DB unreachable at boot): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // Badge-statistics recompute interval (anti-sybil phase 2, §4/§7). Materializes
  // BadgeStat / CohortStat / BucketStat on a schedule so the admin + public pages
  // read cheap rows. PRODUCTION-ONLY (dev/test use `stats:recompute` or the admin
  // button); jittered start so multi-instance boots don't all fire at once; a
  // Postgres advisory lock (STATS_ADVISORY_LOCK_KEY, distinct from the
  // recovery-config lock) + a StatsRun freshness check make a second instance a
  // no-op. Every tick is wrapped in try/catch — a recompute failure LOGS and is
  // never allowed to crash boot or serving.
  //
  // The explicit NEXT_RUNTIME guard (redundant with the early return above at
  // runtime) is FOR WEBPACK, exactly like the Signet check: instrumentation is
  // compiled for the edge bundle too, and stats-recompute pulls in issuer ->
  // @minister/vc -> node:path/node:fs, which cannot resolve on edge. The
  // statically-false branch makes webpack drop this dynamic import from the edge
  // compile entirely.
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.NODE_ENV === "production") {
    const { env } = await import("@/env");
    const intervalMs = env.MINISTER_STATS_INTERVAL_MS;

    const runOnce = async (): Promise<void> => {
      try {
        const { runScheduledStatsRecompute } = await import("@/lib/stats-recompute");
        const outcome = await runScheduledStatsRecompute(intervalMs);
        if (outcome === "recomputed") console.info("[instrumentation] badge stats recomputed.");
      } catch (err) {
        console.error(
          "[instrumentation] badge-stats recompute failed (will retry next interval): " +
            (err instanceof Error ? err.message : String(err)),
        );
      }
    };

    // Jitter the first run across [0, intervalMs) so N instances (and a rolling
    // redeploy) spread their attempts rather than thundering the DB in lockstep.
    const jitter = Math.floor(Math.random() * intervalMs);
    const startTimer = setTimeout(() => {
      void runOnce();
      const interval = setInterval(() => void runOnce(), intervalMs);
      // Don't let the interval keep the process alive on its own.
      interval.unref();
    }, jitter);
    startTimer.unref();
  }

  // Badge-revocation status-list PUBLISHER interval (docs/groups-revocation-design.md
  // §5.5). Without a runner NO list is ever signed: /status/[listId] 503s forever,
  // every RP status check returns "stale", and — with the SDK's fail-open default —
  // a kicked member silently RETAINS access. This is the layer-2 single-writer.
  // PRODUCTION-ONLY (dev/test use the `status:publish` script); jittered start;
  // advisory-locked so a second instance no-ops; publisher-lag alerting (a SECURITY
  // control, §9.8) runs each pass. Every tick is wrapped so a failure LOGS and never
  // crashes boot or serving.
  //
  // The explicit NEXT_RUNTIME guard (redundant with the early return above at
  // runtime) is FOR WEBPACK, exactly like the stats block: the publisher pulls in
  // issuer -> @minister/vc -> node:path/node:fs, which cannot resolve on edge. The
  // statically-false branch makes webpack drop this dynamic import from the edge
  // compile entirely.
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.NODE_ENV === "production") {
    const { env } = await import("@/env");
    const publishIntervalMs = env.MINISTER_STATUS_PUBLISH_INTERVAL_MS;

    const publishOnce = async (): Promise<void> => {
      try {
        const { runScheduledPublish } = await import("@/lib/status-list");
        const outcome = await runScheduledPublish(publishIntervalMs);
        if (outcome === "published") {
          console.info("[instrumentation] status-list publisher pass complete.");
        }
      } catch (err) {
        console.error(
          "[instrumentation] status-list publish failed (will retry next interval): " +
            (err instanceof Error ? err.message : String(err)),
        );
      }
    };

    const publishJitter = Math.floor(Math.random() * publishIntervalMs);
    const publishStartTimer = setTimeout(() => {
      void publishOnce();
      const interval = setInterval(() => void publishOnce(), publishIntervalMs);
      interval.unref();
    }, publishJitter);
    publishStartTimer.unref();
  }
}

// A Prisma/Postgres "schema object is missing" error (table or column absent),
// meaning the migration was not applied — distinct from a transient connection
// failure. Structural (no static Prisma import) so this stays out of the edge
// bundle. P2021 = table missing, P2022 = column missing (Prisma); 42P01 =
// undefined_table, 42703 = undefined_column (raw Postgres).
function isSchemaMissingError(err: unknown): boolean {
  if (typeof err !== "object" || err === null) return false;
  const code = (err as { code?: unknown }).code;
  return code === "P2021" || code === "P2022" || code === "42P01" || code === "42703";
}
