#!/usr/bin/env tsx
// Interim-window deploy gate (crypto-core Phase 1, build plan §2.2 / §3
// "Interim-window guard"). The Phase 1-3 interim nullifier backend stores
// deterministic HMAC values in Minister's own Postgres with the deriving key
// co-resident — the M1 exfil/dictionary oracle the ADR accepts ONLY under a hard
// `users == 0` assumption. This script IS that assertion: it counts real,
// live user rows and exits NON-ZERO if any exist, so a deploy pipeline can gate
// on it, e.g.
//
//   pnpm --filter @minister/app users:count && ./deploy.sh
//
// Exit codes: 0 = zero real users (safe to proceed); 1 = one or more real users
// (STOP — re-plan the interim window, build plan risk #2); 2 = usage error.
//
// EXCLUSIONS (explicit and documented — a "real user" is none of these):
//   * isAdmin = true      — operator/staff accounts (admins are minted only from
//                           a shell via scripts/make-admin.ts, never self-serve).
//   * mergedIntoUserId != null — tombstoned donor accounts from an account merge;
//                           they are not a live identity.
//   * email in --exclude-email <addr> (repeatable) or the comma-separated
//     COUNT_USERS_EXCLUDE_EMAILS env var — named test accounts the operator
//     keeps (e.g. the e2e/demo user). Matched case-insensitively against
//     User.email.
//
// Set DATABASE_URL the same way the app does.

import { parseArgs } from "node:util";

import { PrismaClient } from "../src/generated/prisma/index.js";

const { values } = parseArgs({
  options: {
    "exclude-email": { type: "string", multiple: true },
  },
});

const cliExcludes = values["exclude-email"] ?? [];
const envExcludes = (process.env.COUNT_USERS_EXCLUDE_EMAILS ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter((s) => s.length > 0);
// Case-insensitive email exclusion set.
const excludedEmails = new Set([...cliExcludes, ...envExcludes].map((e) => e.toLowerCase()));

const prisma = new PrismaClient();

async function main(): Promise<void> {
  // Operator + tombstone exclusions run in the query; email exclusion is applied
  // in-process (case-insensitive, small allowlist) so the rule stays obvious.
  const candidates = await prisma.user.findMany({
    where: { isAdmin: false, mergedIntoUserId: null },
    select: { id: true, email: true },
  });

  const realUsers = candidates.filter(
    (u) => !(u.email && excludedEmails.has(u.email.toLowerCase())),
  );

  const excludedByEmail = candidates.length - realUsers.length;
  console.log(
    `real users (excluding operators, tombstones, allowlisted emails): ${realUsers.length}`,
  );
  console.log(
    `  excluded: admins/tombstones filtered in query; ${excludedByEmail} allowlisted-email account(s)`,
  );
  if (excludedEmails.size > 0) {
    console.log(`  email allowlist: ${[...excludedEmails].join(", ")}`);
  }

  if (realUsers.length > 0) {
    console.error(
      `\nSTOP: ${realUsers.length} real user(s) present — the interim-window users==0 gate FAILS.`,
    );
    process.exit(1);
  }
  console.log("\nusers == 0: interim-window gate OK.");
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
