#!/usr/bin/env tsx
// Maintenance CLI: set an OidcClient's anonAppId (the anonymous-identity
// namespace slug) for a given clientId. This is how each RP (deforum, freedink,
// discreetly) is anon-enabled in prod after audit. There is deliberately no
// bulk/UI path — anon-enabling forks every user's per-app anonymous identity, so
// it is a one-time, from-a-shell operation.
//
// Enforces the SAME rules as the admin action (src/server/admin-actions.ts):
//   - shape:       validateAnonAppId  (^[a-z0-9-]{3,32}$)
//   - immutability: resolveAnonAppIdUpdate (only null → slug first-set; a set
//                   value can NEVER change — spec §8.1, invariant I7)
//   - uniqueness:  pre-check + the DB unique constraint (last line of defense)
//
// Usage (positional args; set DATABASE_URL the way the app does):
//   pnpm --filter @minister/app exec tsx scripts/set-anon-app-id.ts <clientId> <anonAppId>

import { prisma } from "../src/lib/prisma.js";
import { resolveAnonAppIdUpdate, validateAnonAppId } from "../src/lib/oidc-client-admin.js";

const [clientId, anonAppIdArg] = process.argv.slice(2);

if (!clientId || !anonAppIdArg) {
  console.error("Usage: set-anon-app-id.ts <clientId> <anonAppId>");
  process.exit(1);
}

async function main() {
  const validated = validateAnonAppId(anonAppIdArg);
  if (!validated.ok) throw new Error(validated.error);
  if (validated.anonAppId === null) {
    // A blank/whitespace slug validates to null; refuse it — this script only
    // ever SETS a value, and null can never clear a set one anyway.
    throw new Error("anonAppId must be a non-empty slug matching ^[a-z0-9-]{3,32}$");
  }

  const existing = await prisma.oidcClient.findUnique({
    where: { clientId },
    select: { id: true, anonAppId: true },
  });
  if (!existing) throw new Error(`No OIDC client with clientId "${clientId}"`);

  // Immutability: only a null → slug first-set is permitted. A repeat of the
  // current value is a no-op (`set: null`); any change is rejected.
  const update = resolveAnonAppIdUpdate(existing.anonAppId, validated.anonAppId);
  if (!update.ok) throw new Error(update.error);

  if (update.set === null) {
    console.log(
      `No change: clientId "${clientId}" already has anonAppId "${existing.anonAppId}" (immutable).`,
    );
    return;
  }

  // Uniqueness pre-check for a clean error; the DB unique constraint is the
  // authoritative guard against a race.
  const clash = await prisma.oidcClient.findUnique({
    where: { anonAppId: update.set },
    select: { clientId: true },
  });
  if (clash) {
    throw new Error(
      `anon app id "${update.set}" is already in use by clientId "${clash.clientId}"`,
    );
  }

  await prisma.$transaction([
    prisma.oidcClient.update({
      where: { id: existing.id },
      data: { anonAppId: update.set },
    }),
    prisma.auditLog.create({
      data: {
        action: "oidc.client.anon_app_id_set",
        metadata: { via: "scripts/set-anon-app-id.ts", clientId, anonAppId: update.set },
      },
    }),
  ]);

  console.log(`Set anonAppId "${update.set}" on clientId "${clientId}".`);
}

main()
  .catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
