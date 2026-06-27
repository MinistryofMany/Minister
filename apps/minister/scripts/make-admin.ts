#!/usr/bin/env tsx
// Admin CLI: grant or revoke the isAdmin flag by email. There is
// deliberately no in-app path to admin-ness — the first (and every)
// admin is minted from a shell with DB access.
//
// Usage (no `--` separator — pnpm forwards flags to the script as-is):
//   pnpm --filter @minister/app admin:grant --email you@example.com
//   pnpm --filter @minister/app admin:grant --email you@example.com --revoke
//
// Set DATABASE_URL the same way the app does.

import { parseArgs } from "node:util";

import { PrismaClient } from "../src/generated/prisma/index.js";

const { values } = parseArgs({
  options: {
    email: { type: "string" },
    revoke: { type: "boolean" },
  },
});

if (!values.email) {
  console.error("Usage: make-admin.ts --email <email> [--revoke]");
  process.exit(1);
}

const prisma = new PrismaClient();

async function main() {
  const isAdmin = !values.revoke;
  // email is no longer @unique on User; resolve to the id first, then update
  // by primary key.
  const match = await prisma.user.findFirst({
    where: { email: values.email },
    select: { id: true },
  });
  if (!match) {
    throw Object.assign(new Error(`No user with email ${values.email}`), { code: "P2025" });
  }
  const user = await prisma.user.update({
    where: { id: match.id },
    data: { isAdmin },
    select: { id: true, email: true, isAdmin: true },
  });
  await prisma.auditLog.create({
    data: {
      userId: user.id,
      action: isAdmin ? "admin.granted" : "admin.revoked",
      metadata: { via: "scripts/make-admin.ts" },
    },
  });
  console.log(`${user.email}: isAdmin = ${user.isAdmin} (userId ${user.id})`);
}

main()
  .catch((err) => {
    if (err instanceof Error && "code" in err && (err as { code?: string }).code === "P2025") {
      console.error(`No user with email ${values.email}`);
    } else {
      console.error(err);
    }
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
