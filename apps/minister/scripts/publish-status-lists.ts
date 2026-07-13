#!/usr/bin/env tsx
// Run ONE pass of the badge-revocation status-list publisher
// (docs/groups-revocation-design.md §5.5): fold in every eligible revocation,
// flip bits, bump versions, re-sign #key-2 credentials, and re-sign quiet lists
// past the heartbeat interval. Single-writer — never run two concurrently.
//
// The escape hatch + test/ops surface for the publisher; wire a scheduler (cron
// every 60s, or an in-process interval) to call `runPublisherOnce`. Exposed as
// `status:publish`. Set DATABASE_URL (and, in prod, the KMS #key-2 env) the same
// way the app does.

import { prisma } from "../src/lib/prisma.js";
import { runPublisherOnce } from "../src/lib/status-list/index.js";

async function main(): Promise<void> {
  const summary = await runPublisherOnce();
  console.log(
    `[status:publish] lists=${summary.lists} published=${summary.published} changed=${summary.changed}`,
  );
}

main()
  .catch((err: unknown) => {
    console.error("[status:publish] failed:", err);
    process.exit(1);
  })
  .finally(() => {
    void prisma.$disconnect();
  });
