import { PrismaClient } from "@/generated/prisma";

// Dedicated Prisma client for the signet advisory-lock transactions
// (withSignetEntryLock in signet-backend.ts) — a BULKHEAD, deliberately
// separate from the shared client in @/lib/prisma.
//
// Why: a lock transaction holds its connection for the whole guarded window,
// which includes a Signet network round trip. On the shared pool that pins
// app-wide connections across network I/O — N concurrent anchor-bearing mints
// could starve every session check in the app, and a DATABASE_URL tuned to
// connection_limit=1 (pgbouncer/serverless) would deadlock outright: the lock
// transaction holds the only connection while the guarded callback's queries
// wait for one. A separate client with its own small pool caps the blast
// radius: at most LOCK_POOL_CONNECTIONS signet windows run concurrently,
// contenders past that fail fast (P2024, surfaced as a retryable wizard
// error), and the shared pool never sees a lock transaction at all.
//
// Sizing: the guarded windows are short (badge mint + one bounded Signet
// round trip, or sibling count + one bounded round trip) and keyed per
// entryRef, so concurrency demand is low; 4 comfortably covers alpha-scale
// issuance while keeping worst-case pinned connections trivial. pool_timeout
// mirrors the previous maxWait bound.
const LOCK_POOL_CONNECTIONS = 4;
const LOCK_POOL_TIMEOUT_S = 10;

// Cache across dev HMR cycles (same reason as @/lib/prisma) — and lazily:
// the interim backend must never construct this client.
const globalForLockClient = globalThis as unknown as { signetLockClient?: PrismaClient };

export function getLockClient(): PrismaClient {
  if (globalForLockClient.signetLockClient) return globalForLockClient.signetLockClient;
  const raw = process.env.DATABASE_URL;
  if (!raw) {
    throw new Error("nullifier: DATABASE_URL must be set (signet lock client)");
  }
  const url = new URL(raw);
  url.searchParams.set("connection_limit", String(LOCK_POOL_CONNECTIONS));
  url.searchParams.set("pool_timeout", String(LOCK_POOL_TIMEOUT_S));
  const client = new PrismaClient({ datasourceUrl: url.toString() });
  globalForLockClient.signetLockClient = client;
  return client;
}
