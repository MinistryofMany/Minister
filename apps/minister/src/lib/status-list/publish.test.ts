import { randomBytes } from "node:crypto";

import { compactVerify, generateKeyPair, exportJWK } from "jose";
import { localSigner, type Issuer } from "@minister/vc";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// The publisher signs with a REAL local Ed25519 key so the output is verified as
// a genuine JWS; prisma + audit are mocked with a tiny in-memory store.

interface ListRow {
  id: string;
  clientId: string;
  shardNo: number;
  version: number;
  bits: Buffer;
  signedJwt: string;
  publishedAt: Date;
}
interface EntryRow {
  id: string;
  listId: string;
  bitIndex: number;
  revokedAt: Date | null;
  revealAfter: Date | null;
}

interface LagWhereCond {
  signedJwt: string | { not: string };
  publishedAt: { lt: Date };
}

const h = vi.hoisted(() => {
  const store = {
    lists: [] as ListRow[],
    entries: [] as EntryRow[],
    audits: [] as { action: string; metadata: Record<string, unknown> }[],
    // runScheduledPublish knobs.
    lockGranted: true,
    failListIds: new Set<string>(), // findUnique throws for these -> publishList throws
    updateManyCalls: 0,
    // When true, the FIRST updateMany bumps the row's version and returns count 0
    // (a concurrent writer took our version) to exercise the optimistic retry.
    raceVersionOnce: false,
  };
  const issuerRef = { current: null as unknown };

  const prismaMock: Record<string, unknown> = {
    $transaction: async <T>(fn: (tx: unknown) => Promise<T>): Promise<T> => fn(prismaMock),
    $queryRaw: vi.fn(async () => [{ locked: store.lockGranted }]),
    statusList: {
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => {
        if (store.failListIds.has(where.id)) throw new Error(`simulated failure for ${where.id}`);
        return store.lists.find((l) => l.id === where.id) ?? null;
      }),
      findMany: vi.fn(async (args?: { where?: { OR: LagWhereCond[] } }) => {
        // No `where` => runPublisherOnce's list sweep. A `where` => the lag query.
        if (!args?.where) return store.lists.map((l) => ({ id: l.id }));
        const or = args.where.OR;
        return store.lists
          .filter((l) =>
            or.some((cond) => {
              const old = l.publishedAt.getTime() < cond.publishedAt.lt.getTime();
              return typeof cond.signedJwt === "string"
                ? l.signedJwt === "" && old // never-signed branch
                : l.signedJwt !== "" && old; // signed-but-expired branch
            }),
          )
          .map((l) => ({ id: l.id, clientId: l.clientId }));
      }),
      updateMany: vi.fn(
        async ({
          where,
          data,
        }: {
          where: { id: string; version: number };
          data: Partial<ListRow>;
        }) => {
          store.updateManyCalls += 1;
          const row = store.lists.find((l) => l.id === where.id);
          if (!row) return { count: 0 };
          if (store.raceVersionOnce) {
            // A concurrent writer advanced the row between our read and write.
            store.raceVersionOnce = false;
            row.version += 1;
            return { count: 0 };
          }
          if (row.version !== where.version) return { count: 0 };
          Object.assign(row, data);
          return { count: 1 };
        },
      ),
    },
    badgeStatusEntry: {
      findMany: vi.fn(
        async ({
          where,
        }: {
          where: {
            listId: string;
            revokedAt: { not: null };
            OR: Array<{ revealAfter: { lte: Date } | null }>;
          };
        }) => {
          // S5: eligible = revoked AND (revealAfter <= now OR revealAfter null).
          const lteCond = where.OR.find((c) => c.revealAfter && "lte" in c.revealAfter);
          const nowMs =
            lteCond && lteCond.revealAfter ? lteCond.revealAfter.lte.getTime() : Date.now();
          return store.entries
            .filter(
              (e) =>
                e.listId === where.listId &&
                e.revokedAt !== null &&
                (e.revealAfter === null || e.revealAfter.getTime() <= nowMs),
            )
            .map((e) => ({ bitIndex: e.bitIndex }));
        },
      ),
    },
    auditLog: {
      create: vi.fn(
        async ({ data }: { data: { action: string; metadata: Record<string, unknown> } }) => {
          store.audits.push({ action: data.action, metadata: data.metadata });
        },
      ),
    },
  };

  return { store, issuerRef, prismaMock };
});
const store = h.store;

vi.mock("@/lib/prisma", () => ({ prisma: h.prismaMock }));
vi.mock("@/lib/issuer", () => ({ getIssuer: vi.fn(async () => h.issuerRef.current) }));

import { statusListUrl } from "./anchors";
import { getBit } from "./bitstring";
import { KMS_RAW_SIGN_MAX_BYTES } from "./constants";
import {
  buildStatusListPayload,
  publishList,
  runPublisherOnce,
  runScheduledPublish,
  signStatusListCredential,
} from "./publish";

const ORIGIN = "https://ministry.id";
let issuer: Issuer;

beforeAll(async () => {
  process.env.AUTH_URL = ORIGIN;
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  // Only did/kid/signer/publicKey are exercised; token/publicJwk are stubbed to
  // satisfy the Issuer shape.
  issuer = {
    did: "did:web:ministry.id",
    domain: "ministry.id",
    kid: "did:web:ministry.id#key-2",
    signer: localSigner(privateKey),
    publicKey,
    publicJwk,
    token: { kid: "did:web:ministry.id#key-3", privateKey, publicKey, publicJwk },
  } as Issuer;
  h.issuerRef.current = issuer;
});

afterAll(() => {
  delete process.env.AUTH_URL;
});

beforeEach(() => {
  store.lists = [];
  store.entries = [];
  store.audits = [];
  store.lockGranted = true;
  store.failListIds = new Set();
  store.updateManyCalls = 0;
  store.raceVersionOnce = false;
  vi.clearAllMocks();
});

async function decodePayload(jwt: string): Promise<Record<string, unknown>> {
  const verified = await compactVerify(jwt, issuer.publicKey);
  return JSON.parse(new TextDecoder().decode(verified.payload));
}

describe("signStatusListCredential — KMS 4096 ceiling (§5.3, auditor #11)", () => {
  it("a worst-case INCOMPRESSIBLE full 8,192-bit shard stays UNDER the 4096-byte cap", async () => {
    const bits = new Uint8Array(randomBytes(1024)); // random => gzip cannot shrink it
    const payload = buildStatusListPayload(issuer.did, "list_worstcase", bits, 1, Date.now());
    const jwt = await signStatusListCredential(issuer, payload);
    // The signing input is everything before the last '.'; confirm it verifies AND
    // was under the cap (the sign would have thrown otherwise).
    const signingInput = jwt.slice(0, jwt.lastIndexOf("."));
    expect(Buffer.byteLength(signingInput, "utf8")).toBeLessThanOrEqual(KMS_RAW_SIGN_MAX_BYTES);
    await expect(decodePayload(jwt)).resolves.toBeTruthy();
  });

  it("REFUSES to sign (throws loudly) when the signing input would exceed the cap", async () => {
    const payload = buildStatusListPayload(
      issuer.did,
      "list_big",
      new Uint8Array(1024),
      1,
      Date.now(),
    );
    // Force an oversized encodedList (simulating a larger shard) — the guard must
    // throw before any signer call, never truncate or downgrade the key.
    payload.vc.credentialSubject.encodedList = `u${"A".repeat(5000)}`;
    await expect(signStatusListCredential(issuer, payload)).rejects.toThrow(
      /exceeds the KMS RAW cap/,
    );
  });
});

describe("publishList — the kick -> bit -> signed-list cycle", () => {
  it("folds an eligible revocation into a fresh, verifiable, URL-bound signed list", async () => {
    const listId = "list_1";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 0,
      bits: Buffer.alloc(1024),
      signedJwt: "",
      publishedAt: new Date(0),
    });
    store.entries.push({
      id: "e1",
      listId,
      bitIndex: 42,
      revokedAt: new Date(),
      revealAfter: new Date(Date.now() - 1000), // jitter elapsed
    });

    const now = Date.now();
    const expectedVersion = Math.max(0 + 1, Math.floor(now / 1000)); // W4 wall clock
    const result = await publishList(listId, { issuer, now });
    expect(result.published).toBe(true);
    expect(result.changed).toBe(true);
    expect(result.version).toBe(expectedVersion);
    expect(result.revokedBits).toBe(1);

    const row = store.lists[0]!;
    expect(row.version).toBe(expectedVersion);
    expect(row.signedJwt).not.toBe("");
    expect(getBit(new Uint8Array(row.bits), 42)).toBe(true);

    const payload = await decodePayload(row.signedJwt);
    expect(payload.sub).toBe(statusListUrl(listId)); // URL binding (defense 1)
    expect(payload.statusListVersion).toBe(expectedVersion);
    const vc = payload.vc as { type: string[]; credentialSubject: { statusPurpose: string } };
    expect(vc.type).toContain("BitstringStatusListCredential");
    expect(vc.credentialSubject.statusPurpose).toBe("revocation");
    expect(store.audits.some((a) => a.action === "status.list_published")).toBe(true);
  });

  it("does NOT fold a revocation whose jitter floor has not elapsed (§5.7)", async () => {
    const listId = "list_2";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 1,
      bits: Buffer.alloc(1024),
      signedJwt: "already-signed",
      publishedAt: new Date(), // fresh -> no heartbeat due
    });
    store.entries.push({
      id: "e2",
      listId,
      bitIndex: 7,
      revokedAt: new Date(),
      revealAfter: new Date(Date.now() + 60_000), // reveal in the future
    });

    const result = await publishList(listId, { issuer });
    expect(result.published).toBe(false);
    expect(getBit(new Uint8Array(store.lists[0]!.bits), 7)).toBe(false);
  });

  it("bumps a MONOTONIC version and re-signs on heartbeat even with no bit change", async () => {
    const listId = "list_3";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 5,
      bits: Buffer.alloc(1024),
      signedJwt: "stale-sig",
      publishedAt: new Date(Date.now() - 10 * 60_000), // 10 min ago -> past heartbeat
    });

    const now = Date.now();
    // W4: version is a wall clock floored strictly above the prior version.
    const expectedVersion = Math.max(5 + 1, Math.floor(now / 1000));
    const result = await publishList(listId, { issuer, now });
    expect(result.published).toBe(true);
    expect(result.changed).toBe(false); // heartbeat, no revocation
    expect(store.lists[0]!.version).toBe(expectedVersion);
    expect(store.lists[0]!.version).toBeGreaterThan(5); // still strictly monotonic
  });

  it("initial publication signs a never-yet-signed shard", async () => {
    const listId = "list_new";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 0,
      bits: Buffer.alloc(1024),
      signedJwt: "",
      publishedAt: new Date(),
    });
    const result = await publishList(listId, { issuer });
    expect(result.published).toBe(true);
    expect(store.lists[0]!.signedJwt).not.toBe("");
  });

  it("runPublisherOnce sweeps every list", async () => {
    store.lists.push(
      {
        id: "a",
        clientId: "mc_1",
        shardNo: 0,
        version: 0,
        bits: Buffer.alloc(1024),
        signedJwt: "",
        publishedAt: new Date(),
      },
      {
        id: "b",
        clientId: "mc_2",
        shardNo: 0,
        version: 0,
        bits: Buffer.alloc(1024),
        signedJwt: "",
        publishedAt: new Date(),
      },
    );
    const summary = await runPublisherOnce();
    expect(summary.lists).toBe(2);
    expect(summary.published).toBe(2);
    expect(summary.failed).toEqual([]);
  });

  it("S5: publishes a revoked entry whose revealAfter is NULL (no jitter floor)", async () => {
    const listId = "list_nulljitter";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 0,
      bits: Buffer.alloc(1024),
      signedJwt: "",
      publishedAt: new Date(0),
    });
    // revokedAt set but revealAfter NULL — must not silently never publish.
    store.entries.push({
      id: "e_null",
      listId,
      bitIndex: 9,
      revokedAt: new Date(),
      revealAfter: null,
    });

    const result = await publishList(listId, { issuer, now: Date.now() });
    expect(result.changed).toBe(true);
    expect(result.revokedBits).toBe(1);
    expect(getBit(new Uint8Array(store.lists[0]!.bits), 9)).toBe(true);
  });

  it("C2b: retries a lost optimistic write (a concurrent writer advanced the version)", async () => {
    const listId = "list_race";
    store.lists.push({
      id: listId,
      clientId: "mc_rp",
      shardNo: 0,
      version: 5,
      bits: Buffer.alloc(1024),
      signedJwt: "stale-sig",
      publishedAt: new Date(Date.now() - 10 * 60_000), // heartbeat-due
    });
    store.raceVersionOnce = true; // first guarded write loses (count 0)

    const result = await publishList(listId, { issuer, now: Date.now() });
    expect(result.published).toBe(true); // the retry succeeded
    expect(store.updateManyCalls).toBeGreaterThanOrEqual(2); // lost once, then won
  });

  it("runPublisherOnce isolates a per-list failure (collects it, sweeps the rest)", async () => {
    store.lists.push(
      {
        id: "ok",
        clientId: "mc_1",
        shardNo: 0,
        version: 0,
        bits: Buffer.alloc(1024),
        signedJwt: "",
        publishedAt: new Date(),
      },
      {
        id: "boom",
        clientId: "mc_2",
        shardNo: 0,
        version: 0,
        bits: Buffer.alloc(1024),
        signedJwt: "",
        publishedAt: new Date(),
      },
    );
    store.failListIds.add("boom");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const summary = await runPublisherOnce();
    errSpy.mockRestore();

    expect(summary.lists).toBe(2);
    expect(summary.published).toBe(1); // "ok" still published
    expect(summary.failed).toHaveLength(1);
    expect(summary.failed[0]!.listId).toBe("boom");
  });

  it("runScheduledPublish no-ops when another instance holds the advisory lock", async () => {
    store.lockGranted = false;
    store.lists.push({
      id: "a",
      clientId: "mc_1",
      shardNo: 0,
      version: 0,
      bits: Buffer.alloc(1024),
      signedJwt: "",
      publishedAt: new Date(),
    });

    const outcome = await runScheduledPublish(60_000);
    expect(outcome).toBe("skipped-locked");
    expect(store.lists[0]!.signedJwt).toBe(""); // never signed under the lost lock
  });

  it("runScheduledPublish holds the lock, sweeps, and ALERTS on publisher lag (§9.8)", async () => {
    store.lockGranted = true;
    // A signed list whose last publication is older than the validity window AND
    // whose re-sign fails this pass -> stays lagging -> a lag alert must fire.
    store.lists.push({
      id: "lagging",
      clientId: "mc_x",
      shardNo: 0,
      version: 3,
      bits: Buffer.alloc(1024),
      signedJwt: "old-sig",
      publishedAt: new Date(Date.now() - 60 * 60_000), // 1h ago, past the 15m window
    });
    store.failListIds.add("lagging");
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const outcome = await runScheduledPublish(60_000);

    expect(outcome).toBe("published");
    expect(store.audits.some((a) => a.action === "status.publisher_lag")).toBe(true);
    expect(errSpy).toHaveBeenCalledWith(expect.stringContaining("PUBLISHER LAG"));
    errSpy.mockRestore();
  });
});
