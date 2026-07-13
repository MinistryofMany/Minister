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

const h = vi.hoisted(() => {
  const store = {
    lists: [] as ListRow[],
    entries: [] as EntryRow[],
    audits: [] as { action: string; metadata: Record<string, unknown> }[],
  };
  const issuerRef = { current: null as unknown };

  const prismaMock = {
    statusList: {
      findUnique: vi.fn(async ({ where }: { where: { id: string } }) => {
        return store.lists.find((l) => l.id === where.id) ?? null;
      }),
      findMany: vi.fn(async () => store.lists.map((l) => ({ id: l.id }))),
      update: vi.fn(async ({ where, data }: { where: { id: string }; data: Partial<ListRow> }) => {
        const row = store.lists.find((l) => l.id === where.id);
        if (row) Object.assign(row, data);
        return row;
      }),
    },
    badgeStatusEntry: {
      findMany: vi.fn(
        async ({ where }: { where: { listId: string; revealAfter: { lte: Date } } }) => {
          const now = where.revealAfter.lte;
          return store.entries
            .filter(
              (e) =>
                e.listId === where.listId &&
                e.revokedAt !== null &&
                e.revealAfter !== null &&
                e.revealAfter.getTime() <= now.getTime(),
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

    const result = await publishList(listId, { issuer });
    expect(result.published).toBe(true);
    expect(result.changed).toBe(true);
    expect(result.version).toBe(1);
    expect(result.revokedBits).toBe(1);

    const row = store.lists[0]!;
    expect(row.version).toBe(1);
    expect(row.signedJwt).not.toBe("");
    expect(getBit(new Uint8Array(row.bits), 42)).toBe(true);

    const payload = await decodePayload(row.signedJwt);
    expect(payload.sub).toBe(statusListUrl(listId)); // URL binding (defense 1)
    expect(payload.statusListVersion).toBe(1);
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

    const result = await publishList(listId, { issuer });
    expect(result.published).toBe(true);
    expect(result.changed).toBe(false); // heartbeat, no revocation
    expect(store.lists[0]!.version).toBe(6);
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
  });
});
