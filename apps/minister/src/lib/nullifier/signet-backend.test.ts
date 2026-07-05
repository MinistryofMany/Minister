import { describe, expect, it, vi } from "vitest";

// Offline unit suite for the SIGNET NullifierService backend: frozen-vector
// byte equality, DLEQ/pin fail-closed behavior, wire mapping, and the
// release-side half of the Phase 3 atomicity mechanism — all against the
// scripted in-memory Signet (signet-backend.testutil.ts), no network.

// In-memory LOCK-CLIENT stand-in (the dedicated PrismaClient the backend
// takes advisory locks on — lock-client.ts): a Badge table (for the release
// sibling check, which runs ON the lock tx) plus an advisory-lock emulation —
// $transaction hands the callback a tx whose $queryRaw acquires a REAL async
// mutex keyed by the lock string and releases it when the callback settles
// (exactly the pg_advisory_xact_lock lifetime), so the race tests exercise
// true mutual exclusion, not a stub. Liveness probes (`SELECT 1`) and the
// `SET LOCAL lock_timeout` statement are recognized and no-op — the fake tx
// never times out.
const h = vi.hoisted(() => {
  const badges: Array<{ id: string; nullifierRef: string | null }> = [];

  const locks = new Map<string, Promise<void>>();
  async function acquire(key: string): Promise<() => void> {
    // Queue behind the current holder (loop: a woken waiter may lose to a
    // faster contender and must re-check).
    for (;;) {
      const holder = locks.get(key);
      if (!holder) break;
      await holder;
    }
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    locks.set(key, held);
    return () => {
      locks.delete(key);
      release();
    };
  }

  const badgeModel = {
    count: vi.fn(async (args: { where: { nullifierRef: string } }) => {
      return badges.filter((b) => b.nullifierRef === args.where.nullifierRef).length;
    }),
  };

  const prisma = {
    badge: badgeModel,
    $transaction: vi.fn(
      async (fn: (tx: unknown) => Promise<unknown>, _opts?: Record<string, unknown>) => {
        // Array, not a nullable local: TS cannot see the closure assignment.
        const held: Array<() => void> = [];
        const tx = {
          badge: badgeModel,
          $executeRaw: async () => 0,
          $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
            if (strings.join("").includes("pg_advisory_xact_lock")) {
              held.push(await acquire(String(values[0])));
            }
            return [];
          },
        };
        try {
          return await fn(tx);
        } finally {
          for (const release of held) release();
        }
      },
    ),
  };
  return { badges, prisma, acquire };
});

vi.mock("@/lib/nullifier/lock-client", () => ({ getLockClient: () => h.prisma }));

import { readFileSync } from "node:fs";
import path from "node:path";

import { buildVoprfDedupInput } from "./encoding";
import {
  _setSignetTransportForTests,
  createSignetBackend,
  withSignetEntryLock,
  type SignetBackendConfig,
} from "./signet-backend";
import { MockSignet, deriveStage2 } from "./signet-backend.testutil";

interface Vectors {
  master_seed_hex: string;
  public_key_b64url: string;
  dedup: { sybil_id: string; badge_type: string; input_hex: string; n_dedup_hex: string };
  disclose: { client_id: string; n_rp: string };
}

const vectors = JSON.parse(
  readFileSync(path.join(__dirname, "prf-vectors.json"), "utf8"),
) as Vectors;
const MASTER_SEED = Buffer.from(vectors.master_seed_hex, "hex");

// Config for a mock-transport backend; PEM fields are inline so resolvePem
// never touches the filesystem, and no HTTPS agent is ever built.
function cfg(pin: string): SignetBackendConfig {
  return {
    baseUrl: "https://signet.test",
    clientCert: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    clientKey: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
    caCert: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    pinnedPublicKey: pin,
  };
}

async function freshMockAndBackend() {
  const mock = await MockSignet.create(MASTER_SEED);
  const backend = createSignetBackend(cfg(mock.publicKeyB64), mock.transport());
  return { mock, backend };
}

describe("signet backend — frozen ecosystem vectors (offline)", () => {
  it("stage-1 LP input encoding matches the frozen input_hex", () => {
    const input = buildVoprfDedupInput(vectors.dedup.sybil_id, vectors.dedup.badge_type);
    expect(input.toString("hex")).toBe(vectors.dedup.input_hex);
  });

  it("blind → evaluate → DLEQ verify → finalize reproduces the frozen N_dedup", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const nDedup = await backend.evaluateDedupValue(
      vectors.dedup.sybil_id,
      vectors.dedup.badge_type,
    );
    expect(Buffer.from(nDedup).toString("hex")).toBe(vectors.dedup.n_dedup_hex);
    // The pin was fetch-verified before the evaluation.
    expect(mock.requests[0]).toEqual({ method: "GET", path: "/prf/public-key" });
  });

  it("the mock's pkS derives to the frozen public key (guards the test double itself)", async () => {
    const mock = await MockSignet.create(MASTER_SEED);
    expect(mock.publicKeyB64).toBe(vectors.public_key_b64url);
  });

  it("disclose returns the frozen N_rp for the frozen client id", async () => {
    const { backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: vectors.dedup.sybil_id,
      badgeType: vectors.dedup.badge_type,
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup: unexpected taken");
    const nRp = await backend.disclose({
      entryRef: reg.entryRef,
      ownerHandle: "handle_A",
      clientId: vectors.disclose.client_id,
    });
    expect(nRp).toBe(vectors.disclose.n_rp);
    // Cross-check the Node-crypto stage-2 derivation against the same vector
    // (the identical check interop/prf.mjs step 5 runs in Signet CI).
    expect(
      deriveStage2(
        MASTER_SEED,
        Buffer.from(vectors.dedup.n_dedup_hex, "hex"),
        vectors.disclose.client_id,
      ),
    ).toBe(vectors.disclose.n_rp);
  });
});

describe("signet backend — pin + DLEQ fail closed", () => {
  it("refuses to evaluate when the served public key does not match the pin", async () => {
    const mock = await MockSignet.create(MASTER_SEED);
    // Pin a DIFFERENT (validly-shaped) key than the mock serves.
    const wrongPin = Buffer.from(
      Buffer.from(mock.publicKeyB64, "base64url").map((b, i) => (i === 3 ? b ^ 0xff : b)),
    ).toString("base64url");
    const backend = createSignetBackend(cfg(wrongPin), mock.transport());
    await expect(
      backend.registerDedup({ anchor: "gh:1", badgeType: "oauth-account", ownerHandle: "h" }),
    ).rejects.toThrow(/does not match the pinned/);
    // Fail closed BEFORE any evaluation left the building.
    expect(mock.requests.map((r) => r.path)).toEqual(["/prf/public-key"]);
  });

  it("rejects an evaluation under a different key even when the advertised pubkey lies (DLEQ)", async () => {
    // The server evaluates under seed B, but advertises the pinned key of
    // seed A — the pin CHECK passes, the DLEQ proof cannot.
    const honest = await MockSignet.create(MASTER_SEED);
    const liar = await MockSignet.create(Buffer.alloc(32, 0x11));
    liar.advertisedPublicKeyB64 = honest.publicKeyB64;
    const backend = createSignetBackend(cfg(honest.publicKeyB64), liar.transport());
    await expect(
      backend.registerDedup({ anchor: "gh:1", badgeType: "oauth-account", ownerHandle: "h" }),
    ).rejects.toThrow();
    // The poisoned value never reached the ledger.
    expect(liar.requests.map((r) => r.path)).not.toContain("/dedup/register");
  });

  it("rejects a tampered DLEQ proof (one flipped byte) before anything reaches the ledger", async () => {
    // Honest server, honest advertised key — the PROOF BYTES are corrupted in
    // transit. Pins the proof-deserialization/verification path of THIS
    // lockfile's voprf-ts stack, independent of the wrong-key case above
    // (which a future dependency bump could start failing at a different
    // layer, e.g. deserialization instead of DLEQ verification).
    const mock = await MockSignet.create(MASTER_SEED);
    const scripted = mock.transport();
    const tampering = createSignetBackend(cfg(mock.publicKeyB64), async (m, p, b) => {
      const res = await scripted(m, p, b);
      if (p === "/prf/evaluate" && res.status === 200) {
        const body = res.json as { evaluation_element: string; proof: string };
        const proof = Buffer.from(body.proof, "base64url");
        proof[7] = proof[7]! ^ 0x01;
        return {
          status: 200,
          json: { ...body, proof: proof.toString("base64url") },
        };
      }
      return res;
    });
    await expect(
      tampering.registerDedup({ anchor: "gh:1", badgeType: "oauth-account", ownerHandle: "h" }),
    ).rejects.toThrow();
    // The tampered evaluation never became a registration.
    expect(mock.requests.map((r) => r.path)).not.toContain("/dedup/register");
    expect(mock.entryCount()).toBe(0);
  });

  it("Signet-down surfaces a retryable error and registers nothing", async () => {
    const { mock, backend } = await freshMockAndBackend();
    mock.downStatus = 503;
    await expect(
      backend.registerDedup({ anchor: "gh:1", badgeType: "oauth-account", ownerHandle: "h" }),
    ).rejects.toThrow(/503/);
    expect(mock.entryCount()).toBe(0);
    // Recovery: the outage ends and the SAME call succeeds (nothing was
    // poisoned or cached from the failure).
    mock.downStatus = null;
    const reg = await backend.registerDedup({
      anchor: "gh:1",
      badgeType: "oauth-account",
      ownerHandle: "h",
    });
    expect(reg.status).toBe("registered");
  });
});

describe("signet backend — register/disclose/probe wire mapping", () => {
  it("maps registered / already_yours (same ref) / taken (409)", async () => {
    const { backend } = await freshMockAndBackend();
    const first = await backend.registerDedup({
      anchor: "gh:42",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    expect(first.status).toBe("registered");
    if (first.status === "taken") throw new Error("unreachable");

    const again = await backend.registerDedup({
      anchor: "gh:42",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    expect(again).toEqual({ status: "already_yours", entryRef: first.entryRef });

    const other = await backend.registerDedup({
      anchor: "gh:42",
      badgeType: "oauth-account",
      ownerHandle: "handle_B",
    });
    expect(other).toEqual({ status: "taken" });
  });

  it("disclose fails closed on owner mismatch and on a missing entry", async () => {
    const { backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:7",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    await expect(
      backend.disclose({ entryRef: reg.entryRef, ownerHandle: "handle_B", clientId: "mc_x" }),
    ).rejects.toThrow(/owner mismatch/);
    await expect(
      backend.disclose({
        entryRef: Buffer.from("0123456789abcdef").toString("base64url"),
        ownerHandle: "handle_A",
        clientId: "mc_x",
      }),
    ).rejects.toThrow(/not found/);
  });

  it("rejects a malformed disclosed nullifier fail-closed", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:8",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    const scripted = mock.transport();
    const tampering = createSignetBackend(cfg(mock.publicKeyB64), async (m, p, b) => {
      const res = await scripted(m, p, b);
      if (p === "/prf/disclose") return { status: 200, json: { nullifier: "mnv2:not-the-shape" } };
      return res;
    });
    await expect(
      tampering.disclose({ entryRef: reg.entryRef, ownerHandle: "handle_A", clientId: "mc_x" }),
    ).rejects.toThrow(/malformed/);
  });

  it("entryExistsForOwner: true when owned, false when gone or mis-owned, throws on 5xx", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:9",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: "handle_A" }),
    ).resolves.toBe(true);
    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: "handle_B" }),
    ).resolves.toBe(false);
    await backend.release({ entryRef: reg.entryRef, ownerHandle: "handle_A" });
    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: "handle_A" }),
    ).resolves.toBe(false);
    mock.downStatus = 503;
    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: "handle_A" }),
    ).rejects.toThrow(/503/);
  });

  it("caps anchor and badge_type before anything reaches the wire", async () => {
    const { mock, backend } = await freshMockAndBackend();
    await expect(
      backend.registerDedup({
        anchor: "x".repeat(513),
        badgeType: "oauth-account",
        ownerHandle: "h",
      }),
    ).rejects.toThrow(/too long/);
    expect(mock.requests).toHaveLength(0);
  });
});

describe("signet backend — release atomicity (Minister-side serialization)", () => {
  it("release skips the Signet delete while a Badge row references the entry", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:100",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    h.badges.push({ id: "b1", nullifierRef: reg.entryRef });

    await backend.release({ entryRef: reg.entryRef, ownerHandle: "handle_A" });
    expect(mock.hasRef(reg.entryRef)).toBe(true);
    expect(mock.requests.map((r) => r.path)).not.toContain("/dedup/release");

    // Sibling gone → the same release now frees the entry (idempotent path).
    h.badges.length = 0;
    await backend.release({ entryRef: reg.entryRef, ownerHandle: "handle_A" });
    expect(mock.hasRef(reg.entryRef)).toBe(false);
  });

  it("Case A across the split: a release blocked behind the mint window sees the committed badge and no-ops", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:200",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    const ref = reg.entryRef;

    // The mint window (wizard.ts serializeMintWindow) holds the per-ref lock
    // across [badge INSERT → probe]. While it is held, the concurrent
    // deleteBadge's release — whose one-shot sibling count back at t4 saw
    // zero — must BLOCK, and once it acquires the lock its FRESH sibling
    // check sees the committed badge: the Signet delete never fires.
    let probeSawEntry: boolean | null = null;
    let releaseFinishedBeforeMintWindowEnded = false;
    // Assigned inside the window, awaited after it — deliberately NOT
    // returned from the callback (awaiting the transaction would then also
    // await the blocked release: a self-inflicted deadlock).
    let release: Promise<void> | null = null;

    await withSignetEntryLock(ref, async () => {
      // t5: the badge INSERT commits inside the window.
      h.badges.push({ id: "b2", nullifierRef: ref });
      // Concurrent release fires NOW (t7 in the audit timeline) — it must
      // block on the lock.
      release = backend.release({ entryRef: ref, ownerHandle: "handle_A" }).then(() => {
        releaseFinishedBeforeMintWindowEnded = true;
      });
      // Yield generously: if the lock did NOT serialize, the release would
      // complete here and delete the entry before the probe.
      for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
      // t6: the mint-side probe runs inside the window.
      probeSawEntry = await backend.entryExistsForOwner({
        entryRef: ref,
        ownerHandle: "handle_A",
      });
    });
    expect(release).not.toBeNull();
    expect(releaseFinishedBeforeMintWindowEnded).toBe(false);
    await release;

    // The probe saw the entry (no self-heal needed), and the release —
    // running strictly after the window — refused to free it: B2 still
    // references a live entry. No dedup bypass.
    expect(probeSawEntry).toBe(true);
    expect(mock.hasRef(ref)).toBe(true);
    const other = await backend.registerDedup({
      anchor: "gh:200",
      badgeType: "oauth-account",
      ownerHandle: "handle_C",
    });
    expect(other).toEqual({ status: "taken" });
  });

  it("opposite ordering: a release that wins the lock frees the entry and the probe self-heal path sees it gone", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:300",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    const ref = reg.entryRef;

    // No badge row references the entry → the release (under the lock) frees it.
    await backend.release({ entryRef: ref, ownerHandle: "handle_A" });
    expect(mock.hasRef(ref)).toBe(false);

    // A mint window that runs AFTER the release probes → gone → the wizard
    // self-heals by re-registering (registered again, new ref).
    const present = await withSignetEntryLock(ref, () =>
      backend.entryExistsForOwner({ entryRef: ref, ownerHandle: "handle_A" }),
    );
    expect(present).toBe(false);
    const reReg = await backend.registerDedup({
      anchor: "gh:300",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    expect(reReg.status).toBe("registered");
  });

  it("release owner mismatch throws (fail loud for the reconcile path)", async () => {
    const { backend } = await freshMockAndBackend();
    const reg = await backend.registerDedup({
      anchor: "gh:400",
      badgeType: "oauth-account",
      ownerHandle: "handle_A",
    });
    if (reg.status === "taken") throw new Error("setup");
    await expect(
      backend.release({ entryRef: reg.entryRef, ownerHandle: "handle_B" }),
    ).rejects.toThrow(/owner mismatch/);
  });
});

describe("signet backend — reassignOwner (per-ref skip semantics)", () => {
  it("moves from-owned refs, skips missing and alien-owned refs, counts moves only", async () => {
    const { mock, backend } = await freshMockAndBackend();
    const mine = await backend.registerDedup({
      anchor: "gh:500",
      badgeType: "oauth-account",
      ownerHandle: "donor",
    });
    if (mine.status === "taken") throw new Error("setup");
    const alien = mock.seedEntry({
      value: Buffer.alloc(64, 7),
      ownerHandle: "somebody_else",
      badgeType: "oauth-account",
    });
    const alreadyMoved = mock.seedEntry({
      value: Buffer.alloc(64, 9),
      ownerHandle: "survivor",
      badgeType: "oauth-account",
    });
    const missing = Buffer.from("ffffffffffffffff").toString("base64url");

    const moved = await backend.reassignOwner({
      entryRefs: [mine.entryRef, alien, alreadyMoved, missing],
      fromOwnerHandle: "donor",
      toOwnerHandle: "survivor",
    });
    // Only the donor-owned ref moved; already-target counted as no-op; the
    // alien and missing refs were skipped (mirrors the interim per-ref
    // semantics merge/reverse-merge retries rely on).
    expect(moved).toBe(1);
  });

  it("no-ops on an empty list and on from === to", async () => {
    const { mock, backend } = await freshMockAndBackend();
    await expect(
      backend.reassignOwner({ entryRefs: [], fromOwnerHandle: "a", toOwnerHandle: "b" }),
    ).resolves.toBe(0);
    await expect(
      backend.reassignOwner({ entryRefs: ["x"], fromOwnerHandle: "a", toOwnerHandle: "a" }),
    ).resolves.toBe(0);
    expect(mock.requests).toHaveLength(0);
  });
});

describe("signet backend — test seams are dev/test-only", () => {
  it("_setSignetTransportForTests throws under NODE_ENV=production", () => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      expect(() => _setSignetTransportForTests(null)).toThrow(/disabled in production/);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
