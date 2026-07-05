import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { afterAll, describe, expect, it } from "vitest";

import { buildVoprfDedupInput } from "./encoding";
import { createSignetBackend, withSignetEntryLock } from "./signet-backend";

// LIVE cross-language fixture suite — the Minister half of the "both CIs"
// interop commitment (build plan §2.1 golden vectors, Phase 3 item 3).
//
// Runs ONLY when MINISTER_SIGNET_FIXTURE=1 with a REAL Signet (sealed with
// the frozen test master seed — signet-e2e/README.md) reachable over mTLS at
// MINISTER_SIGNET_URL, plus a reachable DATABASE_URL with the schema pushed
// (the release-race regression writes real User/Badge rows to exercise the
// real pg advisory lock). `pnpm test` skips it silently otherwise.
//
// What it proves that the offline suite cannot: Minister's pinned client
// stack (@cloudflare/voprf-ts + noble, from THIS lockfile) byte-agrees with
// the Rust `voprf` crate over the real HTTP+mTLS wire — blind → evaluate →
// DLEQ verify → finalize → register → disclose — on the FROZEN ecosystem
// vectors committed to both repos.

const LIVE = process.env.MINISTER_SIGNET_FIXTURE === "1";

interface Vectors {
  master_seed_hex: string;
  public_key_b64url: string;
  dedup: { sybil_id: string; badge_type: string; input_hex: string; n_dedup_hex: string };
  disclose: { client_id: string; n_rp: string };
}

const vectors = JSON.parse(
  readFileSync(path.join(__dirname, "prf-vectors.json"), "utf8"),
) as Vectors;

// Deterministic owner handles: reruns against a persistent fixture ledger
// take the already_yours/taken paths instead of failing.
const OWNER_A = "fixture-owner-A";
const OWNER_B = "fixture-owner-B";

function liveConfig(pin?: string) {
  const need = (key: string): string => {
    const v = process.env[key];
    if (!v) throw new Error(`${key} must be set for the live fixture suite`);
    return v;
  };
  // createSignetBackend takes RESOLVED PEM strings on an explicit config;
  // the env may carry file paths (the compose stack does).
  const pem = (v: string): string =>
    v.trim().startsWith("-----BEGIN") ? v : readFileSync(v.trim(), "utf8");
  return {
    baseUrl: need("MINISTER_SIGNET_URL"),
    clientCert: pem(need("MINISTER_SIGNET_CLIENT_CERT")),
    clientKey: pem(need("MINISTER_SIGNET_CLIENT_KEY")),
    caCert: pem(need("MINISTER_SIGNET_CA_CERT")),
    pinnedPublicKey: pin ?? need("MINISTER_SIGNET_DEDUP_PUBKEY"),
  };
}

const cleanupUserIds: string[] = [];

afterAll(async () => {
  if (!LIVE || cleanupUserIds.length === 0) return;
  const { prisma } = await import("@/lib/prisma");
  await prisma.badge.deleteMany({ where: { userId: { in: cleanupUserIds } } });
  await prisma.user.deleteMany({ where: { id: { in: cleanupUserIds } } });
  await prisma.$disconnect();
});

describe.skipIf(!LIVE)("signet live fixtures (frozen ecosystem vectors over real mTLS)", () => {
  it("pins the served public key to the frozen pkS", () => {
    // The env pin the compose stack wires IS the frozen vector value; the
    // backend fetch-verifies it against GET /prf/public-key on first use.
    expect(process.env.MINISTER_SIGNET_DEDUP_PUBKEY).toBe(vectors.public_key_b64url);
  });

  it("TS blind → Rust evaluate → TS DLEQ verify + finalize reproduces the frozen N_dedup", async () => {
    const backend = createSignetBackend(liveConfig());
    expect(
      buildVoprfDedupInput(vectors.dedup.sybil_id, vectors.dedup.badge_type).toString("hex"),
    ).toBe(vectors.dedup.input_hex);
    const nDedup = await backend.evaluateDedupValue(
      vectors.dedup.sybil_id,
      vectors.dedup.badge_type,
    );
    expect(Buffer.from(nDedup).toString("hex")).toBe(vectors.dedup.n_dedup_hex);
  });

  it("register → disclose reproduces the frozen N_rp; second owner is taken; probe is owner-checked", async () => {
    const backend = createSignetBackend(liveConfig());
    const reg = await backend.registerDedup({
      anchor: vectors.dedup.sybil_id,
      badgeType: vectors.dedup.badge_type,
      ownerHandle: OWNER_A,
    });
    // Rerun-tolerant: first run registers, later runs are already_yours.
    expect(["registered", "already_yours"]).toContain(reg.status);
    if (reg.status === "taken") throw new Error("unreachable");

    const nRp = await backend.disclose({
      entryRef: reg.entryRef,
      ownerHandle: OWNER_A,
      clientId: vectors.disclose.client_id,
    });
    expect(nRp).toBe(vectors.disclose.n_rp);

    const other = await backend.registerDedup({
      anchor: vectors.dedup.sybil_id,
      badgeType: vectors.dedup.badge_type,
      ownerHandle: OWNER_B,
    });
    expect(other).toEqual({ status: "taken" });

    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: OWNER_A }),
    ).resolves.toBe(true);
    await expect(
      backend.entryExistsForOwner({ entryRef: reg.entryRef, ownerHandle: OWNER_B }),
    ).resolves.toBe(false);
    await expect(
      backend.disclose({ entryRef: reg.entryRef, ownerHandle: OWNER_B, clientId: "mc_x" }),
    ).rejects.toThrow(/owner mismatch/);
  });

  it("a mismatched pin refuses to evaluate, fail closed", async () => {
    const pin = process.env.MINISTER_SIGNET_DEDUP_PUBKEY ?? "";
    const tampered = pin.slice(0, -1) + (pin.endsWith("A") ? "B" : "A");
    const backend = createSignetBackend(liveConfig(tampered));
    await expect(
      backend.registerDedup({ anchor: "gh:pin", badgeType: "oauth-account", ownerHandle: "x" }),
    ).rejects.toThrow(/does not match the pinned/);
  });

  it("release race regression (Case A) holds against the REAL advisory lock and REAL Signet", async () => {
    const backend = createSignetBackend(liveConfig());
    const { prisma } = await import("@/lib/prisma");

    // A real user + badge row so the sibling check has something to see.
    const anchor = `fixture:${randomBytes(8).toString("hex")}`;
    const user = await prisma.user.create({ data: { dedupHandle: null } });
    cleanupUserIds.push(user.id);

    const reg = await backend.registerDedup({
      anchor,
      badgeType: "oauth-account",
      ownerHandle: OWNER_A,
    });
    if (reg.status === "taken") throw new Error("setup: fresh anchor was taken");
    const ref = reg.entryRef;
    await prisma.badge.create({
      data: {
        userId: user.id,
        type: "oauth-account",
        attributes: {},
        vcJwt: "fixture",
        issuer: "did:web:fixture.test",
        nullifierRef: ref,
      },
    });

    // Mint window holds the pg advisory lock across [INSERT → probe]; the
    // concurrent release blocks on it, then sees the badge and no-ops.
    let release: Promise<void> | null = null;
    let releaseSettledDuringWindow = false;
    await withSignetEntryLock(ref, async () => {
      release = backend.release({ entryRef: ref, ownerHandle: OWNER_A }).then(() => {
        releaseSettledDuringWindow = true;
      });
      for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
      await expect(
        backend.entryExistsForOwner({ entryRef: ref, ownerHandle: OWNER_A }),
      ).resolves.toBe(true);
    });
    expect(releaseSettledDuringWindow).toBe(false);
    await release;
    // The entry survived the blocked release (the badge references it).
    await expect(
      backend.entryExistsForOwner({ entryRef: ref, ownerHandle: OWNER_A }),
    ).resolves.toBe(true);

    // Delete the badge → the release now frees the entry; re-register works.
    await prisma.badge.deleteMany({ where: { nullifierRef: ref } });
    await backend.release({ entryRef: ref, ownerHandle: OWNER_A });
    await expect(
      backend.entryExistsForOwner({ entryRef: ref, ownerHandle: OWNER_A }),
    ).resolves.toBe(false);
    const reReg = await backend.registerDedup({
      anchor,
      badgeType: "oauth-account",
      ownerHandle: OWNER_B,
    });
    expect(reReg.status).toBe("registered");
    if (reReg.status !== "taken") {
      // Leave the fixture ledger tidy for reruns.
      await backend.release({ entryRef: reReg.entryRef, ownerHandle: OWNER_B });
    }
  });
});
