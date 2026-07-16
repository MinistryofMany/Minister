import { describe, it, expect } from "vitest";
import { createDecipheriv } from "node:crypto";
import {
  PER_APP_SECRET_BYTES,
  PRF_OUTPUT_BYTES,
  WRAP_IV_BYTES,
  WRAP_CIPHERTEXT_BYTES,
  AnonSeedCryptoError,
  deriveAppSecret,
  deriveWrapKek,
  buildWrapAad,
  wrapSeed,
  unwrapSeed,
  createMemoryVault,
  type SeedWrapAad,
} from "./anon-seed-crypto";
import golden from "./anon-seed-golden-vectors.json";

const hex = (h: string): Uint8Array => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// FROZEN golden vectors: root = ASCII "Ministry of Many" (anon-seed-golden-vectors.json).
const GOLDEN_SEED = hex(golden.root.hex);
const L1 = golden.l1.vectors;
// Convenience aliases for the two most-referenced L1 vectors (deforum/freedink
// at epoch 1) so the wrap-KEK and memory-vault tests read cleanly.
const GOLDEN_APP_SECRETS = {
  deforum: L1["deforum:1"],
  freedink: L1["freedink:1"],
} as const;

// Spec 7.1/8.1 KEK golden: prfOutput = 0x11 * 32.
const GOLDEN_PRF = new Uint8Array(PRF_OUTPUT_BYTES).fill(0x11);
const GOLDEN_KEK = "6c9e4af7ffcf6bc5b544c0fa725cd6d08a8aa0b4dbc2fb0e1dbf120c48a5fd7f";

const AAD: SeedWrapAad = {
  userId: "user_abc123",
  credentialId: "Y3JlZC1pZA",
  wrapVersion: 1,
  enrollmentEpoch: 1,
};

describe("deriveAppSecret (L1, frozen golden vectors)", () => {
  it("reproduces every frozen L1 vector (app_id + epoch path)", async () => {
    for (const [key, expected] of Object.entries(L1)) {
      const [app, epochStr] = key.split(":");
      const secret = await deriveAppSecret(GOLDEN_SEED, app!, Number(epochStr));
      expect(toHex(secret), `L1 ${key}`).toBe(expected);
    }
  });

  it("the epoch is part of the path: same app, different epoch, unrelated secret", async () => {
    expect(L1["deforum:1"]).not.toBe(L1["deforum:2"]);
  });

  it("returns 32 bytes", async () => {
    expect((await deriveAppSecret(GOLDEN_SEED, "discreetly", 1)).length).toBe(PER_APP_SECRET_BYTES);
  });

  it("domain separation: different anonAppId yields an unrelated secret", async () => {
    const a = await deriveAppSecret(GOLDEN_SEED, "deforum", 1);
    const b = await deriveAppSecret(GOLDEN_SEED, "deforum-2", 1);
    const c = await deriveAppSecret(GOLDEN_SEED, "freedink", 1);
    expect(toHex(a)).not.toBe(toHex(b));
    expect(toHex(a)).not.toBe(toHex(c));
    expect(toHex(b)).not.toBe(toHex(c));
  });

  it("domain separation: app-secret family is distinct from the wrap-KEK family", async () => {
    // Same-ikm derivations through the two label families must not collide.
    const seed32 = new Uint8Array(32).fill(0x11);
    expect(toHex(await deriveWrapKek(seed32))).toBe(GOLDEN_KEK);
    // Not derivable from any app label: KEK uses different salt+info entirely.
    const asApp = await deriveAppSecret(GOLDEN_SEED, "deforum", 1);
    expect(toHex(asApp)).not.toBe(GOLDEN_KEK);
  });

  it("rejects a seed that is not 16 bytes", async () => {
    await expect(deriveAppSecret(new Uint8Array(15), "deforum", 1)).rejects.toThrow(
      AnonSeedCryptoError,
    );
    await expect(deriveAppSecret(new Uint8Array(32), "deforum", 1)).rejects.toThrow(
      AnonSeedCryptoError,
    );
  });

  it.each(["ab", "UPPER", "has space", "has:colon", "x".repeat(33), ""])(
    "rejects invalid anonAppId %j",
    async (bad) => {
      await expect(deriveAppSecret(GOLDEN_SEED, bad, 1)).rejects.toThrow(AnonSeedCryptoError);
    },
  );

  it.each([0, -1, 1.5, Number.NaN])("rejects a non-positive/non-integer epoch %j", async (bad) => {
    await expect(deriveAppSecret(GOLDEN_SEED, "deforum", bad)).rejects.toThrow(AnonSeedCryptoError);
  });
});

describe("deriveWrapKek (spec 7.1)", () => {
  it("matches the KEK golden vector", async () => {
    expect(toHex(await deriveWrapKek(GOLDEN_PRF))).toBe(GOLDEN_KEK);
  });

  it("rejects a PRF output that is not 32 bytes", async () => {
    await expect(deriveWrapKek(new Uint8Array(16))).rejects.toThrow(AnonSeedCryptoError);
  });
});

describe("buildWrapAad (spec 7.1, I12)", () => {
  it("produces the exact spec byte string", () => {
    expect(new TextDecoder().decode(buildWrapAad(AAD))).toBe(
      "minister/anon-seed/blob/v1:user_abc123:Y3JlZC1pZA:1:1",
    );
  });

  it("rejects field values containing the separator", () => {
    expect(() => buildWrapAad({ ...AAD, userId: "a:b" })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, credentialId: "a:b" })).toThrow(AnonSeedCryptoError);
  });

  it("rejects empty string fields and non-positive or non-integer counters", () => {
    expect(() => buildWrapAad({ ...AAD, userId: "" })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, credentialId: "" })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, wrapVersion: 0 })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, wrapVersion: 1.5 })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, enrollmentEpoch: -1 })).toThrow(AnonSeedCryptoError);
    expect(() => buildWrapAad({ ...AAD, enrollmentEpoch: Number.NaN })).toThrow(
      AnonSeedCryptoError,
    );
  });
});

describe("wrapSeed / unwrapSeed (spec 7.1)", () => {
  it("round-trips and emits spec-exact sizes", async () => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    expect(blob.ciphertext.length).toBe(WRAP_CIPHERTEXT_BYTES);
    expect(blob.iv.length).toBe(WRAP_IV_BYTES);
    expect(toHex(await unwrapSeed(blob, GOLDEN_PRF, AAD))).toBe(toHex(GOLDEN_SEED));
  });

  it("round-trips a random seed", async () => {
    const seed = crypto.getRandomValues(new Uint8Array(16));
    const prf = crypto.getRandomValues(new Uint8Array(32));
    const blob = await wrapSeed(seed, prf, AAD);
    expect(toHex(await unwrapSeed(blob, prf, AAD))).toBe(toHex(seed));
  });

  it("uses a fresh IV per wrap (same inputs never repeat a blob)", async () => {
    const a = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    const b = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    expect(toHex(a.iv)).not.toBe(toHex(b.iv));
    expect(toHex(a.ciphertext)).not.toBe(toHex(b.ciphertext));
  });

  it("interop: node:crypto decrypts the blob under the golden KEK and spec AAD", async () => {
    // Independent implementation check: proves the wrap is real AES-256-GCM
    // keyed by the spec KEK derivation with the spec AAD bytes, not merely
    // self-consistent WebCrypto.
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    const d = createDecipheriv("aes-256-gcm", hex(GOLDEN_KEK), blob.iv);
    d.setAAD(Buffer.from("minister/anon-seed/blob/v1:user_abc123:Y3JlZC1pZA:1:1"));
    d.setAuthTag(blob.ciphertext.subarray(16));
    const plain = Buffer.concat([d.update(blob.ciphertext.subarray(0, 16)), d.final()]);
    expect(plain.toString("hex")).toBe(toHex(GOLDEN_SEED));
  });

  it("fails closed on a wrong PRF output", async () => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    const wrongPrf = new Uint8Array(PRF_OUTPUT_BYTES).fill(0x22);
    await expect(unwrapSeed(blob, wrongPrf, AAD)).rejects.toThrow(AnonSeedCryptoError);
  });

  it.each([
    ["userId", { userId: "user_other" }],
    ["credentialId", { credentialId: "b3RoZXItY3JlZA" }],
    ["wrapVersion", { wrapVersion: 2 }],
    ["enrollmentEpoch", { enrollmentEpoch: 2 }],
  ] as const)("fails closed on AAD mismatch: %s", async (_field, patch) => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    await expect(unwrapSeed(blob, GOLDEN_PRF, { ...AAD, ...patch })).rejects.toThrow(
      AnonSeedCryptoError,
    );
  });

  it("anti-rollback (I12): an epoch-1 blob fails authentication after a reset to epoch 2", async () => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, { ...AAD, enrollmentEpoch: 1 });
    await expect(unwrapSeed(blob, GOLDEN_PRF, { ...AAD, enrollmentEpoch: 2 })).rejects.toThrow(
      /authentication failed/,
    );
  });

  it("fails closed on ciphertext, tag, or IV tamper (every bit position of the tag byte)", async () => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    for (const index of [0, 15, 16, 31]) {
      // 0/15 = ciphertext bytes, 16/31 = tag bytes
      const tampered = { iv: blob.iv, ciphertext: Uint8Array.from(blob.ciphertext) };
      tampered.ciphertext[index]! ^= 0x01;
      await expect(unwrapSeed(tampered, GOLDEN_PRF, AAD)).rejects.toThrow(AnonSeedCryptoError);
    }
    const badIv = { ciphertext: blob.ciphertext, iv: Uint8Array.from(blob.iv) };
    badIv.iv[0]! ^= 0x01;
    await expect(unwrapSeed(badIv, GOLDEN_PRF, AAD)).rejects.toThrow(AnonSeedCryptoError);
  });

  it("rejects malformed blob shapes before touching the KEK", async () => {
    const blob = await wrapSeed(GOLDEN_SEED, GOLDEN_PRF, AAD);
    await expect(
      unwrapSeed({ ciphertext: blob.ciphertext, iv: new Uint8Array(11) }, GOLDEN_PRF, AAD),
    ).rejects.toThrow(/12 bytes/);
    await expect(
      unwrapSeed({ ciphertext: new Uint8Array(31), iv: blob.iv }, GOLDEN_PRF, AAD),
    ).rejects.toThrow(/32 bytes/);
  });

  it("rejects a wrong-size seed or PRF output at wrap time", async () => {
    await expect(wrapSeed(new Uint8Array(17), GOLDEN_PRF, AAD)).rejects.toThrow(
      AnonSeedCryptoError,
    );
    await expect(wrapSeed(GOLDEN_SEED, new Uint8Array(31), AAD)).rejects.toThrow(
      AnonSeedCryptoError,
    );
  });
});

describe("createMemoryVault (spec 7.3/7.5 seam)", () => {
  it("refuses to derive while locked", async () => {
    const vault = createMemoryVault();
    expect(vault.isUnlocked()).toBe(false);
    await expect(vault.deriveAppSecret("deforum", 1)).rejects.toThrow(/locked/);
  });

  it("derives the same per-app secret as the pure function once unlocked", async () => {
    const vault = createMemoryVault();
    vault.unlock(GOLDEN_SEED);
    expect(vault.isUnlocked()).toBe(true);
    expect(toHex(await vault.deriveAppSecret("deforum", 1))).toBe(GOLDEN_APP_SECRETS.deforum);
  });

  it("copies the seed on unlock (later caller mutation cannot corrupt derivation)", async () => {
    const vault = createMemoryVault();
    const mine = Uint8Array.from(GOLDEN_SEED);
    vault.unlock(mine);
    mine.fill(0xff);
    expect(toHex(await vault.deriveAppSecret("freedink", 1))).toBe(GOLDEN_APP_SECRETS.freedink);
  });

  it("lock() drops the seed and derivation refuses again", async () => {
    const vault = createMemoryVault();
    vault.unlock(GOLDEN_SEED);
    vault.lock();
    expect(vault.isUnlocked()).toBe(false);
    await expect(vault.deriveAppSecret("deforum", 1)).rejects.toThrow(/locked/);
  });

  it("rejects unlocking with a wrong-size seed", () => {
    const vault = createMemoryVault();
    expect(() => vault.unlock(new Uint8Array(15))).toThrow(AnonSeedCryptoError);
    expect(vault.isUnlocked()).toBe(false);
  });
});
