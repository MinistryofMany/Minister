import { describe, expect, it } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { sign as btcSign } from "bitcoinjs-message";

import {
  buildWalletChallenge,
  isChallengeExpired,
  normalizeWalletAddress,
  verifyBitcoinSignature,
  verifyEthereumSignature,
  walletAgeBadge,
} from "./verify";

// Throwaway Anvil test key (well-known, never funded).
const ETH_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ethAccount = privateKeyToAccount(ETH_PK);

// Canonical bitcoinjs-message test key. Raw 32-byte key decoded from WIF
// L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1; compressed P2PKH address.
const BTC_PRIVKEY = Buffer.from(
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hex",
);
const BTC_ADDRESS = "1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV";

function signBtc(message: string): string {
  return btcSign(message, BTC_PRIVKEY, true).toString("base64");
}

describe("normalizeWalletAddress", () => {
  it("accepts and lowercases a valid Ethereum address", () => {
    expect(normalizeWalletAddress("ethereum", "0x70997970C51812dc3A010C7d01b50e0d17dc79C8")).toBe(
      "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
    );
  });

  it("trims surrounding whitespace before validating", () => {
    expect(normalizeWalletAddress("ethereum", "  0x" + "a".repeat(40) + "  ")).toBe(
      "0x" + "a".repeat(40),
    );
  });

  it("rejects malformed Ethereum addresses", () => {
    expect(normalizeWalletAddress("ethereum", "0x123")).toBeNull();
    expect(
      normalizeWalletAddress("ethereum", "70997970c51812dc3a010c7d01b50e0d17dc79c8"),
    ).toBeNull();
    expect(normalizeWalletAddress("ethereum", "0x" + "g".repeat(40))).toBeNull();
  });

  it("rejects injection payloads in the address slot", () => {
    // The address is later interpolated into an explorer URL path; anything with
    // a slash, CRLF, or query character must be refused outright.
    for (const bad of [
      "0x" + "a".repeat(40) + "/../etc",
      "0x" + "a".repeat(40) + "?x=1",
      "0x" + "a".repeat(40) + "\r\nHost: evil",
      "0x" + "a".repeat(40) + " ",
    ]) {
      // trailing space is trimmed, so that one normalizes; the rest are rejected.
      const out = normalizeWalletAddress("ethereum", bad);
      if (out !== null) expect(out).toBe("0x" + "a".repeat(40));
      else expect(out).toBeNull();
    }
    expect(normalizeWalletAddress("bitcoin", "1F3sAm6/..")).toBeNull();
    expect(normalizeWalletAddress("bitcoin", "bc1q?evil")).toBeNull();
  });

  it("accepts P2PKH, P2SH, and bech32 mainnet Bitcoin addresses", () => {
    expect(normalizeWalletAddress("bitcoin", BTC_ADDRESS)).toBe(BTC_ADDRESS);
    expect(normalizeWalletAddress("bitcoin", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")).toBe(
      "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
    );
    expect(normalizeWalletAddress("bitcoin", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")).toBe(
      "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
    );
  });

  it("rejects testnet and malformed Bitcoin addresses", () => {
    expect(
      normalizeWalletAddress("bitcoin", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
    ).toBeNull();
    expect(normalizeWalletAddress("bitcoin", "0x" + "a".repeat(40))).toBeNull();
    expect(normalizeWalletAddress("bitcoin", "notanaddress")).toBeNull();
  });
});

describe("buildWalletChallenge", () => {
  it("embeds the domain, address, a 128-bit nonce, and an expiry", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const c = buildWalletChallenge("ethereum", "0x" + "a".repeat(40), now);
    expect(c.message).toContain("ministry.id");
    expect(c.message).toContain("Ethereum");
    expect(c.message).toContain("0x" + "a".repeat(40));
    expect(c.nonce).toMatch(/^[0-9a-f]{32}$/u);
    expect(c.message).toContain(c.nonce);
    // 15-minute TTL from `now`.
    expect(c.expiresAt).toBe("2026-01-01T00:15:00.000Z");
  });

  it("produces a fresh nonce each call", () => {
    const a = buildWalletChallenge("bitcoin", BTC_ADDRESS);
    const b = buildWalletChallenge("bitcoin", BTC_ADDRESS);
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("isChallengeExpired", () => {
  it("is false before expiry and true after", () => {
    const now = new Date("2026-01-01T00:10:00.000Z");
    expect(isChallengeExpired("2026-01-01T00:15:00.000Z", now)).toBe(false);
    expect(isChallengeExpired("2026-01-01T00:05:00.000Z", now)).toBe(true);
  });

  it("treats an unparseable expiry as expired (fail closed)", () => {
    expect(isChallengeExpired("not-a-date")).toBe(true);
  });
});

describe("verifyEthereumSignature", () => {
  const message =
    "ministry.id wants you to prove you control this Ethereum wallet.\nNonce: deadbeef";

  it("verifies a genuine EIP-191 signature (recovers the signer)", async () => {
    const sig = await ethAccount.signMessage({ message });
    expect(await verifyEthereumSignature(ethAccount.address.toLowerCase(), message, sig)).toBe(
      true,
    );
  });

  it("rejects a tampered signature", async () => {
    const sig = await ethAccount.signMessage({ message });
    const tampered = sig.slice(0, -4) + (sig.endsWith("0000") ? "1111" : "0000");
    expect(await verifyEthereumSignature(ethAccount.address.toLowerCase(), message, tampered)).toBe(
      false,
    );
  });

  it("rejects a signature over a different message", async () => {
    const sig = await ethAccount.signMessage({ message });
    expect(await verifyEthereumSignature(ethAccount.address.toLowerCase(), "other", sig)).toBe(
      false,
    );
  });

  it("rejects a signature from a different address", async () => {
    const sig = await ethAccount.signMessage({ message });
    const other = "0x" + "b".repeat(40);
    expect(await verifyEthereumSignature(other, message, sig)).toBe(false);
  });

  it("rejects malformed signatures without throwing", async () => {
    expect(await verifyEthereumSignature(ethAccount.address.toLowerCase(), message, "0xdead")).toBe(
      false,
    );
    expect(
      await verifyEthereumSignature(ethAccount.address.toLowerCase(), message, "garbage"),
    ).toBe(false);
  });
});

describe("verifyBitcoinSignature (BIP-137)", () => {
  it("verifies a genuine BIP-137 signature", () => {
    const message = "ministry.id challenge\nNonce: cafebabe";
    const sig = signBtc(message);
    expect(verifyBitcoinSignature(BTC_ADDRESS, message, sig)).toBe(true);
  });

  it("rejects a tampered signature without throwing", () => {
    const message = "ministry.id challenge\nNonce: cafebabe";
    const sig = signBtc(message);
    const tampered = sig.slice(0, 10) + (sig[10] === "A" ? "B" : "A") + sig.slice(11);
    expect(verifyBitcoinSignature(BTC_ADDRESS, message, tampered)).toBe(false);
  });

  it("rejects a signature over a different message", () => {
    const sig = signBtc("the signed message");
    expect(verifyBitcoinSignature(BTC_ADDRESS, "a different message", sig)).toBe(false);
  });

  it("rejects a signature for a different address", () => {
    const message = "ministry.id challenge";
    const sig = signBtc(message);
    expect(verifyBitcoinSignature("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", message, sig)).toBe(false);
  });

  it("rejects empty or over-long input without throwing", () => {
    expect(verifyBitcoinSignature(BTC_ADDRESS, "m", "")).toBe(false);
    expect(verifyBitcoinSignature(BTC_ADDRESS, "m", "A".repeat(300))).toBe(false);
  });
});

describe("walletAgeBadge", () => {
  const now = new Date("2026-01-01T00:00:00.000Z");
  const anchor = "0x" + "a".repeat(40);

  it("returns null when the first-tx date is unavailable", () => {
    expect(walletAgeBadge("ethereum", null, anchor, now)).toBeNull();
  });

  it("returns null when the wallet is younger than the lowest bucket", () => {
    // 6 months old — below the 12-month floor.
    expect(
      walletAgeBadge("ethereum", new Date("2025-07-01T00:00:00.000Z"), anchor, now),
    ).toBeNull();
  });

  it("buckets to the highest threshold the wallet clears", () => {
    // ~4 years old → 36-month bucket (the [12,24,36,60] set; not yet 60).
    const badge = walletAgeBadge("bitcoin", new Date("2022-01-01T00:00:00.000Z"), anchor, now);
    expect(badge).not.toBeNull();
    expect(badge?.type).toBe("wallet-age");
    expect(badge?.claims).toEqual({ chain: "bitcoin", olderThanMonths: 36 });
    expect(badge?.attributes).toEqual({ chain: "bitcoin", olderThanMonths: 36 });
    // Anchored, address never in the claim.
    expect(badge?.sybilAnchor).toBe(anchor);
    expect(JSON.stringify(badge?.claims)).not.toContain(anchor);
  });

  it("reaches the 60-month bucket for a >5-year-old wallet", () => {
    const badge = walletAgeBadge("ethereum", new Date("2019-01-01T00:00:00.000Z"), anchor, now);
    expect(badge?.claims).toEqual({ chain: "ethereum", olderThanMonths: 60 });
  });
});
