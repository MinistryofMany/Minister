import { randomBytes } from "node:crypto";

import type { IssuedBadge } from "@minister/plugin-sdk";
import { ACCOUNT_AGE_MONTHS, type WalletChain } from "@minister/shared";
import { verify as btcVerify } from "bitcoinjs-message";
import { verifyMessage } from "viem";

import { highestBucket, monthsBetween } from "../oauth-common";

// Pure, mostly network-free helpers for the wallet-ownership flow, kept out of
// index.ts so address validation, challenge-message building, signature
// verification, and badge derivation are unit-testable without a wizard.
//
// The address is the Sybil anchor: it is validated STRICTLY here (it is later
// interpolated into a fixed-host chain-explorer URL, so it must be
// injection-proof — no slashes, whitespace, CRLF, or query characters), then
// nullified and discarded by the wizard runtime. It never enters a claim.

// Strict Ethereum address: 0x + exactly 40 hex chars. This IS the injection
// guard for the explorer URL — nothing but 0x-hex can pass.
const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/u;

// Base58 mainnet address: P2PKH (leading 1) or P2SH (leading 3). Base58 excludes
// 0, O, I, and l, so this admits no URL-hostile character.
const BTC_BASE58_RE = /^[13][1-9A-HJ-NP-Za-km-z]{25,39}$/u;
// Bech32 / bech32m native segwit mainnet (bc1...). Charset is lowercase
// alphanumeric only — again nothing URL-hostile.
const BTC_BECH32_RE = /^bc1[02-9ac-hj-np-z]{8,87}$/u;

// A standard 65-byte EOA ECDSA signature: 0x + 130 hex chars. Smart-contract
// (EIP-1271) signatures are out of v1 scope — verifying them needs an RPC
// client, which we deliberately do not have (no arbitrary outbound calls).
const ETH_SIGNATURE_RE = /^0x[0-9a-fA-F]{130}$/u;

// Validate + normalize an address for the given chain. Returns the normalized
// form (the Sybil anchor and the exact string signed + queried) or null when the
// address is malformed. ETH is lowercased (case-insensitive hex); BTC base58 is
// case-SENSITIVE (its checksum depends on case) so it is preserved verbatim,
// bech32 is already lowercase.
export function normalizeWalletAddress(chain: WalletChain, raw: string): string | null {
  const addr = raw.trim();
  if (chain === "ethereum") {
    return ETH_ADDRESS_RE.test(addr) ? addr.toLowerCase() : null;
  }
  // bitcoin
  if (BTC_BASE58_RE.test(addr)) return addr;
  if (BTC_BECH32_RE.test(addr)) return addr;
  return null;
}

// A single-use, session-bound challenge: a human statement, the ministry.id
// domain, the normalized address, a 128-bit nonce, and an expiry. The exact
// string is stored server-side and is what the signature is verified against, so
// what the user signs is exactly what we check.
export interface WalletChallenge {
  message: string;
  nonce: string;
  expiresAt: string; // ISO 8601
}

const CHALLENGE_TTL_MS = 15 * 60_000;

export function buildWalletChallenge(
  chain: WalletChain,
  normalizedAddress: string,
  now: Date = new Date(),
): WalletChallenge {
  const nonce = randomBytes(16).toString("hex"); // 128 bits
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + CHALLENGE_TTL_MS).toISOString();
  const chainLabel = chain === "ethereum" ? "Ethereum" : "Bitcoin";
  const message = [
    `ministry.id wants you to prove you control this ${chainLabel} wallet.`,
    ``,
    `Address: ${normalizedAddress}`,
    `Nonce: ${nonce}`,
    `Issued at: ${issuedAt}`,
    `Expires at: ${expiresAt}`,
    ``,
    `Signing this message proves you hold the wallet's key. It grants no permissions, moves no funds, and costs no gas.`,
  ].join("\n");
  return { message, nonce, expiresAt };
}

export function isChallengeExpired(expiresAt: string, now: Date = new Date()): boolean {
  const t = Date.parse(expiresAt);
  return !Number.isFinite(t) || now.getTime() > t;
}

// Verify an Ethereum EIP-191 / personal_sign signature: recover the signer and
// require it to equal the claimed address. Never throws — a malformed signature
// is a failed proof, not a server error.
export async function verifyEthereumSignature(
  normalizedAddress: string,
  message: string,
  signature: string,
): Promise<boolean> {
  const sig = signature.trim();
  if (!ETH_SIGNATURE_RE.test(sig)) return false;
  if (!ETH_ADDRESS_RE.test(normalizedAddress)) return false;
  try {
    return await verifyMessage({
      address: normalizedAddress as `0x${string}`,
      message,
      signature: sig as `0x${string}`,
    });
  } catch {
    return false;
  }
}

// Verify a Bitcoin BIP-137 signed message. bitcoinjs-message.verify recovers the
// pubkey and derives the address; a tampered signature THROWS ("couldn't recover
// public key"), a wrong key returns false. We also retry with checkSegwitAlways
// for signatures produced by segwit-address wallets (Electrum/Sparrow), which
// reuse the legacy header byte. Never throws.
export function verifyBitcoinSignature(
  address: string,
  message: string,
  signature: string,
): boolean {
  const sig = signature.trim();
  // Cheap injection/DoS guard: a real base64 BIP-137 signature is ~88 chars.
  if (sig.length === 0 || sig.length > 200) return false;
  return tryBtcVerify(address, message, sig, false) || tryBtcVerify(address, message, sig, true);
}

function tryBtcVerify(
  address: string,
  message: string,
  signature: string,
  checkSegwitAlways: boolean,
): boolean {
  try {
    return btcVerify(message, address, signature, undefined, checkSegwitAlways) === true;
  } catch {
    return false;
  }
}

// Build a wallet-age badge from the wallet's first-transaction date, or null
// when the wallet is too new to clear the lowest bucket (12 months) or the date
// is unavailable. Discloses only the coarse "older than N months" lower bound.
export function walletAgeBadge(
  chain: WalletChain,
  firstTx: Date | null,
  anchor: string,
  now: Date = new Date(),
): IssuedBadge | null {
  if (!firstTx) return null;
  const bucket = highestBucket(monthsBetween(firstTx, now), ACCOUNT_AGE_MONTHS);
  if (bucket === null) return null;
  return {
    type: "wallet-age",
    attributes: { chain, olderThanMonths: bucket },
    claims: { chain, olderThanMonths: bucket },
    sybilAnchor: anchor,
  };
}
