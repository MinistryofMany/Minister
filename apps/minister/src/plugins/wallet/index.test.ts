import { beforeEach, describe, expect, it, vi } from "vitest";
import { privateKeyToAccount } from "viem/accounts";
import { sign as btcSign } from "bitcoinjs-message";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

// Mock the two network/data seams so the flow is fully offline and deterministic.
vi.mock("./chain-age", () => ({ fetchWalletFirstTxDate: vi.fn() }));
vi.mock("./events", () => ({ ethOnchainEventsFor: vi.fn(() => []) }));

import { fetchWalletFirstTxDate } from "./chain-age";
import { ethOnchainEventsFor } from "./events";
import { walletPlugin } from "./index";

const mockAge = vi.mocked(fetchWalletFirstTxDate);
const mockEvents = vi.mocked(ethOnchainEventsFor);

const ETH_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ethAccount = privateKeyToAccount(ETH_PK);

const BTC_PRIVKEY = Buffer.from(
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "hex",
);
const BTC_ADDRESS = "1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV";

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

// Drive the wizard from start through the sign step to the verify (paste) step,
// returning the verify-step state plus the exact challenge message and the
// normalized (anchored) address stashed server-side.
async function toVerify(
  chain: string,
  address: string,
  c: PluginContext,
): Promise<{ state: WizardState; message: string; anchor: string }> {
  const start = await walletPlugin.startWizard(c);
  const form = await walletPlugin.handleStep(start, { chain, address }, c);
  if (form.kind !== "continue") throw new Error("expected continue after form");
  expect(form.state.currentStep.kind).toBe("info");
  const sign = await walletPlugin.handleStep(form.state, {}, c);
  if (sign.kind !== "continue") throw new Error("expected continue after sign");
  expect(sign.state.currentStep.kind).toBe("form");
  return {
    state: sign.state,
    message: String(sign.state.data.message),
    anchor: String(sign.state.data.address),
  };
}

beforeEach(() => {
  mockAge.mockResolvedValue(null);
  mockEvents.mockReturnValue([]);
});

describe("walletPlugin form step", () => {
  it("rejects an unknown chain", async () => {
    const start = await walletPlugin.startWizard(ctx());
    const r = await walletPlugin.handleStep(start, { chain: "dogecoin", address: "x" }, ctx());
    expect(r.kind).toBe("error");
  });

  it("rejects a malformed address", async () => {
    const start = await walletPlugin.startWizard(ctx());
    const r = await walletPlugin.handleStep(start, { chain: "ethereum", address: "0x123" }, ctx());
    expect(r.kind).toBe("error");
  });

  it("advances to a sign step and carries the challenge server-side only", async () => {
    const c = ctx();
    const start = await walletPlugin.startWizard(c);
    const r = await walletPlugin.handleStep(
      start,
      { chain: "ethereum", address: ethAccount.address },
      c,
    );
    if (r.kind !== "continue") throw new Error("kind");
    if (r.state.currentStep.kind !== "info") throw new Error("kind");
    // Message shown in the info body; anchor lowercased and kept in data.
    expect(r.state.data.address).toBe(ethAccount.address.toLowerCase());
    expect(r.state.currentStep.payload.body).toContain(String(r.state.data.message));
    // challenge_issued logs the chain but NEVER the address.
    const call = vi
      .mocked(c.audit.log)
      .mock.calls.find((x) => x[0] === "plugin.wallet.challenge_issued");
    expect(call?.[1]).toEqual({ chain: "ethereum" });
    expect(JSON.stringify(call?.[1])).not.toContain(ethAccount.address.toLowerCase());
  });
});

describe("walletPlugin Ethereum end-to-end", () => {
  it("issues wallet-control on a valid signature, address never in a claim", async () => {
    const c = ctx();
    const { state, message, anchor } = await toVerify("ethereum", ethAccount.address, c);
    const signature = await ethAccount.signMessage({ message });

    const r = await walletPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error(`expected complete, got ${r.kind}`);

    const control = r.badges.find((b) => b.type === "wallet-control");
    expect(control?.claims).toEqual({ chain: "ethereum" });
    // The anchor rides sybilAnchor and appears in NO claim or attribute.
    for (const b of r.badges) {
      expect(b.sybilAnchor).toBe(anchor);
      expect(b.revealsAnchor).toBeUndefined();
      expect(JSON.stringify(b.claims)).not.toContain(anchor);
      expect(JSON.stringify(b.attributes)).not.toContain(anchor);
    }
    // verified log carries the issued types, not the address.
    const call = vi.mocked(c.audit.log).mock.calls.find((x) => x[0] === "plugin.wallet.verified");
    expect(call?.[1]).toMatchObject({ chain: "ethereum", issuedTypes: ["wallet-control"] });
    expect(JSON.stringify(call?.[1])).not.toContain(anchor);
  });

  it("adds an onchain-event badge when the address is a known depositor", async () => {
    mockEvents.mockReturnValue(["eth2-genesis-depositor"]);
    const c = ctx();
    const { state, message } = await toVerify("ethereum", ethAccount.address, c);
    const signature = await ethAccount.signMessage({ message });

    const r = await walletPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error("kind");
    const event = r.badges.find((b) => b.type === "onchain-event");
    expect(event?.claims).toEqual({ event: "eth2-genesis-depositor" });
    const call = vi.mocked(c.audit.log).mock.calls.find((x) => x[0] === "plugin.wallet.verified");
    expect(call?.[1]).toMatchObject({ events: ["eth2-genesis-depositor"] });
  });

  it("adds a wallet-age badge when the explorer returns an old first-tx", async () => {
    // ~7 years old, comfortably past the 60-month top bucket.
    mockAge.mockResolvedValue(new Date(Date.now() - 7 * 365 * 24 * 3600 * 1000));
    const c = ctx();
    const { state, message } = await toVerify("ethereum", ethAccount.address, c);
    const signature = await ethAccount.signMessage({ message });

    const r = await walletPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error("kind");
    const age = r.badges.find((b) => b.type === "wallet-age");
    expect(age?.claims).toMatchObject({ chain: "ethereum", olderThanMonths: 60 });
  });

  it("still issues wallet-control when the age lookup fails (best-effort)", async () => {
    mockAge.mockRejectedValue(new Error("explorer down"));
    const c = ctx();
    const { state, message } = await toVerify("ethereum", ethAccount.address, c);
    const signature = await ethAccount.signMessage({ message });

    const r = await walletPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error("kind");
    expect(r.badges.map((b) => b.type)).toEqual(["wallet-control"]);
  });

  it("rejects a tampered signature", async () => {
    const c = ctx();
    const { state, message } = await toVerify("ethereum", ethAccount.address, c);
    const sig = await ethAccount.signMessage({ message });
    const tampered = sig.slice(0, -4) + (sig.endsWith("0000") ? "1111" : "0000");
    const r = await walletPlugin.handleStep(state, { signature: tampered }, c);
    expect(r.kind).toBe("error");
  });

  it("rejects a signature over a stale (mutated) message", async () => {
    const c = ctx();
    const { state } = await toVerify("ethereum", ethAccount.address, c);
    const sig = await ethAccount.signMessage({ message: "a message I made up" });
    const r = await walletPlugin.handleStep(state, { signature: sig }, c);
    expect(r.kind).toBe("error");
  });

  it("rejects once the challenge has expired", async () => {
    const c = ctx();
    const { state, message } = await toVerify("ethereum", ethAccount.address, c);
    const signature = await ethAccount.signMessage({ message });
    // Force expiry by rewriting the stored expiresAt into the past.
    state.data.expiresAt = new Date(Date.now() - 1000).toISOString();
    const r = await walletPlugin.handleStep(state, { signature }, c);
    expect(r.kind).toBe("error");
    if (r.kind !== "error") throw new Error("kind");
    expect(r.message).toContain("expired");
  });
});

describe("walletPlugin Bitcoin end-to-end", () => {
  it("issues wallet-control on a valid BIP-137 signature", async () => {
    const c = ctx();
    const { state, message, anchor } = await toVerify("bitcoin", BTC_ADDRESS, c);
    const signature = btcSign(message, BTC_PRIVKEY, true).toString("base64");

    const r = await walletPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error(`expected complete, got ${r.kind}`);
    const control = r.badges.find((b) => b.type === "wallet-control");
    expect(control?.claims).toEqual({ chain: "bitcoin" });
    expect(anchor).toBe(BTC_ADDRESS); // base58 preserved verbatim (case-sensitive)
    for (const b of r.badges) {
      expect(JSON.stringify(b.claims)).not.toContain(anchor);
    }
  });

  it("rejects a wrong-key signature", async () => {
    const c = ctx();
    const { state } = await toVerify("bitcoin", BTC_ADDRESS, c);
    // A valid-shape signature over a different message → recovers a different
    // address → verify returns false.
    const signature = btcSign("unrelated message", BTC_PRIVKEY, true).toString("base64");
    const r = await walletPlugin.handleStep(state, { signature }, c);
    expect(r.kind).toBe("error");
  });
});
