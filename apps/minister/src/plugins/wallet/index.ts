import { z } from "zod";

import type { IssuedBadge, Plugin, WizardState } from "@minister/plugin-sdk";
import { WALLET_CHAINS, type OnchainEvent, type WalletChain } from "@minister/shared";

import { fetchWalletFirstTxDate } from "./chain-age";
import { ethOnchainEventsFor } from "./events";
import {
  buildWalletChallenge,
  isChallengeExpired,
  normalizeWalletAddress,
  verifyBitcoinSignature,
  verifyEthereumSignature,
  walletAgeBadge,
} from "./verify";

const STEP_FORM = "wallet-address";
const STEP_SIGN = "wallet-sign";
const STEP_VERIFY = "wallet-verify";

const AddressInput = z.object({
  chain: z.string().min(1),
  address: z.string().min(1),
});

const SignatureInput = z.object({
  signature: z.string().min(1),
});

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "wallet",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Prove you control a wallet",
        description:
          "Prove control of an Ethereum or Bitcoin wallet by signing a short message with it. No wallet connection, no transaction, no gas — you just paste a signature. Your address is used to check the proof and is never stored or shown on your badge.",
        fields: [
          {
            name: "chain",
            label: "Chain",
            type: "text",
            placeholder: "ethereum or bitcoin",
            helpText: "Type ethereum or bitcoin.",
            required: true,
          },
          {
            name: "address",
            label: "Wallet address",
            type: "text",
            placeholder: "0x… for Ethereum, or bc1…/1… for Bitcoin",
            required: true,
          },
        ],
        submitLabel: "Continue",
      },
    },
    data: {},
  };
}

// The sign-step body: shows the exact message to copy into the wallet's
// "sign message" tool. The message is not a secret — it must be shown so the
// user can sign it — but it is bound to this session and expires.
function signStepBody(chain: WalletChain, message: string): string {
  const where =
    chain === "ethereum"
      ? 'In your wallet (MetaMask, Rabby, a hardware wallet, etc.) open "Sign message" (personal_sign) and sign the text below exactly as shown.'
      : 'In your wallet (Electrum, Sparrow, Bitcoin Core, etc.) open "Sign message" for this address and sign the text below exactly as shown.';
  return [
    where,
    ``,
    `--- message to sign ---`,
    message,
    `--- end message ---`,
    ``,
    `Then click Continue and paste the signature your wallet gives you. The challenge expires in a few minutes; if it lapses, restart to get a fresh one.`,
  ].join("\n");
}

async function buildWalletBadges(
  chain: WalletChain,
  anchor: string,
): Promise<{ badges: IssuedBadge[]; events: OnchainEvent[] }> {
  const badges: IssuedBadge[] = [
    // Address is the Sybil anchor: it rides `sybilAnchor` (in-memory only, the
    // runtime nullifies + discards it) and appears in NO claim or attribute.
    {
      type: "wallet-control",
      attributes: { chain },
      claims: { chain },
      sybilAnchor: anchor,
    },
  ];

  // On-chain events are Ethereum-only in v1. The event LABEL is disclosed; the
  // address is not.
  const events = chain === "ethereum" ? ethOnchainEventsFor(anchor) : [];
  for (const event of events) {
    badges.push({
      type: "onchain-event",
      attributes: { event },
      claims: { event },
      sybilAnchor: anchor,
    });
  }

  // Best-effort age: a chain-explorer hiccup must never fail the whole flow, so
  // a null first-tx date just skips the age badge. fetchWalletFirstTxDate is
  // already fail-soft (returns null, never throws); the guard is belt + braces.
  let firstTx: Date | null = null;
  try {
    firstTx = await fetchWalletFirstTxDate(chain, anchor);
  } catch {
    firstTx = null;
  }
  const age = walletAgeBadge(chain, firstTx, anchor);
  if (age) badges.push(age);

  return { badges, events };
}

export const walletPlugin: Plugin = {
  manifest: {
    id: "wallet",
    name: "Crypto wallet",
    description:
      "Prove you control an Ethereum or Bitcoin wallet by signing a challenge message — no wallet connection or transaction needed. Issues a wallet-control badge, a coarse wallet-age badge when the wallet is old enough, and an on-chain event badge (e.g. eth2 genesis depositor) when it qualifies. The address is never disclosed.",
    badgeTypes: ["wallet-control", "wallet-age", "onchain-event"],
    requiresExtension: false,
    iconKey: "shield-check",
  },

  // No credentials required — always available.

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    switch (state.currentStep.id) {
      case STEP_FORM: {
        const parsed = AddressInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Enter the chain and your wallet address." };
        }
        const rawChain = parsed.data.chain.trim().toLowerCase();
        if (!(WALLET_CHAINS as readonly string[]).includes(rawChain)) {
          return { kind: "error", message: "Chain must be ethereum or bitcoin." };
        }
        const chain = rawChain as WalletChain;

        const address = normalizeWalletAddress(chain, parsed.data.address);
        if (address === null) {
          return {
            kind: "error",
            message:
              chain === "ethereum"
                ? "That is not a valid Ethereum address (expected 0x followed by 40 hex characters)."
                : "That is not a valid Bitcoin mainnet address.",
          };
        }

        const challenge = buildWalletChallenge(chain, address);

        // Do NOT log the address here — ownership is unproven at this point, so
        // recording an arbitrary address against the requester would be an
        // unverified-claim leak. Only the (non-identifying) chain is logged.
        await ctx.audit.log("plugin.wallet.challenge_issued", { chain });

        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_SIGN,
              kind: "info",
              payload: {
                title: "Sign the challenge with your wallet",
                body: signStepBody(chain, challenge.message),
                continueLabel: "I've signed it",
              },
            },
            // Carried server-side across the sign + verify steps; never returned
            // to the browser (toClientState scrubs `data`). `address` is the raw
            // Sybil anchor — the runtime scrubs it on completion and the TTL
            // sweep bounds it if the flow is abandoned.
            data: {
              chain,
              address,
              message: challenge.message,
              expiresAt: challenge.expiresAt,
            },
          },
        };
      }

      case STEP_SIGN: {
        // Info step: the only action is Continue. Re-show the message on the
        // paste step so the user can still copy it, and collect the signature.
        const message = typeof state.data.message === "string" ? state.data.message : "";
        if (!message) {
          return { kind: "error", message: "This flow lost its challenge — restart it." };
        }
        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_VERIFY,
              kind: "form",
              payload: {
                title: "Paste the signature",
                description:
                  "Paste the signature your wallet produced for the message below. We recover the signer and check it matches your address.\n\n" +
                  message,
                fields: [
                  {
                    name: "signature",
                    label: "Signature",
                    type: "text",
                    placeholder: "0x… (Ethereum) or a base64 string (Bitcoin)",
                    required: true,
                  },
                ],
                submitLabel: "Verify",
              },
            },
          },
        };
      }

      case STEP_VERIFY: {
        const chain =
          state.data.chain === "ethereum" || state.data.chain === "bitcoin"
            ? (state.data.chain as WalletChain)
            : null;
        const address = typeof state.data.address === "string" ? state.data.address : "";
        const message = typeof state.data.message === "string" ? state.data.message : "";
        const expiresAt = typeof state.data.expiresAt === "string" ? state.data.expiresAt : "";
        if (!chain || !address || !message || !expiresAt) {
          return { kind: "error", message: "This flow lost its challenge — restart it." };
        }
        if (isChallengeExpired(expiresAt)) {
          return {
            kind: "error",
            message: "This challenge expired. Restart to get a fresh message to sign.",
          };
        }

        const parsed = SignatureInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Paste the signature from your wallet." };
        }
        const signature = parsed.data.signature;

        const ok =
          chain === "ethereum"
            ? await verifyEthereumSignature(address, message, signature)
            : verifyBitcoinSignature(address, message, signature);
        if (!ok) {
          return {
            kind: "error",
            message:
              "That signature didn't verify for this address. Make sure you signed the exact message with the right wallet, then try again.",
          };
        }

        const { badges, events } = await buildWalletBadges(chain, address);

        // Verified event: log the issued badge TYPES and any event ids (public
        // labels), NEVER the address.
        await ctx.audit.log("plugin.wallet.verified", {
          chain,
          issuedTypes: badges.map((b) => b.type),
          events,
        });

        return { kind: "complete", badges };
      }
    }

    return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
  },
};
