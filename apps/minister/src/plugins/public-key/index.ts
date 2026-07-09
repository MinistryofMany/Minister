import { z } from "zod";

import type { IssuedBadge, Plugin, WizardState } from "@minister/plugin-sdk";

import {
  buildKeyChallenge,
  buildPublicKeyBadge,
  detectKeyKind,
  isChallengeExpired,
  parsePgpPublicKey,
  parseSshPublicKey,
  SSH_NAMESPACE,
  verifyPgpSignature,
  verifySshSignature,
  type KeyKind,
} from "./verify";

const STEP_FORM = "pubkey-key";
const STEP_SIGN = "pubkey-sign";
const STEP_VERIFY = "pubkey-verify";

// Cap both inputs: a real public key or SSHSIG is a few KB, so 64 KB is
// generous. Without a cap the only bound is Next's implicit server-action body
// limit, and a ~1 MB armored "key" would make signature verification burn CPU on
// an authenticated request (wizard actions are not rate-limited).
const MAX_INPUT_CHARS = 65_536;
const KeyInput = z.object({
  publicKey: z.string().min(1).max(MAX_INPUT_CHARS),
});

const SignatureInput = z.object({
  signature: z.string().min(1).max(MAX_INPUT_CHARS),
});

function makeFormStep(userId: string): WizardState {
  return {
    pluginId: "public-key",
    userId,
    currentStep: {
      id: STEP_FORM,
      kind: "form",
      payload: {
        title: "Prove you control a public key",
        description:
          "Paste an asymmetric public key and prove you hold its private key by signing a short " +
          "challenge. Works with a PGP public key or an SSH public key (Ed25519, RSA, or ECDSA). " +
          "The badge records only the key's fingerprint. Never paste a private key.",
        fields: [
          {
            name: "publicKey",
            label: "Public key",
            type: "text",
            placeholder: "-----BEGIN PGP PUBLIC KEY BLOCK----- …   or   ssh-ed25519 AAAA… you@host",
            helpText: "A PGP public key block, or one SSH public key line.",
            required: true,
          },
        ],
        submitLabel: "Continue",
      },
    },
    data: {},
  };
}

// The sign-step body: shows the exact challenge to sign and the per-kind command
// to produce a signature. The challenge is not a secret (it must be shown so the
// user can sign it) but it is bound to this session and expires.
function signStepBody(kind: KeyKind, challenge: string, keyLabel: string | null): string {
  const intro =
    keyLabel !== null
      ? `We identified this key as: ${keyLabel}. If that is not the key you meant, restart and paste the right one.`
      : `Sign the challenge below with the key you pasted.`;

  const howTo =
    kind === "pgp"
      ? [
          `1. Save the text between the markers to a file, for example challenge.txt.`,
          `2. Sign it with the matching key:`,
          ``,
          `       gpg --clearsign challenge.txt`,
          ``,
          `   (If you hold more than one key, add --local-user <your-key-id>.)`,
          `3. Open the resulting challenge.txt.asc and paste its whole contents on the next step.`,
        ]
      : [
          `1. Save the text between the markers to a file, for example challenge.txt.`,
          `2. Sign it with your private key, using this exact namespace:`,
          ``,
          `       ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n ${SSH_NAMESPACE} challenge.txt`,
          ``,
          `   (Point -f at the private key that matches the public key you pasted.)`,
          `3. Open the resulting challenge.txt.sig and paste its whole contents on the next step.`,
        ];

  return [
    intro,
    ``,
    `--- challenge to sign ---`,
    challenge,
    `--- end challenge ---`,
    ``,
    ...howTo,
    ``,
    `The challenge expires in a few minutes. If it lapses, restart to get a fresh one.`,
  ].join("\n");
}

function pgpKeyLabel(algorithm: string, userId: string | null): string {
  return userId ? `${algorithm} key for ${userId}` : `${algorithm} key`;
}

export const publicKeyPlugin: Plugin = {
  manifest: {
    id: "public-key",
    name: "Public key",
    description:
      "Prove you control a public key by signing a challenge with its private key, Keybase-style. " +
      "Works with PGP keys and SSH keys (Ed25519, RSA, ECDSA). Issues a public-key badge that " +
      "records only the key's fingerprint. Needs no third-party sign-in.",
    badgeTypes: ["public-key"],
    requiresExtension: false,
    iconKey: "key",
  },

  // No credentials required — signature checks are keyless, so always available.

  async startWizard(ctx) {
    return makeFormStep(ctx.userId);
  },

  async handleStep(state, input, ctx) {
    switch (state.currentStep.id) {
      case STEP_FORM: {
        const parsed = KeyInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Paste a public key." };
        }
        const publicKey = parsed.data.publicKey.trim();
        const kind = detectKeyKind(publicKey);
        if (kind === null) {
          return {
            kind: "error",
            message:
              "That doesn't look like a PGP public key block or an SSH public key line. Paste a " +
              "public key (never a private key).",
          };
        }

        let fingerprint: string;
        let algorithm: string;
        let keyLabel: string | null = null;
        if (kind === "pgp") {
          const key = await parsePgpPublicKey(publicKey);
          if (!key) {
            return {
              kind: "error",
              message:
                "We couldn't read that as a PGP public key. Paste the full ASCII-armored public " +
                "key block (not a private key).",
            };
          }
          fingerprint = key.fingerprint;
          algorithm = key.algorithm;
          keyLabel = pgpKeyLabel(key.algorithm, key.userId);
        } else {
          const key = parseSshPublicKey(publicKey);
          if (!key) {
            return {
              kind: "error",
              message:
                "We couldn't read that as an SSH public key. Paste one line beginning with " +
                "ssh-ed25519, ssh-rsa, or ecdsa-sha2-… (DSA keys aren't supported).",
            };
          }
          fingerprint = key.fingerprint;
          algorithm = key.algorithm;
          keyLabel = `${key.algorithm} key (${key.fingerprint})`;
        }

        const challenge = buildKeyChallenge(kind);

        // Do NOT log the fingerprint here: control is unproven at this point, so
        // recording an arbitrary key against the requester would be an
        // unverified-claim leak. Only the (non-identifying) kind is logged. The
        // fingerprint is logged on the verified event below (the revealsAnchor
        // exception, mirroring domain-control).
        await ctx.audit.log("plugin.public_key.challenge_issued", { kind });

        return {
          kind: "continue",
          state: {
            ...state,
            currentStep: {
              id: STEP_SIGN,
              kind: "info",
              payload: {
                title: "Sign the challenge with your private key",
                body: signStepBody(kind, challenge.message, keyLabel),
                continueLabel: "I've signed it",
              },
            },
            // Server-side only (toClientState scrubs `data`). The fingerprint is
            // not the Sybil anchor until the signature verifies; a new key means
            // restarting the flow, which discards this challenge. The raw pasted
            // key is kept only to re-run the check on the verify step.
            data: {
              kind,
              publicKey,
              fingerprint,
              algorithm,
              challenge: challenge.message,
              expiresAt: challenge.expiresAt,
            },
          },
        };
      }

      case STEP_SIGN: {
        // Info step: the only action is Continue. Re-show the challenge on the
        // paste step so the user can still copy it, and collect the signature.
        const challenge = typeof state.data.challenge === "string" ? state.data.challenge : "";
        if (!challenge) {
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
                  "Paste the signature you produced for the challenge below. We check it was made " +
                  "by the key you pasted, over exactly this text.\n\n" +
                  challenge,
                fields: [
                  {
                    name: "signature",
                    label: "Signature",
                    type: "text",
                    placeholder:
                      "-----BEGIN PGP SIGNED MESSAGE----- …   or   -----BEGIN SSH SIGNATURE----- …",
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
        const kind =
          state.data.kind === "pgp" || state.data.kind === "ssh"
            ? (state.data.kind as KeyKind)
            : null;
        const publicKey = typeof state.data.publicKey === "string" ? state.data.publicKey : "";
        const fingerprint =
          typeof state.data.fingerprint === "string" ? state.data.fingerprint : "";
        const algorithm = typeof state.data.algorithm === "string" ? state.data.algorithm : "";
        const challenge = typeof state.data.challenge === "string" ? state.data.challenge : "";
        const expiresAt = typeof state.data.expiresAt === "string" ? state.data.expiresAt : "";
        if (!kind || !publicKey || !fingerprint || !algorithm || !challenge || !expiresAt) {
          return { kind: "error", message: "This flow lost its challenge — restart it." };
        }
        if (isChallengeExpired(expiresAt)) {
          return {
            kind: "error",
            message: "This challenge expired. Restart to get a fresh challenge to sign.",
          };
        }

        const parsed = SignatureInput.safeParse(input);
        if (!parsed.success) {
          return { kind: "error", message: "Paste the signature you produced." };
        }
        const signature = parsed.data.signature;

        const ok =
          kind === "pgp"
            ? await verifyPgpSignature(publicKey, challenge, signature)
            : verifySshSignature(publicKey, challenge, signature);
        if (!ok) {
          return {
            kind: "error",
            message:
              kind === "pgp"
                ? "That signature didn't verify. Make sure you clearsigned the exact challenge with " +
                  "the matching private key, then paste the whole signed block and try again."
                : "That signature didn't verify. Make sure you signed the exact challenge with the " +
                  `right key and the namespace ${SSH_NAMESPACE}, then paste the whole signature and try again.`,
          };
        }

        const badges: IssuedBadge[] = [buildPublicKeyBadge(kind, fingerprint, algorithm)];

        // Verified: the fingerprint IS the disclosed value and the Sybil anchor
        // (revealsAnchor), so it legitimately appears here — nothing else about
        // the key (the raw key, any user id/email) is logged.
        await ctx.audit.log("plugin.public_key.verified", { kind, fingerprint });

        return { kind: "complete", badges };
      }
    }

    return { kind: "error", message: `Unknown wizard step: ${state.currentStep.id}` };
  },
};
