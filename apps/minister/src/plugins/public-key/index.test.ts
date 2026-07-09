import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  createCleartextMessage,
  generateKey,
  readPrivateKey,
  sign as pgpSign,
  type PrivateKey,
} from "openpgp";

import type { PluginContext, WizardState } from "@minister/plugin-sdk";

import { publicKeyPlugin } from "./index";
import { CHALLENGE as SSH_CHALLENGE, ED25519_PUB, ED25519_SIG } from "./ssh-fixtures";

let priv: PrivateKey;
let pubArmored: string;
let otherPriv: PrivateKey;

async function clearsign(key: PrivateKey, text: string): Promise<string> {
  const message = await createCleartextMessage({ text });
  return pgpSign({ message, signingKeys: key, format: "armored" });
}

function ctx(): PluginContext {
  return {
    userId: "user_test",
    origin: "http://localhost:3000",
    audit: { log: vi.fn().mockResolvedValue(undefined) },
    sendMail: vi.fn().mockResolvedValue(undefined),
  };
}

beforeAll(async () => {
  const primary = await generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Wizard User", email: "wizard@example.com" }],
    format: "armored",
  });
  priv = await readPrivateKey({ armoredKey: primary.privateKey });
  pubArmored = primary.publicKey;

  const other = await generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Other", email: "other@example.com" }],
    format: "armored",
  });
  otherPriv = await readPrivateKey({ armoredKey: other.privateKey });
});

// Drive the wizard from start through the sign step to the verify (paste) step,
// returning the verify-step state and the challenge stashed server-side.
async function toVerify(
  publicKey: string,
  c: PluginContext,
): Promise<{ state: WizardState; challenge: string }> {
  const start = await publicKeyPlugin.startWizard(c);
  const form = await publicKeyPlugin.handleStep(start, { publicKey }, c);
  if (form.kind !== "continue") throw new Error(`expected continue after form, got ${form.kind}`);
  expect(form.state.currentStep.kind).toBe("info");
  const sign = await publicKeyPlugin.handleStep(form.state, {}, c);
  if (sign.kind !== "continue") throw new Error("expected continue after sign");
  expect(sign.state.currentStep.kind).toBe("form");
  return { state: sign.state, challenge: String(sign.state.data.challenge) };
}

describe("publicKeyPlugin form step", () => {
  it("rejects input that is neither a PGP nor an SSH key", async () => {
    const start = await publicKeyPlugin.startWizard(ctx());
    const r = await publicKeyPlugin.handleStep(start, { publicKey: "hello" }, ctx());
    expect(r.kind).toBe("error");
  });

  it("rejects a malformed PGP block", async () => {
    const start = await publicKeyPlugin.startWizard(ctx());
    const r = await publicKeyPlugin.handleStep(
      start,
      { publicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnope\n-----END-----" },
      ctx(),
    );
    expect(r.kind).toBe("error");
  });

  it("advances to a sign step and carries the challenge + key server-side", async () => {
    const c = ctx();
    const { state, challenge } = await toVerify(pubArmored, c);
    expect(state.data.kind).toBe("pgp");
    expect(typeof state.data.fingerprint).toBe("string");
    expect(challenge).toContain("ministry.id");
    // challenge_issued logs the kind but NEVER the fingerprint.
    const call = vi
      .mocked(c.audit.log)
      .mock.calls.find((x) => x[0] === "plugin.public_key.challenge_issued");
    expect(call?.[1]).toEqual({ kind: "pgp" });
    expect(JSON.stringify(call?.[1])).not.toContain(String(state.data.fingerprint));
  });
});

describe("publicKeyPlugin PGP end-to-end", () => {
  it("issues a public-key badge on a valid clearsigned challenge", async () => {
    const c = ctx();
    const { state, challenge } = await toVerify(pubArmored, c);
    const fingerprint = String(state.data.fingerprint);
    const signature = await clearsign(priv, challenge);

    const r = await publicKeyPlugin.handleStep(state, { signature }, c);
    if (r.kind !== "complete") throw new Error(`expected complete, got ${r.kind}`);

    const badge = r.badges[0];
    expect(badge?.type).toBe("public-key");
    expect(badge?.claims).toEqual({ kind: "pgp", fingerprint, algorithm: "ed25519" });
    // The fingerprint IS the disclosed anchor (revealsAnchor), like domain-control.
    expect(badge?.sybilAnchor).toBe(fingerprint);
    expect(badge?.revealsAnchor).toBe(true);

    // verified log carries the kind + fingerprint (the intended disclosure), and
    // nothing else about the key.
    const call = vi
      .mocked(c.audit.log)
      .mock.calls.find((x) => x[0] === "plugin.public_key.verified");
    expect(call?.[1]).toEqual({ kind: "pgp", fingerprint });
    expect(JSON.stringify(call?.[1])).not.toContain("wizard@example.com");
  });

  it("rejects a signature made by a different key", async () => {
    const c = ctx();
    const { state, challenge } = await toVerify(pubArmored, c);
    const signature = await clearsign(otherPriv, challenge);
    const r = await publicKeyPlugin.handleStep(state, { signature }, c);
    expect(r.kind).toBe("error");
  });

  it("rejects a signature over a mutated challenge", async () => {
    const c = ctx();
    const { state, challenge } = await toVerify(pubArmored, c);
    const signature = await clearsign(priv, `${challenge} tampered`);
    const r = await publicKeyPlugin.handleStep(state, { signature }, c);
    expect(r.kind).toBe("error");
  });

  it("rejects once the challenge has expired", async () => {
    const c = ctx();
    const { state, challenge } = await toVerify(pubArmored, c);
    const signature = await clearsign(priv, challenge);
    state.data.expiresAt = new Date(Date.now() - 1000).toISOString();
    const r = await publicKeyPlugin.handleStep(state, { signature }, c);
    expect(r.kind).toBe("error");
    if (r.kind !== "error") throw new Error("kind");
    expect(r.message).toContain("expired");
  });
});

describe("publicKeyPlugin SSH end-to-end (real ssh-keygen fixture)", () => {
  it("issues a public-key badge on a valid SSHSIG", async () => {
    const c = ctx();
    const { state } = await toVerify(ED25519_PUB, c);
    expect(state.data.kind).toBe("ssh");
    const fingerprint = String(state.data.fingerprint);
    expect(fingerprint).toMatch(/^SHA256:/u);

    // The wizard issued a random challenge; substitute the fixture's fixed
    // challenge (which the static SSHSIG was actually signed over) so the full
    // handleStep SSH path runs against genuine ssh-keygen output.
    state.data.challenge = SSH_CHALLENGE;

    const r = await publicKeyPlugin.handleStep(state, { signature: ED25519_SIG }, c);
    if (r.kind !== "complete") throw new Error(`expected complete, got ${r.kind}`);
    const badge = r.badges[0];
    expect(badge?.claims).toEqual({ kind: "ssh", fingerprint, algorithm: "ed25519" });
    expect(badge?.revealsAnchor).toBe(true);

    const call = vi
      .mocked(c.audit.log)
      .mock.calls.find((x) => x[0] === "plugin.public_key.verified");
    expect(call?.[1]).toEqual({ kind: "ssh", fingerprint });
  });

  it("rejects a wrong signature for the SSH key", async () => {
    const c = ctx();
    const { state } = await toVerify(ED25519_PUB, c);
    state.data.challenge = SSH_CHALLENGE;
    // A structurally valid armor that isn't the right signature.
    const r = await publicKeyPlugin.handleStep(
      state,
      { signature: "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----" },
      c,
    );
    expect(r.kind).toBe("error");
  });
});
