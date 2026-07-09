import { beforeAll, describe, expect, it } from "vitest";
import {
  createCleartextMessage,
  createMessage,
  generateKey,
  readPrivateKey,
  sign as pgpSign,
  type PrivateKey,
} from "openpgp";

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
} from "./verify";
import {
  CHALLENGE as SSH_CHALLENGE,
  ECDSA_PUB,
  ECDSA_SIG,
  ED25519_PUB,
  ED25519_SIG,
  ED25519_SIG_TRAILING_NL,
  ED25519_SIG_WRONG_NAMESPACE,
  RSA_PUB,
  RSA_SIG,
} from "./ssh-fixtures";

// A real, throwaway PGP keypair generated once for the whole suite (fast for
// ed25519). We sign the exact challenge with it and assert the verifier binds to
// both the challenge and this specific key.
let priv: PrivateKey;
let pubArmored: string;
let otherPubArmored: string;
const CHALLENGE = "ministry.id proof\nNonce: 0123456789abcdef0123456789abcdef\nline three";

async function clearsign(key: PrivateKey, text: string): Promise<string> {
  const message = await createCleartextMessage({ text });
  return pgpSign({ message, signingKeys: key, format: "armored" });
}

async function detachedSign(key: PrivateKey, text: string): Promise<string> {
  const message = await createMessage({ text });
  return pgpSign({ message, signingKeys: key, detached: true, format: "armored" });
}

beforeAll(async () => {
  const primary = await generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Test User", email: "test@example.com" }],
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
  otherPubArmored = other.publicKey;
});

describe("detectKeyKind", () => {
  it("classifies a PGP public key block", () => {
    expect(detectKeyKind("-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END…")).toBe("pgp");
  });
  it("classifies SSH public key lines", () => {
    expect(detectKeyKind(ED25519_PUB)).toBe("ssh");
    expect(detectKeyKind(RSA_PUB)).toBe("ssh");
    expect(detectKeyKind(ECDSA_PUB)).toBe("ssh");
  });
  it("returns null for anything else", () => {
    expect(detectKeyKind("hello world")).toBeNull();
    expect(detectKeyKind("ssh-dss AAAA...")).toBeNull();
    expect(detectKeyKind("")).toBeNull();
  });
});

describe("buildKeyChallenge", () => {
  it("embeds the domain, a 128-bit nonce, and an expiry", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const c = buildKeyChallenge("pgp", now);
    expect(c.message).toContain("ministry.id");
    expect(c.message).toContain("PGP");
    expect(c.nonce).toMatch(/^[0-9a-f]{32}$/u);
    expect(c.message).toContain(c.nonce);
    expect(c.expiresAt).toBe("2026-01-01T00:15:00.000Z");
  });
  it("labels SSH challenges and uses a fresh nonce each call", () => {
    expect(buildKeyChallenge("ssh").message).toContain("SSH");
    expect(buildKeyChallenge("pgp").nonce).not.toBe(buildKeyChallenge("pgp").nonce);
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

describe("parsePgpPublicKey", () => {
  it("extracts the fingerprint, algorithm, and primary user id", async () => {
    const parsed = await parsePgpPublicKey(pubArmored);
    expect(parsed).not.toBeNull();
    expect(parsed?.fingerprint).toMatch(/^[0-9a-f]{40}$/u);
    expect(parsed?.algorithm).toBe("ed25519");
    expect(parsed?.userId).toBe("Test User <test@example.com>");
  });
  it("rejects a malformed key without throwing", async () => {
    expect(await parsePgpPublicKey("not a key")).toBeNull();
    expect(
      await parsePgpPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n-----END-----"),
    ).toBeNull();
  });
  it("rejects a private key (never accept a secret key)", async () => {
    const primary = await generateKey({
      type: "ecc",
      curve: "ed25519Legacy",
      userIDs: [{ name: "Priv", email: "p@e.com" }],
      format: "armored",
    });
    expect(await parsePgpPublicKey(primary.privateKey)).toBeNull();
  });
});

describe("verifyPgpSignature", () => {
  it("verifies a clearsigned challenge from the presented key", async () => {
    const sig = await clearsign(priv, CHALLENGE);
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, sig)).toBe(true);
  });

  it("verifies a detached signature over the challenge", async () => {
    const sig = await detachedSign(priv, CHALLENGE);
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, sig)).toBe(true);
  });

  it("rejects a signature over a different message (wrong challenge)", async () => {
    const sig = await clearsign(priv, "a message I made up");
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, sig)).toBe(false);
    const det = await detachedSign(priv, "a different message");
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, det)).toBe(false);
  });

  it("rejects a valid signature made by a DIFFERENT key", async () => {
    // Signed by `priv`, but verified against a different public key.
    const sig = await clearsign(priv, CHALLENGE);
    expect(await verifyPgpSignature(otherPubArmored, CHALLENGE, sig)).toBe(false);
  });

  it("rejects a tampered signature without throwing", async () => {
    const sig = await clearsign(priv, CHALLENGE);
    const tampered = sig.replace(/[A-Za-z](?=\n)/u, (c) => (c === "A" ? "B" : "A"));
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, tampered)).toBe(false);
  });

  it("rejects malformed signature input without throwing", async () => {
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, "garbage")).toBe(false);
    expect(await verifyPgpSignature(pubArmored, CHALLENGE, "")).toBe(false);
    expect(
      await verifyPgpSignature(
        pubArmored,
        CHALLENGE,
        "-----BEGIN PGP SIGNATURE-----\nnope\n-----END PGP SIGNATURE-----",
      ),
    ).toBe(false);
  });

  it("returns false when the public key itself is malformed", async () => {
    const sig = await clearsign(priv, CHALLENGE);
    expect(await verifyPgpSignature("not a key", CHALLENGE, sig)).toBe(false);
  });
});

describe("parseSshPublicKey", () => {
  it("extracts a SHA256 fingerprint and algorithm for each supported type", () => {
    const ed = parseSshPublicKey(ED25519_PUB);
    expect(ed?.algorithm).toBe("ed25519");
    expect(ed?.fingerprint).toMatch(/^SHA256:/u);

    const rsa = parseSshPublicKey(RSA_PUB);
    expect(rsa?.algorithm).toBe("rsa-3072");
    expect(rsa?.fingerprint).toMatch(/^SHA256:/u);

    const ec = parseSshPublicKey(ECDSA_PUB);
    expect(ec?.algorithm).toBe("ecdsa-nistp256");
    expect(ec?.fingerprint).toMatch(/^SHA256:/u);
  });
  it("rejects malformed / unsupported keys without throwing", () => {
    expect(parseSshPublicKey("not a key")).toBeNull();
    expect(parseSshPublicKey("ssh-ed25519 !!!notbase64!!!")).toBeNull();
  });
});

describe("verifySshSignature (SSHSIG, real ssh-keygen fixtures)", () => {
  it("verifies genuine signatures for ed25519, rsa, and ecdsa", () => {
    expect(verifySshSignature(ED25519_PUB, SSH_CHALLENGE, ED25519_SIG)).toBe(true);
    expect(verifySshSignature(RSA_PUB, SSH_CHALLENGE, RSA_SIG)).toBe(true);
    expect(verifySshSignature(ECDSA_PUB, SSH_CHALLENGE, ECDSA_SIG)).toBe(true);
  });

  it("tolerates a trailing newline in the signed file", () => {
    expect(verifySshSignature(ED25519_PUB, SSH_CHALLENGE, ED25519_SIG_TRAILING_NL)).toBe(true);
  });

  it("rejects a signature over a different message (wrong challenge)", () => {
    expect(verifySshSignature(ED25519_PUB, `${SSH_CHALLENGE}X`, ED25519_SIG)).toBe(false);
  });

  it("rejects a signature made under a different namespace", () => {
    expect(verifySshSignature(ED25519_PUB, SSH_CHALLENGE, ED25519_SIG_WRONG_NAMESPACE)).toBe(false);
  });

  it("rejects a signature verified against a DIFFERENT key", () => {
    // ed25519 signature checked against the rsa public key -> embedded key
    // mismatch -> false.
    expect(verifySshSignature(RSA_PUB, SSH_CHALLENGE, ED25519_SIG)).toBe(false);
  });

  it("rejects a tampered signature without throwing", () => {
    const tampered = ED25519_SIG.replace(/[A-Za-z](?=\n)/u, (c) => (c === "A" ? "B" : "A"));
    expect(verifySshSignature(ED25519_PUB, SSH_CHALLENGE, tampered)).toBe(false);
  });

  it("rejects malformed signature armor without throwing", () => {
    expect(verifySshSignature(ED25519_PUB, SSH_CHALLENGE, "garbage")).toBe(false);
    expect(
      verifySshSignature(
        ED25519_PUB,
        SSH_CHALLENGE,
        "-----BEGIN SSH SIGNATURE-----\nnope\n-----END SSH SIGNATURE-----",
      ),
    ).toBe(false);
  });

  it("uses the namespace the plugin advertises", () => {
    expect(SSH_NAMESPACE).toBe("pubkey-proof@ministry.id");
  });
});

describe("buildPublicKeyBadge", () => {
  it("puts the fingerprint in the claim and rides it as the revealed anchor", () => {
    const badge = buildPublicKeyBadge("pgp", "deadbeef".repeat(5), "ed25519");
    expect(badge.type).toBe("public-key");
    expect(badge.claims).toEqual({
      kind: "pgp",
      fingerprint: "deadbeef".repeat(5),
      algorithm: "ed25519",
    });
    expect(badge.attributes).toEqual(badge.claims);
    // The fingerprint IS the anchor and IS disclosed (revealsAnchor), like
    // domain-control.
    expect(badge.sybilAnchor).toBe("deadbeef".repeat(5));
    expect(badge.revealsAnchor).toBe(true);
  });
});
