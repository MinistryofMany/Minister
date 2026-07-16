import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { describe, expect, it } from "vitest";

import vectors from "./pair-protocol-vectors.json";
import {
  buildPairAad,
  checkPairCode,
  decodeRelayBody,
  derivePairCode,
  encodePairQr,
  generateRecipientKeyPair,
  openRoot,
  PairProtocolError,
  parsePairQr,
  PAIR_RELAY_BODY_BYTES,
  sealRoot,
} from "./pair-protocol";

const fromHex = (h: string) => new Uint8Array(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const userId = vectors.userId;
const sessionId = vectors.sessionId;
const epoch = vectors.epoch;
const pub = fromHex(vectors.recipientPublicKeyHex);
const root = fromHex(vectors.rootHex);

function pairSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}

describe("pair-protocol golden vectors (frozen — regenerate only on a version bump)", () => {
  it("buildPairAad matches the frozen AAD bytes", () => {
    expect(toHex(buildPairAad(userId, sessionId, epoch))).toBe(vectors.aadHex);
  });

  it("encodePairQr matches the frozen QR string", () => {
    expect(encodePairQr(sessionId, pub)).toBe(vectors.qr);
  });

  it("parsePairQr round-trips the frozen QR", () => {
    const parsed = parsePairQr(vectors.qr);
    expect(parsed).not.toBeNull();
    expect(parsed!.sessionId).toBe(sessionId);
    expect(toHex(parsed!.publicKey)).toBe(vectors.recipientPublicKeyHex);
  });

  it("derivePairCode matches the frozen code", () => {
    expect(derivePairCode(sessionId, pub)).toBe(vectors.pairCode);
    expect(checkPairCode(sessionId, pub, ` ${vectors.pairCode.toLowerCase()} `)).toBe(true);
  });

  it("openRoot recovers the root from the frozen sealed relay body", async () => {
    // Deterministic recipient key pair from the frozen ikm.
    const kp = await pairSuite().kem.deriveKeyPair(fromHex(vectors.recipientIkmHex));
    const body = decodeRelayBody(vectors.sealedRelayBody);
    const opened = await openRoot({
      recipientKeyPair: kp,
      relayBody: body,
      userId,
      sessionId,
      epoch,
    });
    expect(toHex(opened)).toBe(vectors.rootHex);
  });
});

describe("AAD separator guard (S2) — a field with '|' is rejected", () => {
  it("rejects a userId containing the separator", () => {
    expect(() => buildPairAad("evil|user", sessionId, epoch)).toThrow(PairProtocolError);
  });

  it("rejects a sessionId containing the separator", () => {
    expect(() => buildPairAad(userId, "sess|ion", epoch)).toThrow(PairProtocolError);
  });

  it("rejects an empty field", () => {
    expect(() => buildPairAad("", sessionId, epoch)).toThrow(PairProtocolError);
    expect(() => buildPairAad(userId, "", epoch)).toThrow(PairProtocolError);
  });
});

describe("HPKE seal/open round-trip", () => {
  it("seals with a fresh recipient key and opens back to the exact root", async () => {
    const { keyPair, publicKey } = await generateRecipientKeyPair();
    const body = await sealRoot({ recipientPublicKey: publicKey, root, userId, sessionId, epoch });
    expect(body.length).toBe(PAIR_RELAY_BODY_BYTES);
    const opened = await openRoot({
      recipientKeyPair: keyPair,
      relayBody: body,
      userId,
      sessionId,
      epoch,
    });
    expect(toHex(opened)).toBe(vectors.rootHex);
  });

  it("a tampered relay body fails GCM — never yields a wrong root", async () => {
    const { keyPair, publicKey } = await generateRecipientKeyPair();
    const body = await sealRoot({ recipientPublicKey: publicKey, root, userId, sessionId, epoch });
    const last = PAIR_RELAY_BODY_BYTES - 1;
    body[last] = (body[last] ?? 0) ^ 0x01; // flip one bit of the tag
    await expect(
      openRoot({ recipientKeyPair: keyPair, relayBody: body, userId, sessionId, epoch }),
    ).rejects.toThrow(PairProtocolError);
  });

  it("a mismatched AAD userId fails to open (the C2 account binding)", async () => {
    const { keyPair, publicKey } = await generateRecipientKeyPair();
    const body = await sealRoot({ recipientPublicKey: publicKey, root, userId, sessionId, epoch });
    await expect(
      openRoot({
        recipientKeyPair: keyPair,
        relayBody: body,
        userId: "someone_else",
        sessionId,
        epoch,
      }),
    ).rejects.toThrow(PairProtocolError);
  });

  it("a mismatched AAD sessionId fails to open", async () => {
    const { keyPair, publicKey } = await generateRecipientKeyPair();
    const body = await sealRoot({ recipientPublicKey: publicKey, root, userId, sessionId, epoch });
    await expect(
      openRoot({
        recipientKeyPair: keyPair,
        relayBody: body,
        userId,
        sessionId: "BBBBBBBBBBBBBBBBBBBBBB",
        epoch,
      }),
    ).rejects.toThrow(PairProtocolError);
  });

  it("a STALE scanner's epoch fails to open (W1 — the re-key soft-brick guard)", async () => {
    // Scanner still holds an epoch-1 root and seals it; the fresh receiver is on
    // the current server epoch 2. The AAD epochs differ, so GCM open must fail
    // closed rather than let the receiver stamp the stale root as ACTIVE@2.
    const { keyPair, publicKey } = await generateRecipientKeyPair();
    const staleBody = await sealRoot({
      recipientPublicKey: publicKey,
      root,
      userId,
      sessionId,
      epoch: 1,
    });
    await expect(
      openRoot({ recipientKeyPair: keyPair, relayBody: staleBody, userId, sessionId, epoch: 2 }),
    ).rejects.toThrow(PairProtocolError);
  });
});

describe("parsePairQr rejects anything that is not a well-formed MP1 payload", () => {
  it("rejects a URL, a foreign QR, and truncated captures", () => {
    expect(parsePairQr("https://ministry.id/pair#" + vectors.qr)).toBeNull();
    expect(parsePairQr("WIFI:S:home;T:WPA;P:secret;;")).toBeNull();
    expect(parsePairQr(vectors.qr.slice(0, 40))).toBeNull();
    expect(parsePairQr(vectors.qr + ".extra")).toBeNull();
    expect(parsePairQr("MP1.tooshort.tooshort")).toBeNull();
    expect(parsePairQr("")).toBeNull();
  });
});
