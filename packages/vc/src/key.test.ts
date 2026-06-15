import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { _resetIssuerCache, loadIssuer } from "./key";

describe("loadIssuer", () => {
  let tmpDir: string;
  let keyPath: string;

  beforeEach(async () => {
    _resetIssuerCache();
    tmpDir = await mkdtemp(join(tmpdir(), "minister-key-test-"));
    keyPath = join(tmpDir, "issuer.jwk");
  });

  afterEach(async () => {
    _resetIssuerCache();
    await rm(tmpDir, { recursive: true, force: true });
  });

  it("generates and persists a fresh Ed25519 key on first boot", async () => {
    const issuer = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    expect(issuer.did).toBe("did:web:minister.local");
    expect(issuer.kid).toBe("did:web:minister.local#key-1");
    expect(issuer.publicJwk.kty).toBe("OKP");
    expect(issuer.publicJwk.crv).toBe("Ed25519");
    // Public JWK must not leak the private scalar.
    expect(issuer.publicJwk.d).toBeUndefined();

    // The file on disk should be a JWK *with* the private scalar.
    const written = JSON.parse(await readFile(keyPath, "utf8"));
    expect(written.kty).toBe("OKP");
    expect(written.crv).toBe("Ed25519");
    expect(typeof written.d).toBe("string");
  });

  it("re-uses the persisted key on subsequent loads", async () => {
    const first = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    // Reset the in-memory cache; the disk-persisted key should be
    // re-imported and produce the same public material.
    _resetIssuerCache();
    const second = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    expect(second.publicJwk.x).toBe(first.publicJwk.x);
  });

  it("caches across calls with identical options", async () => {
    const first = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    const second = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    // Same object reference if the cache short-circuited.
    expect(second).toBe(first);
  });

  it("loads a JWK passed via privateJwk and ignores devKeyPath", async () => {
    // First, generate one via devKeyPath so we have a known good JWK.
    const seed = await loadIssuer({
      domain: "minister.local",
      devKeyPath: keyPath,
    });
    const fileJwk = await readFile(keyPath, "utf8");
    _resetIssuerCache();

    // Now load that JWK via privateJwk, with a different (non-existent)
    // devKeyPath to prove privateJwk wins.
    const reloaded = await loadIssuer({
      domain: "minister.local",
      privateJwk: fileJwk,
      devKeyPath: join(tmpDir, "does-not-exist.jwk"),
    });
    expect(reloaded.publicJwk.x).toBe(seed.publicJwk.x);
  });

  it("throws when no key source is provided", async () => {
    await expect(loadIssuer({ domain: "minister.local" })).rejects.toThrow(/key missing/i);
  });

  it("throws on a JWK with the wrong key type", async () => {
    const badJwk = JSON.stringify({
      kty: "EC",
      crv: "P-256",
      d: "abc",
      x: "abc",
      y: "abc",
    });
    await expect(loadIssuer({ domain: "minister.local", privateJwk: badJwk })).rejects.toThrow(
      /OKP\/Ed25519/,
    );
  });

  it("throws on a public-only JWK (missing d)", async () => {
    const publicOnly = JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "AAAA",
    });
    await expect(loadIssuer({ domain: "minister.local", privateJwk: publicOnly })).rejects.toThrow(
      /missing private scalar/,
    );
  });
});
