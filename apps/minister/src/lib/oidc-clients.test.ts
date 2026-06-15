import { describe, expect, it } from "vitest";

import {
  generateClientId,
  generateClientSecret,
  hashClientSecret,
  isRegisteredRedirectUri,
  verifyClientSecret,
} from "./oidc-clients";

describe("generateClientId", () => {
  it("returns the `tc_` prefix + base64url suffix", () => {
    const id = generateClientId();
    expect(id).toMatch(/^tc_[A-Za-z0-9_-]+$/);
  });

  it("returns unique values on each call", () => {
    const a = generateClientId();
    const b = generateClientId();
    expect(a).not.toBe(b);
  });

  it("encodes >= 128 bits of entropy", () => {
    // 18 random bytes → 24 base64url chars (no padding); plus the
    // 3-char "tc_" prefix = 27.
    const suffix = generateClientId().slice("tc_".length);
    expect(suffix.length).toBeGreaterThanOrEqual(24);
  });
});

describe("generateClientSecret", () => {
  it("returns a base64url string of ~43 chars (32 bytes)", () => {
    const s = generateClientSecret();
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(s.length).toBe(43);
  });

  it("returns unique values on each call", () => {
    expect(generateClientSecret()).not.toBe(generateClientSecret());
  });
});

describe("argon2id client-secret round trip", () => {
  it("hash + verify accepts the original plaintext", async () => {
    const secret = generateClientSecret();
    const encoded = await hashClientSecret(secret);
    expect(encoded.startsWith("$argon2id$")).toBe(true);
    expect(await verifyClientSecret(secret, encoded)).toBe(true);
  });

  it("rejects a different secret", async () => {
    const encoded = await hashClientSecret("password-A");
    expect(await verifyClientSecret("password-B", encoded)).toBe(false);
  });

  it("returns false on a malformed encoded string rather than throwing", async () => {
    expect(await verifyClientSecret("anything", "not-an-argon2-hash")).toBe(false);
  });
});

describe("isRegisteredRedirectUri", () => {
  it("requires exact match (RFC 6749 §3.1.2.2)", () => {
    const client = {
      redirectUris: ["http://localhost:3100/api/auth/callback/minister"],
    };
    expect(
      isRegisteredRedirectUri(client, "http://localhost:3100/api/auth/callback/minister"),
    ).toBe(true);
  });

  it("rejects a substring match", () => {
    const client = {
      redirectUris: ["http://localhost:3100/api/auth/callback/minister"],
    };
    expect(isRegisteredRedirectUri(client, "http://localhost:3100/api/auth")).toBe(false);
  });

  it("rejects a path-suffix-extension attack", () => {
    const client = {
      redirectUris: ["http://localhost:3100/api/auth/callback/minister"],
    };
    expect(
      isRegisteredRedirectUri(client, "http://localhost:3100/api/auth/callback/minister/extra"),
    ).toBe(false);
  });

  it("rejects a trailing-slash variant", () => {
    const client = {
      redirectUris: ["http://localhost:3100/cb"],
    };
    expect(isRegisteredRedirectUri(client, "http://localhost:3100/cb/")).toBe(false);
  });

  it("supports multiple registered redirect URIs", () => {
    const client = {
      redirectUris: ["https://a.example/cb", "https://b.example/cb"],
    };
    expect(isRegisteredRedirectUri(client, "https://b.example/cb")).toBe(true);
  });
});
