import { describe, expect, it } from "vitest";

import { assertionIsValid, buildCheckAuthParams, parseSteamId } from "./verify";

describe("parseSteamId", () => {
  it("extracts the steamid64 from a valid claimed_id", () => {
    expect(parseSteamId("https://steamcommunity.com/openid/id/76561198000000000")).toBe(
      "76561198000000000",
    );
  });

  it("rejects a non-steam host", () => {
    expect(parseSteamId("https://evil.example.com/openid/id/76561198000000000")).toBeNull();
    // A look-alike host must not slip through.
    expect(
      parseSteamId("https://steamcommunity.com.evil.com/openid/id/76561198000000000"),
    ).toBeNull();
  });

  it("rejects a wrong-length id", () => {
    expect(parseSteamId("https://steamcommunity.com/openid/id/123")).toBeNull();
  });

  it("rejects http (non-https)", () => {
    expect(parseSteamId("http://steamcommunity.com/openid/id/76561198000000000")).toBeNull();
  });
});

describe("buildCheckAuthParams", () => {
  it("echoes openid.* params and forces check_authentication mode", () => {
    const params = buildCheckAuthParams({
      "openid.ns": "http://specs.openid.net/auth/2.0",
      "openid.mode": "id_res",
      "openid.sig": "abc",
      // Non-openid params (like our own correlation token) are dropped: they
      // are not part of what Steam signed.
      state: "should-be-dropped",
    });
    expect(params.get("openid.mode")).toBe("check_authentication");
    expect(params.get("openid.ns")).toBe("http://specs.openid.net/auth/2.0");
    expect(params.get("openid.sig")).toBe("abc");
    expect(params.get("state")).toBeNull();
  });
});

describe("assertionIsValid", () => {
  it("accepts a body containing the is_valid:true line", () => {
    expect(assertionIsValid("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n")).toBe(true);
  });
  it("rejects is_valid:false", () => {
    expect(assertionIsValid("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n")).toBe(false);
  });
  it("rejects a substring that is not its own line", () => {
    expect(assertionIsValid("note:is_valid:true is not a standalone line")).toBe(false);
  });
});
