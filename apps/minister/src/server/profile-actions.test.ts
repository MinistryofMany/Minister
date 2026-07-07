import { describe, expect, it } from "vitest";

// normalizeProfileInput lives in profile-validation.ts (not "use server"),
// not profile-actions.ts: a "use server" file may only export async
// functions, and importing one here would drag in the next-auth/session
// chain this pure-function test deliberately avoids.
import { normalizeProfileInput } from "@/server/profile-validation";

describe("normalizeProfileInput", () => {
  it("normalizes empty strings to null for both fields", () => {
    const result = normalizeProfileInput({ displayName: "", avatarUrl: "" });
    expect(result.displayName).toBeNull();
    expect(result.avatarUrl).toBeNull();
  });

  it("normalizes a whitespace-only display name to null", () => {
    const result = normalizeProfileInput({ displayName: "   ", avatarUrl: "" });
    expect(result.displayName).toBeNull();
  });

  it("accepts a normal display name", () => {
    const result = normalizeProfileInput({ displayName: "  Ada Lovelace  ", avatarUrl: "" });
    expect(result.displayName).toBe("Ada Lovelace");
  });

  it("rejects a display name over 80 characters", () => {
    const tooLong = "a".repeat(81);
    expect(() => normalizeProfileInput({ displayName: tooLong, avatarUrl: "" })).toThrow();
  });

  it("accepts an 80-character display name (boundary)", () => {
    const exact = "a".repeat(80);
    const result = normalizeProfileInput({ displayName: exact, avatarUrl: "" });
    expect(result.displayName).toBe(exact);
  });

  it("accepts a valid https avatar URL", () => {
    const result = normalizeProfileInput({ displayName: "", avatarUrl: "https://x/y.png" });
    expect(result.avatarUrl).toBe("https://x/y.png");
  });

  it("rejects an http avatar URL", () => {
    expect(() => normalizeProfileInput({ displayName: "", avatarUrl: "http://x/y.png" })).toThrow();
  });

  it("rejects a javascript: avatar URL", () => {
    expect(() =>
      normalizeProfileInput({ displayName: "", avatarUrl: "javascript:alert(1)" }),
    ).toThrow();
  });

  it("rejects a data: avatar URL", () => {
    expect(() =>
      normalizeProfileInput({
        displayName: "",
        avatarUrl: "data:text/plain;base64,aGVsbG8=",
      }),
    ).toThrow();
  });

  it("rejects a relative path avatar URL", () => {
    expect(() => normalizeProfileInput({ displayName: "", avatarUrl: "/avatar.png" })).toThrow();
  });

  it("strips control chars (CR/LF/tab/NUL/C1) from an avatar URL so none survive into the output", () => {
    // The WHATWG URL parser silently ignores CR/LF/tab while parsing, so without
    // stripping they would ride into the persisted value and the picture claim
    // (a header / log-injection surface). Build the input via char codes so the
    // SOURCE stays plain ASCII - never embed a literal control byte, which makes
    // the file binary in git and fragile under normalization.
    const controls =
      String.fromCharCode(13) + // CR
      String.fromCharCode(10) + // LF
      String.fromCharCode(9) + // tab
      String.fromCharCode(0) + // NUL
      String.fromCharCode(0x85); // C1 (NEL)
    const result = normalizeProfileInput({
      displayName: "",
      avatarUrl: `https://example.com/${controls}avatar.png`,
    });
    expect(result.avatarUrl).toBe("https://example.com/avatar.png");
    // No C0 (incl. NUL), DEL, or C1 byte survives - the full range stripControlChars removes.
    const survivingControl = [...(result.avatarUrl ?? "")].some((ch) => {
      const c = ch.charCodeAt(0);
      return c <= 0x1f || c === 0x7f || (c >= 0x80 && c <= 0x9f);
    });
    expect(survivingControl).toBe(false);
  });
});
