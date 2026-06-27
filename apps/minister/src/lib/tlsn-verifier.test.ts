import type { MockInstance } from "vitest";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { TlsnVerifierError, validateTlsnVerifierConfig, verifyPresentation } from "./tlsn-verifier";

const ORIGINAL = process.env.TLSN_VERIFIER_URL;
beforeAll(() => {
  process.env.TLSN_VERIFIER_URL = "http://verifier.test:7048";
});
afterAll(() => {
  if (ORIGINAL === undefined) delete process.env.TLSN_VERIFIER_URL;
  else process.env.TLSN_VERIFIER_URL = ORIGINAL;
});

// Install the fetch spy per-test and fully restore it afterwards. Under
// Vitest 3, a module-level `spyOn(globalThis, "fetch")` that is only reset
// (not restored) stays installed across the file/worker teardown and leaks
// a stray `fetch(undefined)` into real undici ("Failed to parse URL from
// undefined"). Restoring each time keeps `globalThis.fetch` clean.
let fetchSpy: MockInstance<typeof globalThis.fetch>;
beforeEach(() => {
  fetchSpy = vi.spyOn(globalThis, "fetch");
});
afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(json: unknown, status = 200): Response {
  return new Response(JSON.stringify(json), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("verifyPresentation", () => {
  it("POSTs presentation + expectedDomain to /verify and returns the transcript", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({
        ok: true,
        transcript: {
          sent: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
          received: "HTTP/1.1 200 OK\r\n\r\nExample Domain",
          serverName: "example.com",
        },
      }),
    );

    const transcript = await verifyPresentation({
      presentation: "BASE64_PRESENTATION",
      expectedDomain: "example.com",
    });

    expect(transcript.serverName).toBe("example.com");
    expect(transcript.received).toContain("Example Domain");

    const [url, init] = fetchSpy.mock.calls[0]!;
    expect(url).toBe("http://verifier.test:7048/verify");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(init?.body as string)).toEqual({
      presentation: "BASE64_PRESENTATION",
      expectedDomain: "example.com",
    });
  });

  it("throws TlsnVerifierError with the verifier's message on a failure", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: false, error: "server name mismatch" }));
    const promise = verifyPresentation({
      presentation: "x",
      expectedDomain: "y",
    });
    await expect(promise).rejects.toBeInstanceOf(TlsnVerifierError);
    // Re-mock and re-call to assert the message separately (each
    // verifyPresentation call consumes one fetch).
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: false, error: "server name mismatch" }));
    await expect(verifyPresentation({ presentation: "x", expectedDomain: "y" })).rejects.toThrow(
      /server name mismatch/,
    );
  });

  it("throws on an unreachable verifier", async () => {
    fetchSpy.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    await expect(verifyPresentation({ presentation: "x", expectedDomain: "y" })).rejects.toThrow(
      /Could not reach/,
    );
  });

  it("throws on a non-JSON response", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("plain text", { status: 200 }));
    await expect(verifyPresentation({ presentation: "x", expectedDomain: "y" })).rejects.toThrow(
      /non-JSON/,
    );
  });

  it("throws when the response shape doesn't match", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ unexpected: "shape" }));
    await expect(verifyPresentation({ presentation: "x", expectedDomain: "y" })).rejects.toThrow(
      /expected shape/,
    );
  });

  it("refuses a non-http(s) verifier URL before fetching", async () => {
    const prev = process.env.TLSN_VERIFIER_URL;
    process.env.TLSN_VERIFIER_URL = "file:///etc/passwd";
    try {
      await expect(verifyPresentation({ presentation: "x", expectedDomain: "y" })).rejects.toThrow(
        /must use http/,
      );
      expect(fetchSpy).not.toHaveBeenCalled();
    } finally {
      process.env.TLSN_VERIFIER_URL = prev;
    }
  });
});

describe("validateTlsnVerifierConfig", () => {
  it("warns and does not throw when TLSN_VERIFIER_URL is unset", () => {
    const warnings: string[] = [];
    const result = validateTlsnVerifierConfig({}, (m) => warnings.push(m));
    expect(result.ok).toBe(false);
    expect(warnings.some((w) => /TLSN_VERIFIER_URL is unset/.test(w))).toBe(true);
  });

  it("warns when TLSN_VERIFIER_URL is not a valid URL", () => {
    const warnings: string[] = [];
    validateTlsnVerifierConfig({ TLSN_VERIFIER_URL: "not a url" }, (m) => warnings.push(m));
    expect(warnings.some((w) => /not a valid URL/.test(w))).toBe(true);
  });

  it("warns when the scheme is not http(s)", () => {
    const warnings: string[] = [];
    validateTlsnVerifierConfig({ TLSN_VERIFIER_URL: "file:///etc/passwd" }, (m) =>
      warnings.push(m),
    );
    expect(warnings.some((w) => /must use http/.test(w))).toBe(true);
  });

  it("warns that SSRF hardening is incomplete when the allowlist env is unset", () => {
    const warnings: string[] = [];
    const result = validateTlsnVerifierConfig(
      { TLSN_VERIFIER_URL: "https://verifier.internal:7048" },
      (m) => warnings.push(m),
    );
    expect(result.ok).toBe(false);
    expect(
      warnings.some((w) => /SSRF hardening INCOMPLETE/.test(w) && /not configured/.test(w)),
    ).toBe(true);
  });

  it("warns when the host is not in a configured allowlist", () => {
    const warnings: string[] = [];
    validateTlsnVerifierConfig(
      {
        TLSN_VERIFIER_URL: "https://evil.example:7048",
        MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS: "tlsn-verifier, verifier.internal",
      },
      (m) => warnings.push(m),
    );
    expect(warnings.some((w) => /not in MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS/.test(w))).toBe(true);
  });

  it("passes cleanly when the host is in the allowlist", () => {
    const warnings: string[] = [];
    const result = validateTlsnVerifierConfig(
      {
        TLSN_VERIFIER_URL: "https://verifier.internal:7048",
        MINISTER_TLSN_VERIFIER_ALLOWED_HOSTS: "verifier.internal, other.host",
      },
      (m) => warnings.push(m),
    );
    expect(result.ok).toBe(true);
    expect(warnings).toEqual([]);
  });

  it("never throws", () => {
    expect(() => validateTlsnVerifierConfig({ TLSN_VERIFIER_URL: "::::" }, () => {})).not.toThrow();
  });
});
