import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { TlsnVerifierError, verifyPresentation } from "./tlsn-verifier";

const ORIGINAL = process.env.TLSN_VERIFIER_URL;
beforeAll(() => {
  process.env.TLSN_VERIFIER_URL = "http://verifier.test:7048";
});
afterAll(() => {
  if (ORIGINAL === undefined) delete process.env.TLSN_VERIFIER_URL;
  else process.env.TLSN_VERIFIER_URL = ORIGINAL;
});

const fetchSpy = vi.spyOn(globalThis, "fetch");
beforeEach(() => fetchSpy.mockReset());
afterEach(() => fetchSpy.mockReset());

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
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ ok: false, error: "server name mismatch" }),
    );
    const promise = verifyPresentation({
      presentation: "x",
      expectedDomain: "y",
    });
    await expect(promise).rejects.toBeInstanceOf(TlsnVerifierError);
    // Re-mock and re-call to assert the message separately (each
    // verifyPresentation call consumes one fetch).
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ ok: false, error: "server name mismatch" }),
    );
    await expect(
      verifyPresentation({ presentation: "x", expectedDomain: "y" }),
    ).rejects.toThrow(/server name mismatch/);
  });

  it("throws on an unreachable verifier", async () => {
    fetchSpy.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    await expect(
      verifyPresentation({ presentation: "x", expectedDomain: "y" }),
    ).rejects.toThrow(/Could not reach/);
  });

  it("throws on a non-JSON response", async () => {
    fetchSpy.mockResolvedValueOnce(new Response("plain text", { status: 200 }));
    await expect(
      verifyPresentation({ presentation: "x", expectedDomain: "y" }),
    ).rejects.toThrow(/non-JSON/);
  });

  it("throws when the response shape doesn't match", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ unexpected: "shape" }));
    await expect(
      verifyPresentation({ presentation: "x", expectedDomain: "y" }),
    ).rejects.toThrow(/expected shape/);
  });
});
