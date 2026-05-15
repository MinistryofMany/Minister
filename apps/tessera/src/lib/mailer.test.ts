import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { sendMail } from "./mailer";

describe("sendMail", () => {
  const ORIGINAL = process.env.NODE_ENV;
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);

  beforeAll(() => {
    // jest/vitest default test env. We test prod by toggling.
  });

  afterEach(() => {
    logSpy.mockClear();
  });

  afterAll(() => {
    logSpy.mockRestore();
    if (ORIGINAL === undefined) {
      delete (process.env as Record<string, string | undefined>)["NODE_ENV"];
    } else {
      (process.env as Record<string, string>)["NODE_ENV"] = ORIGINAL;
    }
  });

  it("logs to stdout in non-production environments", async () => {
    // process.env.NODE_ENV is typed as a narrow union (next-env.d.ts).
    // The runtime is just an env var — use bracket access to bypass.
    (process.env as Record<string, string>)["NODE_ENV"] = "development";
    await sendMail({
      to: "alice@example.com",
      subject: "hi",
      text: "body line 1\nbody line 2",
    });
    expect(logSpy).toHaveBeenCalledTimes(1);
    const logged = logSpy.mock.calls[0]?.[0] as string;
    expect(logged).toContain("alice@example.com");
    expect(logged).toContain("Subject: hi");
    expect(logged).toContain("body line 1");
  });

  it("refuses to send (no silent log) in production", async () => {
    (process.env as Record<string, string>)["NODE_ENV"] = "production";
    await expect(
      sendMail({ to: "alice@example.com", subject: "hi", text: "body" }),
    ).rejects.toThrow(/transport is not configured/);
    expect(logSpy).not.toHaveBeenCalled();
  });
});
