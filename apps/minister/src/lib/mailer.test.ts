import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { mailTransportConfigured, sendMail } from "./mailer";

// Mock nodemailer's lazy `await import("nodemailer")`. vi.hoisted lets the
// mock factory (which is hoisted above the imports) share these spies with the
// test body.
const { createTransportMock, smtpSendMailMock } = vi.hoisted(() => {
  const smtpSendMailMock = vi.fn();
  const createTransportMock = vi.fn(() => ({ sendMail: smtpSendMailMock }));
  return { createTransportMock, smtpSendMailMock };
});
vi.mock("nodemailer", () => ({
  default: { createTransport: createTransportMock },
}));

const ORIGINAL = {
  NODE_ENV: process.env.NODE_ENV,
  SMTP_URL: process.env.SMTP_URL,
  RESEND_API_KEY: process.env.RESEND_API_KEY,
  MAIL_FROM: process.env.MAIL_FROM,
  CAPTURE: process.env.MINISTER_MAIL_CAPTURE_FILE,
};

function setEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete (process.env as Record<string, string | undefined>)[name];
  } else {
    (process.env as Record<string, string>)[name] = value;
  }
}

describe("sendMail", () => {
  const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);

  beforeEach(() => {
    logSpy.mockClear();
    createTransportMock.mockClear();
    smtpSendMailMock.mockReset();
    // Each test starts from a clean transport config; the capture hook
    // is disabled so it doesn't try to write a file.
    setEnv("SMTP_URL", undefined);
    setEnv("RESEND_API_KEY", undefined);
    setEnv("MAIL_FROM", undefined);
    setEnv("MINISTER_MAIL_CAPTURE_FILE", undefined);
    setEnv("NODE_ENV", "development");
  });

  afterEach(() => {
    setEnv("NODE_ENV", ORIGINAL.NODE_ENV);
    setEnv("SMTP_URL", ORIGINAL.SMTP_URL);
    setEnv("RESEND_API_KEY", ORIGINAL.RESEND_API_KEY);
    setEnv("MAIL_FROM", ORIGINAL.MAIL_FROM);
    setEnv("MINISTER_MAIL_CAPTURE_FILE", ORIGINAL.CAPTURE);
    vi.unstubAllGlobals();
  });

  it("logs to stdout in non-production when no transport is configured", async () => {
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

  it("refuses to send (no silent log) in production without a transport", async () => {
    setEnv("NODE_ENV", "production");
    await expect(
      sendMail({ to: "alice@example.com", subject: "hi", text: "body" }),
    ).rejects.toThrow(/No mail transport is configured/);
    expect(logSpy).not.toHaveBeenCalled();
  });

  describe("SMTP transport", () => {
    const SMTP_URL = "smtps://user:pass@email-smtp.us-east-1.amazonaws.com:465";

    beforeEach(() => {
      setEnv("SMTP_URL", SMTP_URL);
      setEnv("MAIL_FROM", "Minister <noreply@example.com>");
    });

    it("creates a transport from SMTP_URL and sends with the right from/to/subject/text", async () => {
      await sendMail({
        to: "bob@example.com",
        subject: "Verify",
        text: "click here",
        html: "<p>click here</p>",
      });

      expect(logSpy).not.toHaveBeenCalled(); // real transport, no console fallback
      expect(createTransportMock).toHaveBeenCalledTimes(1);
      expect(createTransportMock).toHaveBeenCalledWith(SMTP_URL);
      expect(smtpSendMailMock).toHaveBeenCalledTimes(1);
      expect(smtpSendMailMock).toHaveBeenCalledWith({
        from: "Minister <noreply@example.com>",
        to: "bob@example.com",
        subject: "Verify",
        text: "click here",
        html: "<p>click here</p>",
      });
    });

    it("omits html when not provided", async () => {
      await sendMail({ to: "c@example.com", subject: "s", text: "t" });
      const arg = smtpSendMailMock.mock.calls[0]![0] as Record<string, unknown>;
      expect(arg).not.toHaveProperty("html");
    });

    it("wins over Resend when both are configured (no Resend fetch)", async () => {
      setEnv("RESEND_API_KEY", "re_test_key");
      const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      await sendMail({ to: "bob@example.com", subject: "s", text: "t" });

      expect(smtpSendMailMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("throws a clear error when SMTP_URL is set but MAIL_FROM is not", async () => {
      setEnv("MAIL_FROM", undefined);
      await expect(sendMail({ to: "bob@example.com", subject: "s", text: "t" })).rejects.toThrow(
        /SMTP_URL is set but MAIL_FROM is not/,
      );
      expect(createTransportMock).not.toHaveBeenCalled();
    });

    it("lets a nodemailer send failure propagate", async () => {
      smtpSendMailMock.mockRejectedValueOnce(new Error("535 auth failed"));
      await expect(sendMail({ to: "bob@example.com", subject: "s", text: "t" })).rejects.toThrow(
        /535 auth failed/,
      );
    });

    it("prefers SMTP over the production throw", async () => {
      setEnv("NODE_ENV", "production");
      await expect(
        sendMail({ to: "e@example.com", subject: "s", text: "t" }),
      ).resolves.toBeUndefined();
      expect(smtpSendMailMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("Resend transport", () => {
    beforeEach(() => {
      setEnv("RESEND_API_KEY", "re_test_key");
      setEnv("MAIL_FROM", "Minister <noreply@example.com>");
    });

    it("POSTs the message to the Resend API with auth + correct shape", async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValue(new Response(JSON.stringify({ id: "abc" }), { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      await sendMail({
        to: "bob@example.com",
        subject: "Verify",
        text: "click here",
        html: "<p>click here</p>",
      });

      expect(logSpy).not.toHaveBeenCalled(); // real transport, no console fallback
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0]!;
      expect(url).toBe("https://api.resend.com/emails");
      expect(init.method).toBe("POST");
      expect(init.headers.Authorization).toBe("Bearer re_test_key");
      const body = JSON.parse(init.body as string);
      expect(body).toEqual({
        from: "Minister <noreply@example.com>",
        to: ["bob@example.com"],
        subject: "Verify",
        text: "click here",
        html: "<p>click here</p>",
      });
    });

    it("omits html when not provided", async () => {
      const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      await sendMail({ to: "c@example.com", subject: "s", text: "t" });
      const body = JSON.parse(fetchMock.mock.calls[0]![1].body as string);
      expect(body).not.toHaveProperty("html");
    });

    it("throws with Resend's error detail on a non-2xx (e.g. unverified domain)", async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValue(new Response("The example.com domain is not verified", { status: 403 }));
      vi.stubGlobal("fetch", fetchMock);

      await expect(sendMail({ to: "d@example.com", subject: "s", text: "t" })).rejects.toThrow(
        /Resend send failed \(HTTP 403\): The example.com domain is not verified/,
      );
    });

    it("prefers Resend over the production throw", async () => {
      setEnv("NODE_ENV", "production");
      const fetchMock = vi.fn().mockResolvedValue(new Response("{}", { status: 200 }));
      vi.stubGlobal("fetch", fetchMock);

      await expect(
        sendMail({ to: "e@example.com", subject: "s", text: "t" }),
      ).resolves.toBeUndefined();
      expect(fetchMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("mailTransportConfigured", () => {
    it("is true only when both Resend key and from are set", () => {
      expect(mailTransportConfigured()).toBe(false);
      setEnv("RESEND_API_KEY", "re_x");
      expect(mailTransportConfigured()).toBe(false);
      setEnv("MAIL_FROM", "x@y.z");
      expect(mailTransportConfigured()).toBe(true);
    });

    it("is true when SMTP_URL is set (regardless of Resend)", () => {
      expect(mailTransportConfigured()).toBe(false);
      setEnv("SMTP_URL", "smtps://user:pass@host:465");
      expect(mailTransportConfigured()).toBe(true);
    });
  });
});
