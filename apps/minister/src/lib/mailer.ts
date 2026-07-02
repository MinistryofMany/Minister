import { appendFileSync } from "node:fs";

import type { MailMessage } from "@minister/plugin-sdk";

// Single point of email egress for the app. Everything that sends mail
// — Auth.js sign-in magic links, the email-domain plugin, share-link
// emails — routes through sendMail so there's exactly one transport to
// configure and one place that can leak link tokens.
//
// Transport selection:
//   * SMTP_URL set                   → send via nodemailer over SMTP (any
//                                       SMTP provider, e.g. AWS SES). MAIL_FROM
//                                       is still required as the From address.
//   * RESEND_API_KEY + MAIL_FROM set → send via Resend's HTTP API.
//   * otherwise, dev/test            → print to the server log (links
//                                       stay clickable without a relay).
//   * otherwise, production          → throw (never silently drop mail).

// e2e hook: when MINISTER_MAIL_CAPTURE_FILE is set (never in
// production), every outbound message is appended as a JSON line so
// the Playwright suite can read magic links instead of scraping the
// server log.
function capture(message: MailMessage): void {
  const file = process.env.MINISTER_MAIL_CAPTURE_FILE;
  if (!file || process.env.NODE_ENV === "production") return;
  appendFileSync(
    file,
    JSON.stringify({
      ts: Date.now(),
      to: message.to,
      subject: message.subject,
      text: message.text,
    }) + "\n",
  );
}

// True when a real transport is configured. Handy for surfacing
// "magic link printed to the server log" vs "check your inbox" copy.
export function mailTransportConfigured(): boolean {
  return Boolean(process.env.SMTP_URL || (process.env.RESEND_API_KEY && process.env.MAIL_FROM));
}

// Generic SMTP transport via nodemailer. Works with any SMTP relay (AWS SES,
// Postmark, a self-hosted MTA, …). nodemailer is lazy-imported so it stays out
// of the bundle for deployments that never set SMTP_URL. `from` must be a
// From address the relay is allowed to send as, e.g. "Minister <noreply@your.domain>".
async function sendViaSmtp(message: MailMessage, smtpUrl: string, from: string): Promise<void> {
  const { default: nodemailer } = await import("nodemailer");
  const transport = nodemailer.createTransport(smtpUrl);
  // nodemailer rejects on connection/auth/send failure; let it propagate so
  // misconfig is loud (the caller logs it server-side; it never reaches a user).
  await transport.sendMail({
    from,
    to: message.to,
    subject: message.subject,
    text: message.text,
    ...(message.html ? { html: message.html } : {}),
  });
}

// Resend HTTP transport. A single POST, so we use fetch rather than
// pulling in a dependency. `from` must be an address on a domain
// verified in the Resend account, e.g. "Minister <noreply@your.domain>".
async function sendViaResend(message: MailMessage, apiKey: string, from: string): Promise<void> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [message.to],
      subject: message.subject,
      text: message.text,
      ...(message.html ? { html: message.html } : {}),
    }),
  });
  if (!res.ok) {
    // Surface Resend's error body (e.g. unverified-domain) so misconfig
    // is loud. The caller logs this server-side; it never reaches a user.
    const detail = await res.text().catch(() => "");
    throw new Error(`Resend send failed (HTTP ${res.status}): ${detail}`);
  }
}

export async function sendMail(message: MailMessage): Promise<void> {
  // Offer the message to the e2e capture hook first (no-op unless the
  // capture-file env is set and we're not in production).
  capture(message);

  const smtpUrl = process.env.SMTP_URL;
  const from = process.env.MAIL_FROM;
  if (smtpUrl) {
    if (!from) {
      throw new Error(
        'SMTP_URL is set but MAIL_FROM is not. Set MAIL_FROM to the From address the SMTP relay may send as, e.g. "Minister <noreply@your.domain>".',
      );
    }
    await sendViaSmtp(message, smtpUrl, from);
    return;
  }

  const apiKey = process.env.RESEND_API_KEY;
  if (apiKey && from) {
    await sendViaResend(message, apiKey, from);
    return;
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "No mail transport is configured. Set SMTP_URL (+ MAIL_FROM) to send via SMTP, or RESEND_API_KEY and MAIL_FROM to send via Resend, or wire another transport in apps/minister/src/lib/mailer.ts.",
    );
  }

  // Dev/test fallback: print to the server log so magic links remain
  // clickable without a relay.
  console.log(
    `\n[minister:mailer] -> ${message.to}\n  Subject: ${message.subject}\n  ${message.text.split("\n").join("\n  ")}\n`,
  );
}
