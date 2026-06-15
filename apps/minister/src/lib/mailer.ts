import { appendFileSync } from "node:fs";

import type { MailMessage } from "@minister/plugin-sdk";

// Single point of email egress for the app. Everything that sends mail
// — Auth.js sign-in magic links, the email-domain plugin, share-link
// emails — routes through sendMail so there's exactly one transport to
// configure and one place that can leak link tokens.
//
// Transport selection:
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
  return Boolean(process.env.RESEND_API_KEY && process.env.MAIL_FROM);
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

  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.MAIL_FROM;
  if (apiKey && from) {
    await sendViaResend(message, apiKey, from);
    return;
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "No mail transport is configured. Set RESEND_API_KEY and MAIL_FROM to send via Resend, or wire another transport in apps/minister/src/lib/mailer.ts.",
    );
  }

  // Dev/test fallback: print to the server log so magic links remain
  // clickable without a relay.
  console.log(
    `\n[minister:mailer] -> ${message.to}\n  Subject: ${message.subject}\n  ${message.text.split("\n").join("\n  ")}\n`,
  );
}
