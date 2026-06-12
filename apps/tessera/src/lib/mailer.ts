import { appendFileSync } from "node:fs";

import type { MailMessage } from "@tessera/plugin-sdk";

// e2e hook: when TESSERA_MAIL_CAPTURE_FILE is set (never in
// production), every outbound message is appended as a JSON line so
// the Playwright suite can read magic links instead of scraping the
// server log. The auth.ts ConsoleEmail provider routes through
// captureAuthMail for the same reason.
function capture(message: MailMessage): void {
  const file = process.env.TESSERA_MAIL_CAPTURE_FILE;
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

export function captureAuthMail(to: string, url: string): void {
  capture({ to, subject: "Sign in to Tessera", text: url });
}

// Single point of email egress for the app. Stage 0/1: console log in
// dev. Stage 9+: swap in Resend/SES based on env. Plugins must use this
// (via PluginContext.sendMail) so they don't grow their own transports.
export async function sendMail(message: MailMessage): Promise<void> {
  // No production transport wired yet. Logging both prod and dev would
  // leak link tokens — refuse to "send" in prod to make this loud.
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "Production mail transport is not configured. Set up Resend/SES in apps/tessera/src/lib/mailer.ts before going live.",
    );
  }

  capture(message);

  console.log(
    `\n[tessera:mailer] -> ${message.to}\n  Subject: ${message.subject}\n  ${message.text.split("\n").join("\n  ")}\n`,
  );
}
