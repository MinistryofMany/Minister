import type { MailMessage } from "@tessera/plugin-sdk";

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

  console.log(
    `\n[tessera:mailer] -> ${message.to}\n  Subject: ${message.subject}\n  ${message.text.split("\n").join("\n  ")}\n`,
  );
}
