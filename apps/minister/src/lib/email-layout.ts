// Shared, email-client-safe layout for every transactional email Minister
// sends (sign-in, email verification, credential/merge notifications, account
// recovery, share links). One layout keeps every message on-brand and
// maintainable: change the shell here, every email follows.
//
// Design constraints (email clients are not browsers):
//   * Inline CSS is the baseline for everything visual. The one <style> block
//     is a progressive enhancement for dark mode only (prefers-color-scheme);
//     the email renders correctly with it stripped.
//   * Table-based container so Outlook's Word engine lays it out.
//   * max-width ~600px, centered, web-safe font stack with fallbacks.
//   * CTA is a table + bgcolor button with padding on the <td> (Outlook
//     ignores padding on <a>), so it renders as a solid button everywhere and
//     stays width-flexible for variable labels.
//
// Brand tokens are pulled straight from the site (Tailwind neutral scale used
// across globals.css, the Card, and the primary Button): monochrome neutral
// palette, near-black primary button, white card on a light-gray page.

// --- Brand tokens (Tailwind `neutral` scale + the site's primary button) ---
const LIGHT = {
  page: "#f5f5f5", // neutral-100
  card: "#ffffff",
  border: "#e5e5e5", // neutral-200
  text: "#171717", // neutral-900
  muted: "#525252", // neutral-600
  fine: "#737373", // neutral-500
  buttonBg: "#171717", // neutral-900 (primary button)
  buttonText: "#fafafa", // neutral-50
  codeBg: "#f5f5f5", // neutral-100
} as const;

// Multi-word family names use single quotes: these strings land inside
// double-quoted style="…" attributes, so double quotes would truncate them.
const FONT_SANS =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif";
const FONT_MONO =
  "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";

// HTML-escape text destined for element content. Realistic dynamic values
// (domains, email addresses, counts) never contain these characters, so this
// is behavior-preserving while closing off any stray markup.
function esc(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Escape a URL for an href attribute. Encodes `&` to `&amp;` (correct HTML;
// the parser turns it back into `&`, so the effective link is unchanged) and
// the quote/angle characters that would break the attribute.
function escAttr(url: string): string {
  return url
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// A body paragraph. Pass already-escaped/trusted inner HTML (use `emailText`
// for plain strings). `muted` renders secondary copy.
export function emailParagraph(innerHtml: string, opts?: { muted?: boolean }): string {
  const color = opts?.muted ? LIGHT.muted : LIGHT.text;
  const cls = opts?.muted ? "m-muted" : "m-text";
  return `<p class="${cls}" style="margin:0 0 16px;font-family:${FONT_SANS};font-size:15px;line-height:1.6;color:${color};">${innerHtml}</p>`;
}

// A body paragraph from a plain (untrusted) string — escaped for you.
export function emailText(text: string, opts?: { muted?: boolean }): string {
  return emailParagraph(esc(text), opts);
}

// Small print (expiry notes, "if this wasn't you" disclaimers).
export function emailFinePrint(text: string): string {
  return `<p class="m-fine" style="margin:20px 0 0;font-family:${FONT_SANS};font-size:12px;line-height:1.6;color:${LIGHT.fine};">${esc(text)}</p>`;
}

// Bulletproof CTA button. Table + bgcolor + padding-on-td renders as a solid,
// tappable button in Outlook, Gmail, Apple Mail, and mobile clients alike.
export function emailButton(label: string, url: string): string {
  const href = escAttr(url);
  return [
    `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:8px 0 20px;">`,
    `<tr>`,
    `<td class="m-btn" align="center" bgcolor="${LIGHT.buttonBg}" style="border-radius:8px;padding:13px 30px;">`,
    `<a href="${href}" target="_blank" class="m-btn-a" style="display:inline-block;font-family:${FONT_SANS};font-size:15px;font-weight:600;line-height:1;color:${LIGHT.buttonText};text-decoration:none;">${esc(label)}</a>`,
    `</td>`,
    `</tr>`,
    `</table>`,
  ].join("");
}

// The raw link under a CTA, for clients that don't render the button or users
// who prefer to copy it. Shown small and muted.
export function emailLinkFallback(url: string): string {
  const href = escAttr(url);
  return `<p class="m-fine" style="margin:0 0 20px;font-family:${FONT_SANS};font-size:12px;line-height:1.5;color:${LIGHT.fine};word-break:break-all;">Or paste this link into your browser:<br/><a href="${href}" target="_blank" class="m-link" style="color:${LIGHT.muted};">${esc(url)}</a></p>`;
}

// An inline text link (for notification emails that point at a settings page
// rather than carrying a one-time action token).
export function emailInlineLink(label: string, url: string): string {
  return `<a href="${escAttr(url)}" class="m-link" style="color:${LIGHT.muted};text-decoration:underline;">${esc(label)}</a>`;
}

// A one-time code, shown large, monospace, and letter-spaced so it's easy to
// read and type from a phone.
export function emailCode(code: string): string {
  return [
    `<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 20px;">`,
    `<tr>`,
    `<td class="m-code" align="center" bgcolor="${LIGHT.codeBg}" style="border-radius:8px;border:1px solid ${LIGHT.border};padding:18px 12px;font-family:${FONT_MONO};font-size:32px;font-weight:700;letter-spacing:8px;color:${LIGHT.text};">${esc(code)}</td>`,
    `</tr>`,
    `</table>`,
  ].join("");
}

// Assemble a full email document from a heading and a list of pre-rendered
// content blocks (paragraphs, buttons, codes, fine print).
export function renderEmail(opts: { title: string; heading: string; blocks: string[] }): string {
  const preheader = esc(opts.title);
  const body = opts.blocks.join("\n");
  return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="color-scheme" content="light dark"/>
<meta name="supported-color-schemes" content="light dark"/>
<title>${preheader}</title>
<style>
  /* Dark mode is a progressive enhancement over the inline light defaults. */
  @media (prefers-color-scheme: dark) {
    body, .m-page { background:#0a0a0a !important; }
    .m-card { background:#171717 !important; border-color:#262626 !important; }
    .m-wordmark, .m-heading, .m-text { color:#fafafa !important; }
    .m-muted { color:#a3a3a3 !important; }
    .m-fine, .m-footer { color:#8a8a8a !important; }
    .m-code { background:#0a0a0a !important; border-color:#262626 !important; color:#fafafa !important; }
    .m-btn { background:#fafafa !important; }
    .m-btn-a { color:#171717 !important; }
    .m-link { color:#d4d4d4 !important; }
    .m-divider { border-color:#262626 !important; }
  }
  a { color:${LIGHT.text}; }
</style>
</head>
<body class="m-page" style="margin:0;padding:0;width:100%;background:${LIGHT.page};-webkit-font-smoothing:antialiased;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${preheader}</div>
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background:${LIGHT.page};">
<tr>
<td align="center" style="padding:32px 16px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="600" style="width:100%;max-width:600px;">
<!-- Header / wordmark -->
<tr>
<td style="padding:4px 8px 20px;">
<span class="m-wordmark" style="font-family:${FONT_SANS};font-size:20px;font-weight:600;letter-spacing:-0.02em;color:${LIGHT.text};">Minister</span>
</td>
</tr>
<!-- Card -->
<tr>
<td class="m-card" bgcolor="${LIGHT.card}" style="background:${LIGHT.card};border:1px solid ${LIGHT.border};border-radius:12px;padding:32px;">
<h1 class="m-heading" style="margin:0 0 20px;font-family:${FONT_SANS};font-size:20px;font-weight:600;line-height:1.3;letter-spacing:-0.01em;color:${LIGHT.text};">${esc(opts.heading)}</h1>
${body}
</td>
</tr>
<!-- Footer -->
<tr>
<td style="padding:24px 8px 0;">
<hr class="m-divider" style="border:none;border-top:1px solid ${LIGHT.border};margin:0 0 16px;"/>
<p class="m-footer" style="margin:0;font-family:${FONT_SANS};font-size:12px;line-height:1.6;color:${LIGHT.fine};">Minister — your verifiable identity, your terms.<br/>You received this because someone used this address on Minister.</p>
</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>`;
}
