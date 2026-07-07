import { z } from "zod";

// Pure validation for the profile editor. Deliberately NOT "use server" —
// unlike profile-actions.ts, this module has no session/Prisma dependency,
// so it (and its test) can import plain Node without dragging in the
// next-auth/next/server module chain that "use server" actions carry.
// Mirrors the oidc-consent-minimize.ts split (pure helper vs. the "use
// server" action file that calls it).

export const MAX_DISPLAY_NAME_LENGTH = 80;
export const MAX_AVATAR_URL_LENGTH = 2048;

// Strips C0/C1 control characters and line breaks a user could paste into a
// plain-text input (e.g. from a compromised clipboard or a copy-pasted
// script). Built from char codes rather than a literal escape range so the
// pattern can't be silently corrupted by an editor normalizing whitespace.
function stripControlChars(value: string): string {
  let out = "";
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    const isC0 = code <= 0x1f;
    const isDel = code === 0x7f;
    const isC1 = code >= 0x80 && code <= 0x9f;
    if (!isC0 && !isDel && !isC1) out += ch;
  }
  return out;
}

// Only https: is allowed — this value is rendered as an `<img src>` in the
// public profile, /u/[userId], and the consent screen, so accepting http:,
// data:, javascript:, blob:, or a relative path would open mixed-content or
// script-injection surface. Rejecting everything but https: is deliberate
// and not merely a default.
function normalizeAvatarUrl(raw: string): string | null {
  // Strip C0/C1/DEL control chars BEFORE parsing: the WHATWG URL parser
  // silently ignores tab, CR, and LF while parsing, so a URL with an embedded
  // "\r\n" or "\t" would validate as https: yet carry those control chars into
  // the rendered `<img src>` and the disclosed `picture` claim (a header /
  // log-injection surface). Strip first, then validate + return the stripped
  // value so what we validate is exactly what we persist and disclose.
  const cleaned = stripControlChars(raw).trim();
  if (cleaned.length === 0) return null;
  if (cleaned.length > MAX_AVATAR_URL_LENGTH) {
    throw new Error(`Avatar URL must be ${MAX_AVATAR_URL_LENGTH} characters or fewer`);
  }

  let parsed: URL;
  try {
    parsed = new URL(cleaned);
  } catch {
    throw new Error("Avatar URL must be a valid absolute URL");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("Avatar URL must use https:");
  }
  return cleaned;
}

function normalizeDisplayName(raw: string): string | null {
  const cleaned = stripControlChars(raw).trim();
  if (cleaned.length === 0) return null;
  if (cleaned.length > MAX_DISPLAY_NAME_LENGTH) {
    throw new Error(`Display name must be ${MAX_DISPLAY_NAME_LENGTH} characters or fewer`);
  }
  return cleaned;
}

const UpdateProfileInput = z.object({
  displayName: z.string(),
  avatarUrl: z.string(),
});

export type UpdateProfileInput = z.infer<typeof UpdateProfileInput>;

// Pure — no Prisma/session dependency — so validation is unit-testable
// without a database. Throws a plain Error with a user-safe message on
// invalid input; the client renders `error.message` directly.
export function normalizeProfileInput(raw: UpdateProfileInput): {
  displayName: string | null;
  avatarUrl: string | null;
} {
  const parsed = UpdateProfileInput.parse(raw);
  return {
    displayName: normalizeDisplayName(parsed.displayName),
    avatarUrl: normalizeAvatarUrl(parsed.avatarUrl),
  };
}
