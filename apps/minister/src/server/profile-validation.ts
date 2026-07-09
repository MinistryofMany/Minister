import { z } from "zod";

// Pure validation for the profile editors. Deliberately NOT "use server" —
// unlike profile-actions.ts, this module has no session/Prisma dependency,
// so it (and its test) can import plain Node without dragging in the
// next-auth/next/server module chain that "use server" actions carry.
// Mirrors the oidc-consent-minimize.ts split (pure helper vs. the "use
// server" action file that calls it).
//
// Two entry points:
//   - normalizeProfileInput       — the legacy { displayName, avatarUrl }
//     free-text shape, still used by the per-RP persona editor
//     (rp-profile-actions) and consent seeding (oidc-actions). Empty avatar
//     URL -> null (clears the field).
//   - normalizeProfileEditorInput — the main /profile editor's three-way
//     avatar selection (deterministic | gravatar | url).

export const MAX_DISPLAY_NAME_LENGTH = 80;
export const MAX_AVATAR_URL_LENGTH = 2048;
export const MAX_EMAIL_LENGTH = 254;

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
// and not merely a default. Empty -> null (the caller decides what that means:
// "clear the field" for the persona editor, an error for the URL avatar kind).
function normalizeAvatarUrlOrNull(raw: string): string | null {
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

// Conservative shape check + normalization for the Gravatar email. The action
// re-checks that this address is actually PROVEN on the account before building
// a Gravatar URL from it — this only rejects obvious garbage and normalizes the
// address the same way Gravatar hashes it (trim + lowercase).
function normalizeGravatarEmail(raw: string): string {
  const cleaned = stripControlChars(raw).trim().toLowerCase();
  if (cleaned.length === 0) {
    throw new Error("Choose which verified email to use for your Gravatar");
  }
  if (cleaned.length > MAX_EMAIL_LENGTH) {
    throw new Error("That email address is too long");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleaned)) {
    throw new Error("Choose a valid verified email for your Gravatar");
  }
  return cleaned;
}

// -------------------------------------------------------------------------
// Legacy free-text shape (per-RP persona editor + consent seeding).
// -------------------------------------------------------------------------

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
    avatarUrl: normalizeAvatarUrlOrNull(parsed.avatarUrl),
  };
}

// -------------------------------------------------------------------------
// Main /profile editor: a tagged three-way avatar selection.
// -------------------------------------------------------------------------

// The avatar sources, tagged so the editor and the action share one wire shape.
// `deterministic` carries no value (the generated identicon has no stored URL —
// a null avatarUrl IS the deterministic case). `gravatar` carries the chosen
// email; the action verifies it and derives the URL server-side. `url` carries a
// free-text https URL. `uploaded` carries NO value and means "keep the photo the
// user already uploaded" — a NEW upload goes through uploadAvatarAction (which
// stores the blob and sets the serve-route avatarUrl), so through this editor
// path `uploaded` only ever preserves the existing avatarUrl while the display
// name is edited. It can therefore never inject a client-chosen URL.
const AvatarSelection = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("deterministic") }),
  z.object({ kind: z.literal("gravatar"), email: z.string() }),
  z.object({ kind: z.literal("url"), url: z.string() }),
  z.object({ kind: z.literal("uploaded") }),
]);

const ProfileEditorInput = z.object({
  displayName: z.string(),
  avatar: AvatarSelection,
});

export type ProfileEditorInput = z.infer<typeof ProfileEditorInput>;

// The normalized avatar the action resolves to a stored avatarUrl:
//   - deterministic -> store null (the identicon renders from the user id)
//   - url           -> store the validated https URL
//   - gravatar      -> the action verifies the email is proven, then stores
//                      gravatarUrl(email); we can't do that here (no DB), so we
//                      hand back the normalized email for the action to finish.
export type NormalizedAvatar =
  | { kind: "deterministic" }
  | { kind: "url"; url: string }
  | { kind: "gravatar"; email: string }
  | { kind: "uploaded" };

export function normalizeProfileEditorInput(raw: ProfileEditorInput): {
  displayName: string | null;
  avatar: NormalizedAvatar;
} {
  const parsed = ProfileEditorInput.parse(raw);
  const displayName = normalizeDisplayName(parsed.displayName);

  let avatar: NormalizedAvatar;
  switch (parsed.avatar.kind) {
    case "deterministic":
      avatar = { kind: "deterministic" };
      break;
    case "url": {
      const url = normalizeAvatarUrlOrNull(parsed.avatar.url);
      if (url === null) {
        throw new Error("Enter an image link, or choose a different avatar option");
      }
      avatar = { kind: "url", url };
      break;
    }
    case "gravatar":
      avatar = { kind: "gravatar", email: normalizeGravatarEmail(parsed.avatar.email) };
      break;
    case "uploaded":
      // No value to normalize — the action keeps the existing uploaded avatar.
      avatar = { kind: "uploaded" };
      break;
  }

  return { displayName, avatar };
}
