// Server-side image validation for avatar uploads. Pure and dependency-free
// (no "use server", no Prisma, no node: imports beyond Buffer typing), so the
// upload action imports it and a unit test can exercise it without a database.
//
// SECURITY: this is the whole trust boundary for uploaded bytes. We never trust
// the browser's declared MIME type (a client sets it freely) and we never
// re-encode. Instead we SNIFF the leading bytes (the file's magic number) and
// accept ONLY the three raster formats below. SVG is rejected on purpose — it is
// XML that can carry <script>, so serving a stored SVG inline would be a
// stored-XSS vector. The serve route additionally sends `X-Content-Type-Options:
// nosniff` so a browser can't re-interpret the bytes as something executable.

// The only content types an avatar may be stored and served as. Kept as a
// readonly tuple so both the sniffer and the serve route share one list.
export const ALLOWED_AVATAR_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export type AllowedAvatarType = (typeof ALLOWED_AVATAR_TYPES)[number];

// Hard cap on a stored avatar. 512 KB is generous for a profile photo and small
// enough that a bytea blob stays cheap. Enforced in the action BEFORE this
// sniff, and worth stating here as the shared contract.
export const MAX_AVATAR_BYTES = 512 * 1024;

export function isAllowedAvatarType(value: string): value is AllowedAvatarType {
  return (ALLOWED_AVATAR_TYPES as readonly string[]).includes(value);
}

// Does `bytes` start with `sig` at `offset`? Bounds-checked so a truncated
// upload (fewer bytes than the signature) simply fails to match rather than
// reading past the end.
function matchesAt(bytes: Uint8Array, sig: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (bytes[offset + i] !== sig[i]) return false;
  }
  return true;
}

// PNG:  89 50 4E 47 0D 0A 1A 0A  (the 8-byte signature)
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
// JPEG: FF D8 FF  (SOI marker + first marker byte)
const JPEG_SIG = [0xff, 0xd8, 0xff];
// WebP: "RIFF" ???? "WEBP"  — a RIFF container whose form type is WEBP. The
// four size bytes at offset 4 vary, so we match "RIFF" at 0 and "WEBP" at 8.
const RIFF_SIG = [0x52, 0x49, 0x46, 0x46]; // "RIFF"
const WEBP_SIG = [0x57, 0x45, 0x42, 0x50]; // "WEBP"

// Sniff the true image type from the leading bytes, or null if the bytes are
// not one of the three allowed formats. This is the authoritative type — the
// caller stores exactly what this returns, never the client's declared MIME.
export function sniffAvatarType(bytes: Uint8Array): AllowedAvatarType | null {
  if (matchesAt(bytes, PNG_SIG)) return "image/png";
  if (matchesAt(bytes, JPEG_SIG)) return "image/jpeg";
  if (matchesAt(bytes, RIFF_SIG) && matchesAt(bytes, WEBP_SIG, 8)) return "image/webp";
  return null;
}

// Result of fully validating an uploaded avatar's bytes + declared type.
export type AvatarValidation =
  { ok: true; contentType: AllowedAvatarType } | { ok: false; error: string };

// The complete server-side gate for one upload. Order matters: reject empty and
// oversize first (cheap, and avoids sniffing attacker-controlled megabytes),
// then sniff. If the client DECLARED one of the allowed types, it must agree
// with what we sniffed — a PNG-declared file whose bytes are JPEG (or anything
// else) is rejected as a mismatch. A blank/other declared type is ignored; the
// sniffed type wins. The stored contentType is always the sniffed one.
export function validateAvatarBytes(bytes: Uint8Array, declaredType: string): AvatarValidation {
  if (bytes.length === 0) {
    return { ok: false, error: "That file is empty." };
  }
  if (bytes.length > MAX_AVATAR_BYTES) {
    return { ok: false, error: "That image is over 512 KB. Pick a smaller one." };
  }
  const sniffed = sniffAvatarType(bytes);
  if (sniffed === null) {
    return { ok: false, error: "Only PNG, JPEG, or WebP images are allowed." };
  }
  // If the browser declared a supported type, it must match the real bytes.
  // (An unrecognized/blank declared type is not trusted either way — the sniff
  // is authoritative — so we only reject on an explicit, contradictory claim.)
  const declared = declaredType.trim().toLowerCase();
  if (isAllowedAvatarType(declared) && declared !== sniffed) {
    return { ok: false, error: "That file's contents do not match its type." };
  }
  return { ok: true, contentType: sniffed };
}
