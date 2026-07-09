import { createHash } from "node:crypto";

// Gravatar URL derivation. Server-only (uses node:crypto), so it is imported
// by the profile page (a server component) and the profile action — never by a
// client component.
//
// PRIVACY: a Gravatar URL embeds a STABLE hash of the user's email. Anyone who
// receives the URL (a relying party under the avatar grant, a viewer of the
// public profile) can test a guessed email against that hash, and two sites
// that both receive it can correlate the user by it. This is why the Gravatar
// option is strictly opt-in, offered only for an already-PROVEN email, and
// labeled as such in the editor. The caller is responsible for confirming the
// email is verified on the account before building the URL.

// Gravatar spec: hash the trimmed, lowercased email. We use SHA-256 (Gravatar's
// current recommendation); the legacy MD5 form is intentionally not offered.
export function gravatarHash(email: string): string {
  return createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
}

// `d=404` makes Gravatar return HTTP 404 (rather than a generated placeholder)
// when the email has no Gravatar, so the <img> onError handler can fall back to
// our own deterministic avatar instead of showing a stranger's placeholder art.
export function gravatarUrl(email: string): string {
  return `https://www.gravatar.com/avatar/${gravatarHash(email)}?d=404`;
}
