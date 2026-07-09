// Deterministic identicon-style avatar. Pure, dependency-free, and safe on
// both the server and the client (no node: imports), so the profile editor,
// the public profile, and any future render site all draw the SAME avatar for
// a given seed. The seed is a stable per-user value (the user id) — never PII —
// so the drawing leaks nothing about the person.
//
// This is DELIBERATELY not a "use server" module: it exports plain values
// (a pure function), which a "use server" file may not do. Keeping it here
// means both a server component and a client component can import it.
//
// Aesthetic: a jazzicon-style disc — a solid background plus a few rotated,
// translated color panels drawn from one harmonious palette, clipped to a
// circle. Small, boring in the nice sense, and recognizably distinct per user.

// Number of rotated color panels layered over the background. Four is the
// jazzicon default and reads well at both 24px (header) and 96px (profile).
const PANEL_COUNT = 4;

// A stable 32-bit hash of the seed (FNV-1a). Deterministic across engines —
// only integer ops, no locale/float dependence — so the same seed yields the
// same avatar on the server and in every browser.
function hashSeed(seed: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// mulberry32: a tiny, deterministic PRNG. Given the same 32-bit state it
// produces the same [0,1) stream everywhere, which is exactly what makes the
// avatar reproducible.
function mulberry32(state: number): () => number {
  let a = state >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Build a small analogous palette in HSL. Starting from one random base hue and
// walking it forward keeps the colors related (never a clashing random spray),
// which is what gives the boring-avatars / jazzicon look its calm.
function buildPalette(rand: () => number): string[] {
  const baseHue = Math.floor(rand() * 360);
  const palette: string[] = [];
  for (let i = 0; i < PANEL_COUNT + 1; i++) {
    const hue = Math.floor((baseHue + i * (rand() * 45 + 20)) % 360);
    const sat = 55 + Math.floor(rand() * 30); // 55-85%
    const light = 45 + Math.floor(rand() * 25); // 45-70%
    palette.push(`hsl(${hue}, ${sat}%, ${light}%)`);
  }
  return palette;
}

// Generate the avatar as a self-contained SVG string. `size` sets the viewBox
// (the SVG scales to whatever box it is rendered in; size only affects the
// coordinate space, so the output stays crisp at any display size).
export function generateAvatarSvg(seed: string, size = 100): string {
  const rand = mulberry32(hashSeed(seed));
  const palette = buildPalette(rand);
  const center = size / 2;

  const panels: string[] = [];
  for (let i = 0; i < PANEL_COUNT; i++) {
    const color = palette[i + 1] ?? palette[0]!;
    // Translate each full-size panel by up to ±half the box and rotate it, so
    // the overlapping edges cut the characteristic jazzicon facets.
    const tx = Math.floor(rand() * size - center);
    const ty = Math.floor(rand() * size - center);
    const rot = Math.floor(rand() * 360);
    panels.push(
      `<rect x="0" y="0" width="${size}" height="${size}" fill="${color}" ` +
        `transform="translate(${tx} ${ty}) rotate(${rot} ${center} ${center})"/>`,
    );
  }

  const clipId = "c"; // scoped by the surrounding <svg>; a fixed id is fine
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" ` +
    `width="${size}" height="${size}" role="img" aria-hidden="true">` +
    `<defs><clipPath id="${clipId}"><circle cx="${center}" cy="${center}" r="${center}"/></clipPath></defs>` +
    `<g clip-path="url(#${clipId})">` +
    `<rect x="0" y="0" width="${size}" height="${size}" fill="${palette[0]}"/>` +
    panels.join("") +
    `</g></svg>`
  );
}

// The same avatar as a `data:` URI, ready to drop into an <img src>. Used for
// on-page rendering only — never disclosed as an OIDC `picture` claim (a
// deterministic avatar has no external URL, so `picture` is simply omitted;
// see oidc-claims.ts).
export function avatarDataUri(seed: string, size = 100): string {
  return `data:image/svg+xml,${encodeURIComponent(generateAvatarSvg(seed, size))}`;
}
