// Badge-revocation status-list constants (docs/groups-revocation-design.md).
// One place so the publisher, the allocator, the route, and the tests can never
// drift on the load-bearing sizes and windows.

// Fixed shard size: 8,192 bits = 1 KiB raw (§5.3). Sized so the worst-case
// (incompressible) signed BitstringStatusListCredential stays under the KMS
// #key-2 RAW-sign 4,096-byte ceiling; a 16 Kib shard busts it.
export const SHARD_SIZE_BITS = 8192;
export const SHARD_SIZE_BYTES = SHARD_SIZE_BITS / 8; // 1024

// Open a fresh shard once the current one passes ~75% fill, to bound
// random-index allocation retries under contention (§5.2).
export const SHARD_FILL_THRESHOLD = 0.75;

// KMS `Sign` with MessageType=RAW caps the message at 4,096 bytes and Ed25519
// requires RAW (docs/kms-signing.md). The publisher HARD-asserts the JWS signing
// input is at or under this and refuses to publish otherwise (§5.3, auditor #11).
export const KMS_RAW_SIGN_MAX_BYTES = 4096;

// Publisher epoch: dirty lists republish at most this often (§5.5).
export const EPOCH_MS = 60_000; // 60s

// Signed-list validity window: the credential's `exp = iat + this`. A
// stale-served list is useful to an attacker for at most this long (§5.6.2).
export const VALIDITY_WINDOW_MS = 15 * 60_000; // 15 min

// Heartbeat: re-sign unchanged live lists this often so max-age never forces a
// long fail-open/closed limbo in a quiet period. VALIDITY_WINDOW / 3 (§5.5).
export const HEARTBEAT_MS = VALIDITY_WINDOW_MS / 3; // 5 min

// Per-(event, list) jitter ceiling: revealAfter = now + uniform(0, this),
// drawn independently per RP list, decorrelating one kick's publication instant
// across RPs (§5.7). Widening strengthens anti-correlation but slows revocation.
export const JITTER_MAX_MS = 4 * 60_000; // 4 min

// `ttl` refresh hint (ms) stamped in the credential — advisory per spec.
export const LIST_TTL_MS = 60_000;

// HTTP Cache-Control max-age (seconds) on the GET route (§5.5).
export const HTTP_MAX_AGE_SECONDS = 60;
