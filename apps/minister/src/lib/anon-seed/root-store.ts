import { ROOT_SEED_BYTES } from "@minister/shared";

// The anon-identity ROOT store (identity plan, Lane C). This is the ONLY module
// in the tree permitted to name `indexedDB` — the anon-seed invariants test
// allowlists exactly this file and bans it everywhere else.
//
// WHY IndexedDB, not string-based storage: a JS string is interned and cannot be
// zeroized, so the root would live forever in an immortal heap string. IndexedDB
// stores raw bytes via structured clone, so the value stays a Uint8Array that
// .fill(0) clears. At rest both are equally plaintext and script-readable — which
// is exactly why the site-wide strict CSP (Lane B) is a precondition of this
// store, not a follow-up.
//
// WHY raw bytes, not a non-extractable CryptoKey: QR pairing and the 28-char
// backup string both need the 16 root bytes exported. A non-extractable key that
// must be exported is a contradiction, so the store rejects a CryptoKey outright.
//
// GOVERNING INVARIANT: this module persists the root only to the user's OWN
// origin storage, one record per userId. It NEVER transmits it — no network
// transport of any kind lives here (enforced by the anon-seed invariants test).
// Ministry's server holds nothing derived from the root.

const DB_NAME = "ministry-anon-root";
const STORE_NAME = "root";
const DB_VERSION = 1;

/** What the store hands back: the raw root plus the epoch it was enrolled at. */
export interface StoredRoot {
  root: Uint8Array;
  epoch: number;
}

interface RootRecord {
  userId: string;
  root: Uint8Array;
  epoch: number;
}

/** IndexedDB is absent under SSR, in Node, and in jsdom: the store degrades to
 * memory-only (the root simply is not persisted), never an error. */
function idbAvailable(): boolean {
  return typeof indexedDB !== "undefined";
}

function assertRootBytes(root: Uint8Array): void {
  // Reject a CryptoKey (or anything else) that is not raw bytes: the store's
  // whole contract is exportable material.
  if (!(root instanceof Uint8Array)) {
    throw new TypeError("root must be raw Uint8Array bytes, not a CryptoKey");
  }
  if (root.length !== ROOT_SEED_BYTES) {
    throw new RangeError(`root must be exactly ${ROOT_SEED_BYTES} bytes, got ${root.length}`);
  }
}

function assertEpoch(epoch: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 1) {
    throw new RangeError(`epoch must be an integer >= 1, got ${epoch}`);
  }
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "userId" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB open failed"));
  });
}

function requestToPromise<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("indexedDB request failed"));
  });
}

/**
 * Persist the root for `userId`. Call this exactly when enrollment becomes
 * ACTIVE (identity plan): a mid-backup write must never happen, so nothing
 * orphans if the tab closes before backup. Stores a COPY, so a caller zeroizing
 * its own buffer afterwards does not wipe the stored bytes. No-op (resolves)
 * when IndexedDB is unavailable.
 */
export async function putRoot(userId: string, root: Uint8Array, epoch: number): Promise<void> {
  assertRootBytes(root);
  assertEpoch(epoch);
  if (userId.length === 0) throw new RangeError("userId must be non-empty");
  if (!idbAvailable()) return;
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const record: RootRecord = { userId, root: new Uint8Array(root), epoch };
    tx.objectStore(STORE_NAME).put(record);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("indexedDB write failed"));
      tx.onabort = () => reject(tx.error ?? new Error("indexedDB write aborted"));
    });
  } finally {
    db.close();
  }
}

/** Load the persisted root + enrollment epoch for `userId`, or null when none
 * is stored (or IndexedDB is unavailable). */
export async function getRoot(userId: string): Promise<StoredRoot | null> {
  if (userId.length === 0) throw new RangeError("userId must be non-empty");
  if (!idbAvailable()) return null;
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, "readonly");
    const record = await requestToPromise(
      tx.objectStore(STORE_NAME).get(userId) as IDBRequest<RootRecord | undefined>,
    );
    if (!record) return null;
    // Structured clone already gave us an independent Uint8Array; copy defensively.
    return { root: new Uint8Array(record.root), epoch: record.epoch };
  } finally {
    db.close();
  }
}

/**
 * Zeroize and delete the persisted root for `userId` (re-key / sign-out / reset).
 * Best-effort overwrite of the stored bytes before removal, then delete the row.
 * No-op when IndexedDB is unavailable.
 */
export async function deleteRoot(userId: string): Promise<void> {
  if (userId.length === 0) throw new RangeError("userId must be non-empty");
  if (!idbAvailable()) return;
  const db = await openDb();
  try {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const existing = await requestToPromise(
      store.get(userId) as IDBRequest<RootRecord | undefined>,
    );
    if (existing) {
      existing.root.fill(0);
      store.put(existing); // overwrite bytes at rest before removing the row
    }
    store.delete(userId);
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error("indexedDB delete failed"));
      tx.onabort = () => reject(tx.error ?? new Error("indexedDB delete aborted"));
    });
  } finally {
    db.close();
  }
}
