import { createHmac, hkdfSync, randomBytes } from "node:crypto";

import { EvaluationRequest, Oprf, VOPRFServer, deriveKeyPair } from "@cloudflare/voprf-ts";
import { CryptoNoble } from "@cloudflare/voprf-ts/crypto-noble";

import { lp, lpStr } from "./encoding";
import type { SignetResponse, SignetTransport } from "./signet-backend";

// In-memory scripted Signet for the OFFLINE unit suite (no network, no mTLS).
// Implements the exact /prf + /dedup wire of Signet/src/handlers.rs on top of
// a REAL voprf-ts VOPRF server derived from a caller-supplied master seed via
// the frozen key schedule (Signet/src/prf.rs):
//
//   seed_null = HKDF-SHA512(ikm=master_seed, salt="", info="minister/v1/nullifier", 32)
//   (skS,pkS) = DeriveKeyPair(seed_null, "minister/v1/nullifier/dedup")
//
// Built from the frozen test master seed (prf-vectors.json) it therefore
// reproduces the frozen ecosystem vector bytes, so the offline suite can
// assert the same N_dedup/N_rp values the cross-language interop jobs pin.
// Test-only: imported exclusively by *.test.ts files.

const SUITE = Oprf.Suite.RISTRETTO255_SHA512;

function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

// Stage-2 disclose, reproduced with Node crypto exactly as Signet computes it
// (and as Signet/interop/prf.mjs cross-checks it):
//   k_disc = HKDF-SHA512(master_seed, "", "minister/v1/nullifier/disclose" || LP(clientId), 32)
//   N_rp   = "mnv1:" + b64url(HMAC-SHA256(k_disc, LP("minister/null/v1")||LP("rp")||LP(N_dedup)||LP(clientId)))
export function deriveStage2(masterSeed: Buffer, nDedup: Buffer, clientId: string): string {
  const kDisc = Buffer.from(
    hkdfSync(
      "sha512",
      masterSeed,
      Buffer.alloc(0),
      Buffer.concat([Buffer.from("minister/v1/nullifier/disclose", "utf8"), lpStr(clientId)]),
      32,
    ),
  );
  const msg = Buffer.concat([lpStr("minister/null/v1"), lpStr("rp"), lp(nDedup), lpStr(clientId)]);
  return `mnv1:${createHmac("sha256", kDisc).update(msg).digest("base64url")}`;
}

interface LedgerEntry {
  refB64: string;
  value: Buffer;
  ownerHandle: string;
  badgeType: string;
}

export class MockSignet {
  // What GET /prf/public-key SERVES. Normally the true pkS; tests set it to a
  // lie to prove the backend's pin check (and, separately, that DLEQ against
  // the pin catches a server whose advertised key is honest-looking but whose
  // evaluations are under another key).
  advertisedPublicKeyB64: string;
  // What GET /prf/public-key advertises as the suite. Normally the real suite;
  // tests set it to a lie to prove the backend treats a suite mismatch as a
  // FATAL fork signal (SignetPinMismatchError), not a transient outage.
  advertisedSuite = "ristretto255-SHA512";
  // When set, every request short-circuits to this status (Signet-down).
  downStatus: number | null = null;
  readonly requests: Array<{ method: string; path: string }> = [];

  private readonly ledgerByValue = new Map<string, LedgerEntry>();
  private readonly ledgerByRef = new Map<string, LedgerEntry>();

  private constructor(
    private readonly masterSeed: Buffer,
    private readonly server: VOPRFServer,
    readonly publicKeyB64: string,
  ) {
    this.advertisedPublicKeyB64 = publicKeyB64;
  }

  static async create(masterSeed: Buffer): Promise<MockSignet> {
    const seedNull = new Uint8Array(
      hkdfSync("sha512", masterSeed, Buffer.alloc(0), "minister/v1/nullifier", 32),
    );
    const kp = await deriveKeyPair(
      Oprf.Mode.VOPRF,
      SUITE,
      seedNull,
      new Uint8Array(Buffer.from("minister/v1/nullifier/dedup", "utf8")),
      CryptoNoble,
    );
    const server = new VOPRFServer(SUITE, kp.privateKey, CryptoNoble);
    return new MockSignet(masterSeed, server, b64url(kp.publicKey));
  }

  transport(): SignetTransport {
    return (method, path, body) => this.handle(method, path, body);
  }

  entryCount(): number {
    return this.ledgerByRef.size;
  }

  hasRef(refB64: string): boolean {
    return this.ledgerByRef.has(refB64);
  }

  // Direct ledger seeding for tests that need a pre-existing entry.
  seedEntry(entry: { value: Buffer; ownerHandle: string; badgeType: string }): string {
    const row: LedgerEntry = { refB64: b64url(randomBytes(16)), ...entry };
    this.ledgerByValue.set(row.value.toString("hex"), row);
    this.ledgerByRef.set(row.refB64, row);
    return row.refB64;
  }

  private async handle(method: string, path: string, body?: unknown): Promise<SignetResponse> {
    this.requests.push({ method, path });
    if (this.downStatus !== null) {
      return { status: this.downStatus, json: { error: "down", message: "scripted outage" } };
    }
    const req = (body ?? {}) as Record<string, unknown>;

    if (method === "GET" && path === "/prf/public-key") {
      return {
        status: 200,
        json: { suite: this.advertisedSuite, public_key: this.advertisedPublicKeyB64 },
      };
    }

    if (method === "POST" && path === "/prf/evaluate") {
      const blinded = Buffer.from(String(req.blinded_element), "base64url");
      // voprf-ts list wire: u16 element count || element bytes.
      const evalReq = EvaluationRequest.deserialize(
        SUITE,
        new Uint8Array(Buffer.concat([Buffer.from([0, 1]), blinded])),
        CryptoNoble,
      );
      const evaluation = await this.server.blindEvaluate(evalReq);
      const elt = evaluation.evaluated[0];
      const proof = evaluation.proof;
      if (!elt || !proof) throw new Error("mock signet: evaluation missing element or proof");
      return {
        status: 200,
        json: { evaluation_element: b64url(elt.serialize()), proof: b64url(proof.serialize()) },
      };
    }

    if (method === "POST" && path === "/prf/disclose") {
      const entry = this.ledgerByRef.get(String(req.entry_ref));
      if (!entry) return { status: 404, json: { error: "not_found", message: "no such entry" } };
      if (entry.ownerHandle !== String(req.owner_handle)) {
        return { status: 403, json: { error: "forbidden", message: "owner mismatch" } };
      }
      return {
        status: 200,
        json: { nullifier: deriveStage2(this.masterSeed, entry.value, String(req.client_id)) },
      };
    }

    if (method === "POST" && path === "/dedup/register") {
      const value = Buffer.from(String(req.value), "base64url");
      const existing = this.ledgerByValue.get(value.toString("hex"));
      if (existing) {
        if (existing.ownerHandle === String(req.owner_handle)) {
          return { status: 200, json: { status: "already_yours", entry_ref: existing.refB64 } };
        }
        return { status: 409, json: { error: "taken", message: "already registered" } };
      }
      const refB64 = this.seedEntry({
        value,
        ownerHandle: String(req.owner_handle),
        badgeType: String(req.badge_type),
      });
      return { status: 200, json: { status: "registered", entry_ref: refB64 } };
    }

    if (method === "POST" && path === "/dedup/release") {
      const entry = this.ledgerByRef.get(String(req.entry_ref));
      if (!entry) return { status: 200, json: { status: "already_released" } };
      if (entry.ownerHandle !== String(req.owner_handle)) {
        return { status: 403, json: { error: "forbidden", message: "owner mismatch" } };
      }
      this.ledgerByRef.delete(entry.refB64);
      this.ledgerByValue.delete(entry.value.toString("hex"));
      return { status: 200, json: { status: "released" } };
    }

    if (method === "POST" && path === "/dedup/reassign") {
      // Mirrors Signet's all-or-nothing per-batch semantics (the backend
      // sends one ref per call precisely because of them).
      const refs = (req.entry_refs as string[]) ?? [];
      const from = String(req.from_owner_handle);
      const to = String(req.to_owner_handle);
      const rows: LedgerEntry[] = [];
      for (const r of refs) {
        const entry = this.ledgerByRef.get(r);
        if (!entry) return { status: 404, json: { error: "not_found", message: "no such entry" } };
        if (entry.ownerHandle !== from && entry.ownerHandle !== to) {
          // Signet's real owner-mismatch message (src/handlers.rs
          // dedup_reassign) — the backend's 403 discriminator keys on it.
          return {
            status: 403,
            json: {
              error: "forbidden",
              message: "an entry is owned by neither from_owner_handle nor to_owner_handle",
            },
          };
        }
        rows.push(entry);
      }
      let moved = 0;
      for (const entry of rows) {
        if (entry.ownerHandle === from) {
          entry.ownerHandle = to;
          moved++;
        }
      }
      return { status: 200, json: { status: "reassigned", reassigned: moved } };
    }

    return { status: 404, json: { error: "not_found", message: `no route ${method} ${path}` } };
  }
}
