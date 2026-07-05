import { createHmac } from "node:crypto";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { SignetResponse, SignetTransport } from "./nullifier/signet-backend";
import {
  deriveLocalPairwise,
  derivePairwiseJti,
  derivePairwiseSub,
  derivePairwiseSubForPersistence,
  deriveShareLinkPairwiseJti,
  deriveShareLinkPairwiseSub,
  pairwiseJtiInput,
  pairwiseSubInput,
  shareLinkPairwiseJtiInput,
  shareLinkPairwiseSubInput,
  _flushPairwiseShadowForTests,
  _setPairwiseObserverForTests,
  _setPairwiseTransportForTests,
  type PairwiseFamily,
  type PairwiseObserver,
} from "./pairwise-backend";

// ---------------------------------------------------------------------------
// FROZEN GOLDEN VECTORS — the exact same triples pinned in
// oidc-claims.pairwise.test.ts and asserted byte-equal by Signet's
// /prf/pairwise interop tests. Re-declared here (frozen forever) so a wire
// encoding change breaks BOTH files, and so the seam is proven to reproduce the
// golden bytes in EVERY mode (local, signet, fallback).
// ---------------------------------------------------------------------------
const GOLDEN_SECRET = "minister-golden-vector-secret-v1-do-not-change!!";

const GOLDEN = {
  userId: "user_golden_0001",
  clientId: "mc_golden_client_0001",
  badgeId: "badge_golden_0001",
  shareLinkId: "share_golden_0001",
} as const;

const GOLDEN_OUTPUTS = {
  sub: "xOfT05jnZI0r8hweyDLf7GnlAlPoUhHHoUsKH49Olm0",
  jti: "5fIc0YcinsYRBEf1J6aZXcoKuxmDStXGch6Rk_bDylM",
  shareLinkSub: "3Wfr4iEXijtFDIQ9JkYamk6r427jpcY4ApbNbShi9sY",
  shareLinkJti: "8ITdmHQXFlAukLUGdhAOqexFVwIEbnQFKvOnHy3LoOo",
} as const;

// The four family calls, so tests iterate every derivation family uniformly.
const FAMILIES: Array<{
  family: PairwiseFamily;
  call: () => Promise<string>;
  input: string;
  golden: string;
}> = [
  {
    family: "sub",
    call: () => derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId),
    input: pairwiseSubInput(GOLDEN.userId, GOLDEN.clientId),
    golden: GOLDEN_OUTPUTS.sub,
  },
  {
    family: "jti",
    call: () => derivePairwiseJti(GOLDEN.badgeId, GOLDEN.clientId),
    input: pairwiseJtiInput(GOLDEN.badgeId, GOLDEN.clientId),
    golden: GOLDEN_OUTPUTS.jti,
  },
  {
    family: "sharelink-sub",
    call: () => deriveShareLinkPairwiseSub(GOLDEN.userId, GOLDEN.shareLinkId),
    input: shareLinkPairwiseSubInput(GOLDEN.userId, GOLDEN.shareLinkId),
    golden: GOLDEN_OUTPUTS.shareLinkSub,
  },
  {
    family: "sharelink-jti",
    call: () => deriveShareLinkPairwiseJti(GOLDEN.badgeId, GOLDEN.shareLinkId),
    input: shareLinkPairwiseJtiInput(GOLDEN.badgeId, GOLDEN.shareLinkId),
    golden: GOLDEN_OUTPUTS.shareLinkJti,
  },
];

// A mocked Signet transport that mirrors /prf/pairwise: base64url(no-pad,
// HMAC-SHA256(the current secret, input)). This is byte-for-byte what the real
// Signet computes with the imported secret, so it proves the Signet path equals
// the local path for the SAME key + input.
function hmacTransport(): SignetTransport {
  return (method, path, body): Promise<SignetResponse> => {
    expect(method).toBe("POST");
    expect(path).toBe("/prf/pairwise");
    const input = (body as { input: string }).input;
    const output = createHmac("sha256", process.env.OIDC_PAIRWISE_SECRET as string)
      .update(input)
      .digest("base64url");
    return Promise.resolve({ status: 200, json: { output } });
  };
}

// A transport that returns a VALID-shaped but DIFFERENT value (a genuine value
// mismatch, not a transport error) — a compromised/forked Signet.
function driftTransport(): SignetTransport {
  return (_method, _path, body): Promise<SignetResponse> => {
    const input = (body as { input: string }).input;
    const output = createHmac("sha256", process.env.OIDC_PAIRWISE_SECRET as string)
      .update(`${input}::drift`)
      .digest("base64url");
    return Promise.resolve({ status: 200, json: { output } });
  };
}

function capturingObserver(): {
  obs: PairwiseObserver;
  mismatches: PairwiseFamily[];
  compareOks: PairwiseFamily[];
  shadowErrors: Array<{ family: PairwiseFamily; error: string }>;
  shadowSkipped: PairwiseFamily[];
  serveMismatches: PairwiseFamily[];
  fallbacks: Array<{ family: PairwiseFamily; error: string }>;
} {
  const mismatches: PairwiseFamily[] = [];
  const compareOks: PairwiseFamily[] = [];
  const shadowErrors: Array<{ family: PairwiseFamily; error: string }> = [];
  const shadowSkipped: PairwiseFamily[] = [];
  const serveMismatches: PairwiseFamily[] = [];
  const fallbacks: Array<{ family: PairwiseFamily; error: string }> = [];
  return {
    obs: {
      onShadowMismatch: ({ family }) => mismatches.push(family),
      onShadowCompareOk: ({ family }) => compareOks.push(family),
      onShadowError: (i) => shadowErrors.push(i),
      onShadowSkipped: ({ family }) => shadowSkipped.push(family),
      onServeMismatch: ({ family }) => serveMismatches.push(family),
      onFallback: (i) => fallbacks.push(i),
    },
    mismatches,
    compareOks,
    shadowErrors,
    shadowSkipped,
    serveMismatches,
    fallbacks,
  };
}

const ORIGINAL_SECRET = process.env.OIDC_PAIRWISE_SECRET;
const ORIGINAL_BACKEND = process.env.MINISTER_SUB_BACKEND;

beforeAll(() => {
  process.env.OIDC_PAIRWISE_SECRET = GOLDEN_SECRET;
});

afterAll(() => {
  if (ORIGINAL_SECRET === undefined) delete process.env.OIDC_PAIRWISE_SECRET;
  else process.env.OIDC_PAIRWISE_SECRET = ORIGINAL_SECRET;
  if (ORIGINAL_BACKEND === undefined) delete process.env.MINISTER_SUB_BACKEND;
  else process.env.MINISTER_SUB_BACKEND = ORIGINAL_BACKEND;
});

beforeEach(() => {
  process.env.OIDC_PAIRWISE_SECRET = GOLDEN_SECRET;
  delete process.env.MINISTER_SUB_BACKEND;
  _setPairwiseTransportForTests(null);
  _setPairwiseObserverForTests(null);
});

afterEach(async () => {
  await _flushPairwiseShadowForTests();
  _setPairwiseTransportForTests(null);
  _setPairwiseObserverForTests(null);
  delete process.env.MINISTER_SUB_BACKEND;
});

describe("pairwise-backend — local mode (default)", () => {
  it("every family reproduces the FROZEN golden vector", async () => {
    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden);
    }
  });

  it("local == base64url(HMAC-SHA256(secret, taggedInput)) for every family", async () => {
    for (const f of FAMILIES) {
      const expected = createHmac("sha256", GOLDEN_SECRET).update(f.input).digest("base64url");
      expect(await f.call()).toBe(expected);
      expect(deriveLocalPairwise(f.input)).toBe(expected);
      expect(expected).toBe(f.golden);
    }
  });

  it("makes NO Signet call in local mode (a transport call would throw)", async () => {
    _setPairwiseTransportForTests(() => {
      throw new Error("local mode must never touch Signet");
    });
    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden);
    }
  });

  it("throws when OIDC_PAIRWISE_SECRET is unset (no silent AUTH_SECRET fallback)", async () => {
    delete process.env.OIDC_PAIRWISE_SECRET;
    await expect(derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId)).rejects.toThrow(
      /OIDC_PAIRWISE_SECRET must be set/,
    );
  });
});

describe("pairwise-backend — signet mode (byte-identical to local)", () => {
  beforeEach(() => {
    process.env.MINISTER_SUB_BACKEND = "signet";
    _setPairwiseTransportForTests(hmacTransport());
  });

  it("serves the Signet value, byte-equal to local AND the golden vector for every family", async () => {
    for (const f of FAMILIES) {
      const served = await f.call();
      expect(served).toBe(f.golden);
      expect(served).toBe(deriveLocalPairwise(f.input));
    }
  });

  it("propagates a Signet transport error (Tier-0: no local fallback in signet mode)", async () => {
    _setPairwiseTransportForTests(() => Promise.reject(new Error("boom")));
    await expect(derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId)).rejects.toThrow(/boom/);
  });

  it("rejects a malformed Signet output (wrong length) fail-closed", async () => {
    _setPairwiseTransportForTests(() =>
      Promise.resolve({ status: 200, json: { output: "too-short" } }),
    );
    await expect(derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId)).rejects.toThrow(
      /malformed pairwise output/,
    );
  });

  it("rejects a non-200 Signet status fail-closed", async () => {
    _setPairwiseTransportForTests(() => Promise.resolve({ status: 503, json: null }));
    await expect(derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId)).rejects.toThrow(
      /\/prf\/pairwise returned 503/,
    );
  });
});

describe("pairwise-backend — shadow mode (serve local, compare async)", () => {
  beforeEach(() => {
    process.env.MINISTER_SUB_BACKEND = "shadow";
  });

  it("serves the LOCAL value and reports a SUCCESSFUL compare (not just no mismatch) when Signet agrees", async () => {
    const { obs, mismatches, compareOks, shadowErrors } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(hmacTransport());

    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden); // served == local
    }
    await _flushPairwiseShadowForTests();
    expect(mismatches).toEqual([]);
    expect(shadowErrors).toEqual([]);
    // The soak exit gate is "successful compares == derivations AND 0
    // mismatches" — a positive success count, never just absence of mismatches.
    expect(compareOks.sort()).toEqual(["jti", "sharelink-jti", "sharelink-sub", "sub"]);
  });

  it("records NO successful compare when every Signet call errors (a vacuous soak is visible)", async () => {
    const { obs, mismatches, compareOks, shadowErrors } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(() => Promise.reject(new Error("PRF 403")));

    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden);
    }
    await _flushPairwiseShadowForTests();
    // Zero mismatches — but ALSO zero successful compares, so counting only the
    // mismatch signal would falsely read as a passed equivalence proof.
    expect(mismatches).toEqual([]);
    expect(compareOks).toEqual([]);
    expect(shadowErrors).toHaveLength(FAMILIES.length);
  });

  it("caps in-flight compares: past the cap the compare is SKIPPED and counted, never blocking the served value", async () => {
    const { obs, shadowSkipped } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    // A transport that stays pending keeps every launched compare in-flight, so
    // the calls past the cap (64) hit it and are skipped. Resolvers are held so
    // the in-flight set can be drained before the afterEach flush.
    const resolvers: Array<() => void> = [];
    _setPairwiseTransportForTests(
      () =>
        new Promise<SignetResponse>((resolve) => {
          resolvers.push(() => resolve({ status: 200, json: { output: "x".repeat(43) } }));
        }),
    );
    // Shadow serves the local value immediately (fire-and-forget compare), so
    // each call returns without awaiting the pending transport. 64 fill the cap,
    // the next 20 are skipped.
    for (let i = 0; i < 84; i++) {
      const client = `mc_client_${i}`;
      expect(await derivePairwiseSub(GOLDEN.userId, client)).toBe(
        deriveLocalPairwise(pairwiseSubInput(GOLDEN.userId, client)),
      );
    }
    expect(shadowSkipped.length).toBe(20);
    expect(shadowSkipped.every((f) => f === "sub")).toBe(true);
    // Drain the 64 pending compares so the afterEach flush can settle.
    for (const r of resolvers) r();
    await _flushPairwiseShadowForTests();
  });

  it("still SERVES the local value when Signet disagrees, and reports the mismatch", async () => {
    const { obs, mismatches } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(driftTransport());

    // The served value is the local golden bytes — NEVER the drifting Signet value.
    for (const f of FAMILIES) {
      const served = await f.call();
      expect(served).toBe(f.golden);
      expect(served).toBe(deriveLocalPairwise(f.input));
    }
    await _flushPairwiseShadowForTests();
    // Every family's async compare flagged a mismatch (load-bearing pre-cutover signal).
    expect(mismatches.sort()).toEqual(["jti", "sharelink-jti", "sharelink-sub", "sub"]);
  });

  it("serves local and records a shadow ERROR (not a mismatch) on a Signet transport failure", async () => {
    const { obs, mismatches, shadowErrors } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(() => Promise.reject(new Error("net down")));

    const served = await derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId);
    expect(served).toBe(GOLDEN_OUTPUTS.sub); // served regardless of Signet health
    await _flushPairwiseShadowForTests();
    expect(mismatches).toEqual([]);
    expect(shadowErrors).toHaveLength(1);
    expect(shadowErrors[0]?.error).toMatch(/net down/);
  });
});

describe("pairwise-backend — signet-fallback mode (serve Signet, byte-identical local fallback)", () => {
  beforeEach(() => {
    process.env.MINISTER_SUB_BACKEND = "signet-fallback";
  });

  it("serves the Signet value (byte-equal to local) and does NOT alert when Signet is healthy", async () => {
    const { obs, fallbacks, serveMismatches } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(hmacTransport());

    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden);
    }
    expect(fallbacks).toEqual([]);
    expect(serveMismatches).toEqual([]);
  });

  it("serves the LOCAL golden value (never the drift) and fires onServeMismatch when a healthy Signet returns a WRONG value", async () => {
    const { obs, fallbacks, serveMismatches } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    // A well-formed 200 response that DIFFERS from local (a re-keyed / forked
    // Signet). This is NOT a transport error, so onFallback must stay silent;
    // the divergence must instead surface as onServeMismatch — the only drift
    // detector /prf/pairwise (no DLEQ) will ever have — and the served value
    // must be the byte-identical local golden value, preserving byte-stability.
    _setPairwiseTransportForTests(driftTransport());

    for (const f of FAMILIES) {
      const served = await f.call();
      expect(served).toBe(f.golden);
      expect(served).toBe(deriveLocalPairwise(f.input));
    }
    expect(fallbacks).toEqual([]);
    expect(serveMismatches.sort()).toEqual(["jti", "sharelink-jti", "sharelink-sub", "sub"]);
  });

  it("falls back to the byte-identical LOCAL value and ALERTS on a transport error", async () => {
    const { obs, fallbacks } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(() => Promise.reject(new Error("timeout")));

    for (const f of FAMILIES) {
      const served = await f.call();
      // Invisible fallback: the served value is byte-identical to Signet's would-be output.
      expect(served).toBe(f.golden);
      expect(served).toBe(deriveLocalPairwise(f.input));
    }
    expect(fallbacks.map((e) => e.family).sort()).toEqual([
      "jti",
      "sharelink-jti",
      "sharelink-sub",
      "sub",
    ]);
    expect(fallbacks.every((e) => /timeout/.test(e.error))).toBe(true);
  });

  it("falls back and alerts on a non-200 Signet status too", async () => {
    const { obs, fallbacks } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(() => Promise.resolve({ status: 500, json: null }));

    const served = await derivePairwiseSub(GOLDEN.userId, GOLDEN.clientId);
    expect(served).toBe(GOLDEN_OUTPUTS.sub);
    expect(fallbacks).toHaveLength(1);
    expect(fallbacks[0]?.family).toBe("sub");
  });
});

describe("derivePairwiseSubForPersistence — merge-time frozen-value crosscheck", () => {
  it("returns the golden sub in local mode (byte-equal to the plain seam)", async () => {
    const served = await derivePairwiseSubForPersistence(GOLDEN.userId, GOLDEN.clientId);
    expect(served).toBe(GOLDEN_OUTPUTS.sub);
  });

  it("returns the value in signet mode when Signet AGREES with local", async () => {
    process.env.MINISTER_SUB_BACKEND = "signet";
    _setPairwiseTransportForTests(hmacTransport());
    const served = await derivePairwiseSubForPersistence(GOLDEN.userId, GOLDEN.clientId);
    expect(served).toBe(GOLDEN_OUTPUTS.sub);
  });

  it("THROWS in signet mode when a well-formed Signet value DIVERGES from local (never persists a wrong frozen sub)", async () => {
    process.env.MINISTER_SUB_BACKEND = "signet";
    _setPairwiseTransportForTests(driftTransport());
    // A merge that stored this drift would permanently re-key the donor's
    // identity at that RP; the crosscheck aborts fail-closed (retryable).
    await expect(derivePairwiseSubForPersistence(GOLDEN.userId, GOLDEN.clientId)).rejects.toThrow(
      /merge-time sub crosscheck failed/,
    );
  });

  it("does NOT throw in signet-fallback drift (the seam already serves the byte-identical local value)", async () => {
    process.env.MINISTER_SUB_BACKEND = "signet-fallback";
    _setPairwiseTransportForTests(driftTransport());
    const served = await derivePairwiseSubForPersistence(GOLDEN.userId, GOLDEN.clientId);
    // signet-fallback serves local on divergence, so served === local and the
    // crosscheck is a no-op — the value persisted is the golden truth.
    expect(served).toBe(GOLDEN_OUTPUTS.sub);
  });
});
