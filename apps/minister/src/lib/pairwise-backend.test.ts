import { createHmac } from "node:crypto";

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import type { SignetResponse, SignetTransport } from "./nullifier/signet-backend";
import {
  deriveLocalPairwise,
  derivePairwiseJti,
  derivePairwiseSub,
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
  shadowErrors: Array<{ family: PairwiseFamily; error: string }>;
  fallbacks: Array<{ family: PairwiseFamily; error: string }>;
} {
  const mismatches: PairwiseFamily[] = [];
  const shadowErrors: Array<{ family: PairwiseFamily; error: string }> = [];
  const fallbacks: Array<{ family: PairwiseFamily; error: string }> = [];
  return {
    obs: {
      onShadowMismatch: ({ family }) => mismatches.push(family),
      onShadowError: (i) => shadowErrors.push(i),
      onFallback: (i) => fallbacks.push(i),
    },
    mismatches,
    shadowErrors,
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

  it("serves the LOCAL value and reports NO mismatch when Signet agrees", async () => {
    const { obs, mismatches, shadowErrors } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(hmacTransport());

    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden); // served == local
    }
    await _flushPairwiseShadowForTests();
    expect(mismatches).toEqual([]);
    expect(shadowErrors).toEqual([]);
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
    const { obs, fallbacks } = capturingObserver();
    _setPairwiseObserverForTests(obs);
    _setPairwiseTransportForTests(hmacTransport());

    for (const f of FAMILIES) {
      expect(await f.call()).toBe(f.golden);
    }
    expect(fallbacks).toEqual([]);
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
