import { describe, expect, it } from "vitest";

import { anonymityHint } from "./anonymity-hint";

describe("anonymityHint", () => {
  it("buckets by coarse thresholds, never exposing the integer", () => {
    expect(anonymityHint(0).bucket).toBe("very-small");
    expect(anonymityHint(9).bucket).toBe("very-small");
    expect(anonymityHint(10).bucket).toBe("small");
    expect(anonymityHint(99).bucket).toBe("small");
    expect(anonymityHint(100).bucket).toBe("medium");
    expect(anonymityHint(999).bucket).toBe("medium");
    expect(anonymityHint(1000).bucket).toBe("large");
    expect(anonymityHint(50_000).bucket).toBe("large");
  });

  it("provides a human label for each bucket", () => {
    expect(anonymityHint(5).label).toMatch(/least private/i);
    expect(anonymityHint(50_000).label).toMatch(/most private/i);
  });
});
