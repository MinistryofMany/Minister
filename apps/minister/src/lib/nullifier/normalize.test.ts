import { describe, expect, it } from "vitest";

import { ANCHOR_NORMALIZATION_VERSION, normalizeEmailAnchor } from "./normalize";

// Golden normalization table (build-plan §2.3). These vectors ARE the anchor
// contract: changing any output re-keys deployed anchors, so a change here must
// bump ANCHOR_NORMALIZATION_VERSION and be treated as a re-verification event.

describe("normalizeEmailAnchor — gmail (strip +tag AND remove dots)", () => {
  it("strips a +tag and removes local-part dots together", () => {
    expect(normalizeEmailAnchor("John.Doe+news@gmail.com")).toBe("johndoe@gmail.com");
  });
  it("removes dots with no tag", () => {
    expect(normalizeEmailAnchor("j.o.h.n@gmail.com")).toBe("john@gmail.com");
  });
  it("strips a tag with no dots", () => {
    expect(normalizeEmailAnchor("john+anything@gmail.com")).toBe("john@gmail.com");
  });
  it("lowercases a mixed-case gmail address before folding", () => {
    expect(normalizeEmailAnchor("Foo.Bar@GMAIL.COM")).toBe("foobar@gmail.com");
  });
});

describe("normalizeEmailAnchor — googlemail.com folds to gmail.com", () => {
  it("folds the host and applies gmail dot+tag rules", () => {
    expect(normalizeEmailAnchor("John.Doe+x@googlemail.com")).toBe("johndoe@gmail.com");
  });
  it("makes a googlemail address collide with the equivalent gmail address", () => {
    expect(normalizeEmailAnchor("alice@googlemail.com")).toBe(
      normalizeEmailAnchor("alice@gmail.com"),
    );
  });
});

describe("normalizeEmailAnchor — Microsoft (strip +tag, KEEP dots)", () => {
  it("strips the +tag but preserves dots on outlook.com", () => {
    expect(normalizeEmailAnchor("john.doe+tag@outlook.com")).toBe("john.doe@outlook.com");
  });
  it("strips the +tag on hotmail.com", () => {
    expect(normalizeEmailAnchor("a+b@hotmail.com")).toBe("a@hotmail.com");
  });
  it("strips the +tag on live.com", () => {
    expect(normalizeEmailAnchor("a+b@live.com")).toBe("a@live.com");
  });
  it("leaves a dotted outlook address with no tag untouched (beyond lowercasing)", () => {
    expect(normalizeEmailAnchor("First.Last@Outlook.com")).toBe("first.last@outlook.com");
  });
});

describe("normalizeEmailAnchor — every other provider: lowercase ONLY", () => {
  it("PRESERVES a +tag at an unknown provider (may be a distinct mailbox)", () => {
    expect(normalizeEmailAnchor("user+tag@example.com")).toBe("user+tag@example.com");
  });
  it("preserves dots at an unknown provider", () => {
    expect(normalizeEmailAnchor("user.name@example.com")).toBe("user.name@example.com");
  });
  it("preserves a +tag at fastmail (freemail, but NOT a plus-stripping provider)", () => {
    expect(normalizeEmailAnchor("me+x@fastmail.com")).toBe("me+x@fastmail.com");
  });
  it("keeps two +tag addresses at an unknown provider DISTINCT", () => {
    expect(normalizeEmailAnchor("bob+a@corp.test")).not.toBe(
      normalizeEmailAnchor("bob+b@corp.test"),
    );
  });
});

describe("normalizeEmailAnchor — trim + lowercase", () => {
  it("lowercases local and domain", () => {
    expect(normalizeEmailAnchor("Alice@Example.COM")).toBe("alice@example.com");
  });
  it("trims surrounding whitespace", () => {
    expect(normalizeEmailAnchor("  Bob@Example.com  ")).toBe("bob@example.com");
  });
});

describe("normalizeEmailAnchor — invalid input", () => {
  it("throws when there is no @ (caller must pre-validate)", () => {
    expect(() => normalizeEmailAnchor("not-an-email")).toThrow(/local@domain/u);
  });
  it("throws on a trailing @ with no domain", () => {
    expect(() => normalizeEmailAnchor("user@")).toThrow(/local@domain/u);
  });
  it("throws on a leading @ with no local part", () => {
    expect(() => normalizeEmailAnchor("@example.com")).toThrow(/local@domain/u);
  });
});

describe("ANCHOR_NORMALIZATION_VERSION", () => {
  it("is the frozen version these goldens describe", () => {
    expect(ANCHOR_NORMALIZATION_VERSION).toBe(1);
  });
});
