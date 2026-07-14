import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

// Source-level enforcement of the anon-identity UI invariants that are
// grep-able rules by spec (§12 checklist 1, 3, 10; findings W1/W2). These are
// deliberately tests over the source text: the runtime behavior needs a real
// browser (e2e), but the structural rules — no named field, no network-capable
// form, no seed-adjacent storage — must hold at the text level too, and a
// regression here should fail CI before it ever reaches a browser.

const COMPONENTS_DIR = join(__dirname);
const VAULT_PATH = join(__dirname, "..", "..", "lib", "anon-seed", "vault.ts");
const CONSENT_SCREEN_PATH = join(__dirname, "..", "consent-screen.tsx");

function componentSources(): Array<{ file: string; source: string }> {
  return readdirSync(COMPONENTS_DIR)
    .filter((f) => f.endsWith(".tsx"))
    .map((file) => ({ file, source: readFileSync(join(COMPONENTS_DIR, file), "utf8") }));
}

const vaultSource = readFileSync(VAULT_PATH, "utf8");
const consentSource = readFileSync(CONSENT_SCREEN_PATH, "utf8");

describe("W1: the unlock field is structurally quarantined", () => {
  it("no anon-seed component renders a form field with a name attribute", () => {
    for (const { file, source } of componentSources()) {
      // A JSX name= attribute would make the value serializable by any
      // enclosing form. None may exist in the vault-owned components.
      expect(source, `${file} must not carry a name= attribute`).not.toMatch(/\sname=/);
    }
  });

  it("the unlock panel contains no form element at all", () => {
    const unlock = componentSources().find((c) => c.file === "unlock-panel.tsx");
    expect(unlock).toBeDefined();
    expect(unlock!.source).not.toContain("<form");
  });

  it("the consent screen clears the anon field before dispatching approve", () => {
    const clearIdx = consentSource.indexOf("anonClearRef.current?.()");
    const approveIdx = consentSource.indexOf("await approveConsent(");
    expect(clearIdx).toBeGreaterThan(-1);
    expect(approveIdx).toBeGreaterThan(clearIdx);
  });
});

describe("W2 / I11: the only form is the network-incapable dialog save form", () => {
  it("pm-save's form is method=dialog with no action and submit-event preventDefault", () => {
    const pmSave = componentSources().find((c) => c.file === "pm-save.tsx");
    expect(pmSave).toBeDefined();
    const formTags = pmSave!.source.match(/<form[\s\S]*?>/g) ?? [];
    expect(formTags).toHaveLength(1);
    expect(formTags[0]).toContain('method="dialog"');
    expect(formTags[0]).not.toContain("action=");
    // preventDefault bound to the form's submit event, not a click handler.
    expect(formTags[0]).toContain("onSubmit=");
    expect(pmSave!.source).toMatch(/onSubmit=\{[\s\S]{0,80}e\.preventDefault\(\)/);
    // The preferred no-form path exists.
    expect(vaultSource).toContain("navigator.credentials.store(");
  });

  it("no other anon-seed component contains a form", () => {
    for (const { file, source } of componentSources()) {
      if (file === "pm-save.tsx") continue;
      expect(source, `${file} must not contain a <form>`).not.toContain("<form");
    }
  });
});

describe("checklist 10: credential mediation is required, never optional", () => {
  it('vault uses mediation: "required" and nothing anon-side uses "optional"', () => {
    expect(vaultSource).toContain('mediation: "required"');
    expect(vaultSource).not.toContain('"optional"');
    for (const { file, source } of componentSources()) {
      expect(source, `${file} must not use optional mediation`).not.toContain(
        'mediation: "optional"',
      );
    }
  });
});

describe("I1-adjacent: no transport or storage primitives near seed material", () => {
  const sources = [{ file: "vault.ts", source: vaultSource }, ...componentSources()];

  it("no direct network primitives in the vault or its owned components", () => {
    for (const { file, source } of sources) {
      expect(source, `${file}: no fetch`).not.toMatch(/\bfetch\(/);
      expect(source, `${file}: no XHR`).not.toContain("XMLHttpRequest");
      expect(source, `${file}: no sendBeacon`).not.toContain("sendBeacon");
      expect(source, `${file}: no WebSocket`).not.toContain("WebSocket");
    }
  });

  it("no script-readable storage for seed material (7.3 global rule)", () => {
    for (const { file, source } of sources) {
      expect(source, `${file}: no sessionStorage`).not.toContain("sessionStorage");
      expect(source, `${file}: no indexedDB`).not.toMatch(/indexedDB/i);
      if (file === "vault.ts") {
        // The one permitted localStorage use: the boolean memory-only
        // preference — every usage sits in the pref helpers.
        const uses = source.match(/localStorage\.(get|set|remove)Item\(\s*([^)]+)/g) ?? [];
        expect(uses.length).toBeGreaterThan(0);
        for (const use of uses) {
          expect(use).toContain("MEMORY_ONLY_PREF_PREFIX");
        }
      } else {
        expect(source, `${file}: no localStorage`).not.toContain("localStorage");
      }
    }
  });

  it("the PRF assertion is never serialized (7.1 invariant-critical)", () => {
    expect(vaultSource).not.toContain("JSON.stringify");
  });
});

describe("8.2/8.4/S3: fragment handling stays client-side and single-hop", () => {
  it("the fragment prefix is built only in the vault", () => {
    expect(vaultSource).toContain('"#minister_anon=v1."');
    for (const { file, source } of componentSources()) {
      expect(source, `${file} must not build the fragment itself`).not.toContain("minister_anon");
    }
    expect(consentSource).not.toContain("minister_anon");
  });

  it("consent navigates via location.assign and never writes history", () => {
    expect(consentSource).toContain("window.location.assign(");
    expect(consentSource).not.toContain("history.pushState");
    expect(consentSource).not.toContain("sessionStorage");
    expect(consentSource).not.toContain("localStorage");
  });
});
