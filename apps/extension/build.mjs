// Bundles the extension into dist/ (load-unpacked target).
//
// Three entry points -> dist/{background,popup,offscreen}.js, plus the static
// assets (manifest, HTML, icons). The offscreen bundle pulls in tlsn-js and its
// WASM; the .wasm is emitted as a sibling asset via the `copy` loader.
//
// Endpoint config is injected at build time via esbuild `define`, so a
// deployment can point the prover at its own notary / ws-proxy without editing
// source:
//   MINISTER_NOTARY_URL, MINISTER_WS_PROXY_URL

import { cp, mkdir, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import * as esbuild from "esbuild";

const root = dirname(fileURLToPath(import.meta.url));
const dist = join(root, "dist");

function defineEnv() {
  const keys = ["MINISTER_NOTARY_URL", "MINISTER_WS_PROXY_URL"];
  /** @type {Record<string, string>} */
  const define = {};
  for (const k of keys) {
    if (process.env[k] !== undefined) {
      define[`process.env.${k}`] = JSON.stringify(process.env[k]);
    }
  }
  return define;
}

async function main() {
  await rm(dist, { recursive: true, force: true });
  await mkdir(dist, { recursive: true });

  await esbuild.build({
    entryPoints: [
      join(root, "src/background.ts"),
      join(root, "src/popup.ts"),
      join(root, "src/offscreen.ts"),
    ],
    outdir: dist,
    bundle: true,
    format: "esm",
    target: ["chrome110"],
    platform: "browser",
    sourcemap: true,
    logLevel: "info",
    // tlsn-wasm ships a .wasm binary; emit it next to the JS and rewrite the
    // import to its asset path.
    loader: { ".wasm": "copy" },
    define: defineEnv(),
  });

  // Static assets. manifest + HTML live at the dist root; icons keep their dir.
  await cp(join(root, "manifest.json"), join(dist, "manifest.json"));
  await cp(join(root, "src/popup.html"), join(dist, "popup.html"));
  await cp(join(root, "src/offscreen.html"), join(dist, "offscreen.html"));
  await cp(join(root, "icons"), join(dist, "icons"), { recursive: true }).catch(() => {
    // icons are optional in dev; a missing dir should not fail the build.
  });

  await copyWasmAssets();

  console.log("extension bundled -> dist/");
}

// tlsn-wasm resolves its binary + worker relative to `import.meta.url`. esbuild
// inlines the JS glue into offscreen.js, so the default init fetches
// `dist/tlsn_wasm_bg.wasm` and the rayon worker spawns from `dist/snippets/...`.
// We copy the whole tlsn-wasm asset set into dist so those lookups resolve.
//
// KNOWN REMAINING WORK (needs a browser to validate): the copied
// `snippets/.../js/spawn.js` dynamic-imports `../../../tlsn_wasm.js`, which does
// not exist once the glue is inlined. Final wiring (ship tlsn_wasm.js unbundled,
// or patch the snippet's import) must be confirmed against a running Chrome with
// cross-origin isolation (the manifest COOP/COEP keys) so SharedArrayBuffer +
// workers are available. Tracked in README "What's left".
async function copyWasmAssets() {
  // tlsn-wasm is a transitive dep (of tlsn-js), so resolve it FROM tlsn-js's
  // location rather than the extension root (pnpm does not hoist it).
  const tlsnJsEntry = fileURLToPath(await import.meta.resolve("tlsn-js"));
  const wasmEntry = createRequire(tlsnJsEntry).resolve("tlsn-wasm");
  const wasmDir = dirname(wasmEntry); // .../tlsn-wasm
  for (const asset of ["tlsn_wasm_bg.wasm", "tlsn_wasm.js", "spawn.js"]) {
    await cp(join(wasmDir, asset), join(dist, asset)).catch((err) => {
      console.warn(`warning: could not copy ${asset}: ${err.message}`);
    });
  }
  await cp(join(wasmDir, "snippets"), join(dist, "snippets"), { recursive: true }).catch(
    (err) => {
      console.warn(`warning: could not copy snippets/: ${err.message}`);
    },
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
