// Popup script — runs every time the user clicks the extension icon.
// Stage 6 placeholder: just renders the message in popup.html. Wiring
// to the active wizard session lands when the prover does.
//
// Planned flow once tlsn-js is integrated:
//   1. Read the active Tessera tab URL.
//   2. Hit a tiny in-page bridge that exposes the current wizard step
//      payload (only for extension-action steps).
//   3. Show a "Run proof" button. On click, postMessage to the
//      background service worker with { kind: "tlsn-prove", request }.
//   4. Background performs the proof + submits to /api/tlsn/submit
//      and reports back; popup either shows success or the error.
export {};
