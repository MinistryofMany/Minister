# tlsn-verifier

Placeholder. Stage 6 will host a small Rust HTTP service that wraps the [`tlsn-verifier`](https://docs.rs/tlsn-verifier) crate. Tessera POSTs a finalized TLSNotary presentation and the expected domain to this sidecar; the sidecar returns a verified transcript (or an error). Running this as a separate Rust service rather than tlsn-via-WASM-in-Node keeps tlsn version pinning simple and isolates breaking upstream changes.
