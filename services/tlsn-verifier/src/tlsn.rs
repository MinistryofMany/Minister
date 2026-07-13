//! Real TLSNotary presentation verification.
//!
//! The Minister browser extension runs a TLSNotary prover, obtains a
//! notary-signed attestation, then builds a `Presentation` disclosing the
//! parts of the session it chooses to reveal. It bincode-serializes that
//! presentation and base64-encodes it for the `/verify` wire.
//!
//! Here we reverse that: base64 -> bincode -> `tlsn_core::presentation::
//! Presentation`, then call `Presentation::verify`, which cryptographically
//! checks the notary's signature over the attestation, the server-identity
//! proof (the server's certificate chain, validated against the crypto
//! provider's roots at the recorded connection time), and the transcript
//! proof (that the revealed bytes are authentic to the attested session).
//!
//! Trust model: `verify()` proves the presentation is internally consistent
//! and signed by *some* notary key. It does NOT decide whether that notary is
//! *ours*. That is what `TLSN_NOTARY_PUBLIC_KEY` pinning does below — without
//! it, any notary's signature would pass, so anyone could forge a session by
//! running their own notary. We therefore fail closed on a key mismatch, and
//! loudly warn when no key is pinned.
//!
//! This function NEVER returns success for input it could not cryptographically
//! verify. Every failure path returns `Err`, so a misconfigured `real` mode
//! rejects rather than rubber-stamps.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use tlsn_core::{
    presentation::{Presentation, PresentationOutput},
    CryptoProvider,
};
use tracing::warn;

use crate::{host_matches, Transcript, VerifyOutcome};

const NOTARY_KEY_ENV: &str = "TLSN_NOTARY_PUBLIC_KEY";

/// Verifies a base64(bincode(Presentation)) against `expected_domain`.
pub fn verify_real(presentation_b64: &str, expected_domain: &str) -> Result<VerifyOutcome> {
    let bytes = B64
        .decode(presentation_b64.as_bytes())
        .map_err(|e| anyhow!("presentation is not valid base64: {e}"))?;

    let presentation: Presentation = bincode::deserialize(&bytes)
        .context("presentation could not be decoded as a TLSNotary Presentation (bincode)")?;

    // Capture the notary key before `verify` consumes the presentation.
    let notary_key_hex = hex::encode(&presentation.verifying_key().data);

    // Notary pinning: the whole trust chain rests on this. Enforce a pinned
    // key when configured; otherwise verify cryptographic validity but warn
    // that the notary is not being pinned.
    match pinned_notary_key() {
        Some(pinned) => {
            if !constant_time_eq_hex(&pinned, &notary_key_hex) {
                return Err(anyhow!(
                    "presentation notary key does not match the pinned {NOTARY_KEY_ENV}"
                ));
            }
        }
        None => warn!(
            notary_key = %notary_key_hex,
            "{NOTARY_KEY_ENV} is unset — verifying cryptographic validity but NOT pinning the \
             notary. Set it in production or any notary's signature will be accepted."
        ),
    }

    // Production trust anchors (webpki roots baked into tlsn-core). This is the
    // same provider the upstream `verify` example uses for real sessions.
    let provider = CryptoProvider::default();

    let PresentationOutput {
        server_name,
        transcript,
        ..
    } = presentation
        .verify(&provider)
        .map_err(|e| anyhow!("presentation verification failed: {e}"))?;

    // A presentation without an identity proof cannot bind the transcript to a
    // server name, so we cannot honor `expectedDomain`: reject.
    let server_name = server_name
        .ok_or_else(|| anyhow!("presentation did not include a server-identity proof"))?;
    let server_name = server_name.as_str().to_string();

    if !host_matches(&server_name, expected_domain) {
        return Err(anyhow!(
            "verified server name {server_name:?} does not match expectedDomain {expected_domain:?}"
        ));
    }

    // A presentation without a transcript proof reveals nothing to attest.
    let mut partial =
        transcript.ok_or_else(|| anyhow!("presentation did not include a transcript proof"))?;
    // Mark bytes the prover chose not to reveal so a plugin's substring check
    // can't be satisfied by unauthenticated data. 'X' matches the upstream
    // example's sentinel.
    partial.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial.sent_unsafe()).into_owned();
    let received = String::from_utf8_lossy(partial.received_unsafe()).into_owned();

    Ok(VerifyOutcome {
        transcript: Transcript {
            sent,
            received,
            server_name,
        },
        notary_key: Some(notary_key_hex),
    })
}

/// Reads and normalizes the pinned notary key (lowercase hex, optional `0x`).
fn pinned_notary_key() -> Option<String> {
    std::env::var(NOTARY_KEY_ENV)
        .ok()
        .map(|s| normalize_hex(&s))
        .filter(|s| !s.is_empty())
}

fn normalize_hex(s: &str) -> String {
    let s = s.trim().to_ascii_lowercase();
    s.strip_prefix("0x").unwrap_or(&s).to_string()
}

/// Length-independent-ish constant-time compare of two hex strings. The notary
/// key is public, so this is belt-and-suspenders, not a strict requirement.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guard against a silent env leak between tests: these do not set the env
    // var, so pinning is off and verification still fails closed on bad input.

    #[test]
    fn rejects_non_base64() {
        let err = verify_real("!!! not base64 !!!", "example.com").unwrap_err();
        assert!(err.to_string().contains("base64"), "got: {err}");
    }

    #[test]
    fn rejects_valid_base64_that_is_not_a_presentation() {
        // Well-formed base64, but the bytes are not a bincode Presentation.
        let junk = B64.encode(b"this is not a tlsnotary presentation");
        let err = verify_real(&junk, "example.com").unwrap_err();
        assert!(
            err.to_string().contains("Presentation"),
            "expected a decode error, got: {err}"
        );
    }

    #[test]
    fn rejects_empty_presentation() {
        let empty = B64.encode(b"");
        assert!(verify_real(&empty, "example.com").is_err());
    }

    #[test]
    fn rejects_truncated_bincode() {
        // A few arbitrary bytes: enough to pass base64, not a valid struct.
        let truncated = B64.encode([0x01, 0x00, 0x00, 0x00, 0xff]);
        assert!(verify_real(&truncated, "example.com").is_err());
    }

    #[test]
    fn normalize_hex_strips_prefix_and_lowercases() {
        assert_eq!(normalize_hex("0xABcd"), "abcd");
        assert_eq!(normalize_hex("  DEAD "), "dead");
    }

    #[test]
    fn constant_time_eq_hex_matches_and_rejects() {
        assert!(constant_time_eq_hex("abcd", "abcd"));
        assert!(!constant_time_eq_hex("abcd", "abce"));
        assert!(!constant_time_eq_hex("abcd", "abcdef"));
    }
}
