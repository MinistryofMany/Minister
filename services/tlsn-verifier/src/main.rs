//! Minister TLSNotary verifier sidecar.
//!
//! Accepts POST /verify {presentation, expectedDomain} from the
//! Minister Next.js app, returns the verified transcript (or an error).
//!
//! Two modes, switched by `VERIFIER_MODE`:
//!   - `passthrough` (default in dev): decodes the presentation as JSON
//!     of shape `{ sent, received, serverName }` and returns it
//!     untouched. Lets us exercise the Minister side without a real
//!     TLSNotary prover.
//!   - `real`: cryptographically verifies the presentation via `tlsn-core`
//!     (`Presentation::verify`). Entry point is `tlsn::verify_real`; it fails
//!     closed on any input it cannot verify (never rubber-stamps).
//!
//! Listens on `0.0.0.0:7048` by default; override with `LISTEN_ADDR`.

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

mod tlsn;

#[derive(Clone)]
struct AppState {
    mode: Mode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Passthrough,
    Real,
}

impl Mode {
    fn from_env() -> Self {
        match std::env::var("VERIFIER_MODE").ok().as_deref() {
            Some("real") => Mode::Real,
            _ => Mode::Passthrough,
        }
    }
}

#[derive(Deserialize)]
struct VerifyRequest {
    presentation: String,
    #[serde(rename = "expectedDomain")]
    expected_domain: String,
}

#[derive(Serialize, Debug)]
struct Transcript {
    sent: String,
    received: String,
    #[serde(rename = "serverName")]
    server_name: String,
}

/// The result of a verification, plus the notary key the caller may pin.
#[derive(Debug)]
pub struct VerifyOutcome {
    transcript: Transcript,
    /// Hex-encoded notary verifying key the presentation was signed with.
    /// `None` in passthrough mode (no real signature).
    notary_key: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum VerifyResponse {
    Ok {
        ok: bool, // always true
        transcript: Transcript,
        #[serde(rename = "notaryKey", skip_serializing_if = "Option::is_none")]
        notary_key: Option<String>,
    },
    Err {
        ok: bool, // always false
        error: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let state = AppState {
        mode: Mode::from_env(),
    };
    info!(?state.mode, "starting tlsn-verifier sidecar");

    let app = Router::new()
        .route("/health", get(health))
        .route("/verify", post(verify))
        .with_state(state);

    let addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:7048".to_string())
        .parse()?;
    info!(%addr, "listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let outcome = match state.mode {
        Mode::Passthrough => verify_passthrough(&req),
        Mode::Real => tlsn::verify_real(&req.presentation, &req.expected_domain),
    };

    match outcome {
        Ok(VerifyOutcome {
            transcript,
            notary_key,
        }) => (
            StatusCode::OK,
            Json(VerifyResponse::Ok {
                ok: true,
                transcript,
                notary_key,
            }),
        ),
        Err(err) => {
            warn!(error = %err, "verification failed");
            (
                StatusCode::OK, // protocol-level errors are 200 with ok:false
                Json(VerifyResponse::Err {
                    ok: false,
                    error: err.to_string(),
                }),
            )
        }
    }
}

/// Dev-mode passthrough. The "presentation" is base64-encoded JSON of
/// shape `{ sent, received, serverName }`. Verify only that the server
/// name matches; trust the rest. Lets Minister plugin flows be tested
/// end-to-end without a TLSNotary prover in the loop.
fn verify_passthrough(req: &VerifyRequest) -> Result<VerifyOutcome> {
    let bytes = B64
        .decode(req.presentation.as_bytes())
        .map_err(|e| anyhow!("presentation is not valid base64: {e}"))?;
    let transcript: PassthroughTranscript = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow!("presentation JSON did not match expected shape: {e}"))?;

    if !host_matches(&transcript.server_name, &req.expected_domain) {
        return Err(anyhow!(
            "server name {:?} does not match expectedDomain {:?}",
            transcript.server_name,
            req.expected_domain
        ));
    }

    Ok(VerifyOutcome {
        transcript: Transcript {
            sent: transcript.sent,
            received: transcript.received,
            server_name: transcript.server_name,
        },
        notary_key: None,
    })
}

#[derive(Deserialize)]
struct PassthroughTranscript {
    sent: String,
    received: String,
    #[serde(rename = "serverName")]
    server_name: String,
}

/// Exact-match domain check, with the small concession that the
/// recorded server name is allowed to be `<expected>` or `<expected>:<port>`.
/// `pub(crate)` so the real-verification module (`tlsn`) reuses the same rule.
pub(crate) fn host_matches(server_name: &str, expected: &str) -> bool {
    let trimmed = server_name.split(':').next().unwrap_or(server_name);
    trimmed.eq_ignore_ascii_case(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_is_case_insensitive() {
        assert!(host_matches("Example.com", "example.com"));
        assert!(host_matches("EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn host_matches_strips_port() {
        assert!(host_matches("example.com:443", "example.com"));
    }

    #[test]
    fn host_matches_rejects_subdomains_and_unrelated_domains() {
        assert!(!host_matches("evil.example.com", "example.com"));
        assert!(!host_matches("other.com", "example.com"));
    }

    #[test]
    fn passthrough_rejects_server_name_mismatch() {
        let payload = serde_json::to_string(&serde_json::json!({
            "sent": "",
            "received": "",
            "serverName": "evil.test",
        }))
        .unwrap();
        let req = VerifyRequest {
            presentation: B64.encode(payload),
            expected_domain: "example.com".to_string(),
        };
        let result = verify_passthrough(&req);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("does not match expectedDomain"));
    }

    #[test]
    fn passthrough_returns_transcript_on_match() {
        let payload = serde_json::to_string(&serde_json::json!({
            "sent": "GET / HTTP/1.1\r\n",
            "received": "HTTP/1.1 200 OK\r\n\r\nhello",
            "serverName": "example.com",
        }))
        .unwrap();
        let req = VerifyRequest {
            presentation: B64.encode(payload),
            expected_domain: "example.com".to_string(),
        };
        let transcript = verify_passthrough(&req).unwrap().transcript;
        assert_eq!(transcript.server_name, "example.com");
        assert!(transcript.received.contains("hello"));
    }

    #[test]
    fn passthrough_rejects_non_base64() {
        let req = VerifyRequest {
            presentation: "!!! not base64 !!!".to_string(),
            expected_domain: "example.com".to_string(),
        };
        assert!(verify_passthrough(&req).is_err());
    }

    #[test]
    fn passthrough_returns_no_notary_key() {
        let payload = serde_json::to_string(&serde_json::json!({
            "sent": "",
            "received": "",
            "serverName": "example.com",
        }))
        .unwrap();
        let req = VerifyRequest {
            presentation: B64.encode(payload),
            expected_domain: "example.com".to_string(),
        };
        let outcome = verify_passthrough(&req).unwrap();
        assert!(outcome.notary_key.is_none());
    }
}
