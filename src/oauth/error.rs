//! Shared JSON error responses for the OAuth/WebAuthn endpoints.
//!
//! Bodies follow the OAuth 2.0 error shape (`error` + `error_description`) so
//! both Claude's token client and the browser ceremony JS can read them
//! uniformly. Messages are deliberately generic — they never disclose whether a
//! password was wrong versus a user unknown.

use std::time::Duration;

use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// An error from any OAuth/WebAuthn endpoint. Rendered as an RFC 6749-style JSON
/// body; some variants also carry response headers (e.g. `Retry-After`).
/// Construct via the helper functions below so error codes stay consistent.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// 400 with an explicit OAuth error code (`invalid_request`, `invalid_grant`,
    /// `invalid_client_metadata`, `unsupported_grant_type`, …).
    #[error("{code}: {description}")]
    BadRequest {
        code: &'static str,
        description: String,
    },
    /// 401 — owner authentication failed.
    #[error("access_denied: {0}")]
    Unauthorized(String),
    /// 403 — request understood but refused (disabled path, locked enrollment).
    #[error("access_denied: {0}")]
    Forbidden(String),
    /// 429 — rate limited; emits a `Retry-After` header.
    #[error("{code}: {description}")]
    RateLimited {
        code: &'static str,
        description: String,
        retry_after: u64,
    },
    /// 503 — a bounded resource is temporarily exhausted.
    #[error("{code}: {description}")]
    Unavailable {
        code: &'static str,
        description: String,
    },
    /// 500 — the cause is logged server-side; the body is always generic.
    #[error("server_error")]
    Internal,
}

impl OAuthError {
    fn parts(&self) -> (StatusCode, &'static str, &str) {
        match self {
            OAuthError::BadRequest { code, description } => {
                (StatusCode::BAD_REQUEST, code, description.as_str())
            }
            OAuthError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, "access_denied", d.as_str()),
            OAuthError::Forbidden(d) => (StatusCode::FORBIDDEN, "access_denied", d.as_str()),
            OAuthError::RateLimited {
                code, description, ..
            } => (StatusCode::TOO_MANY_REQUESTS, code, description.as_str()),
            OAuthError::Unavailable { code, description } => {
                (StatusCode::SERVICE_UNAVAILABLE, code, description.as_str())
            }
            OAuthError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "internal error",
            ),
        }
    }

    /// HTTP status this error maps to (used when rendering the HTML error page).
    pub fn status(&self) -> StatusCode {
        self.parts().0
    }

    /// Human-readable description, safe to display (it never reveals which secret
    /// failed).
    pub fn message(&self) -> &str {
        self.parts().2
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let retry_after = match &self {
            OAuthError::RateLimited { retry_after, .. } => Some(*retry_after),
            _ => None,
        };
        let (status, code, description) = self.parts();
        let body = Json(json!({ "error": code, "error_description": description }));
        match retry_after {
            Some(secs) => (status, [(header::RETRY_AFTER, secs.to_string())], body).into_response(),
            None => (status, body).into_response(),
        }
    }
}

pub fn bad_request(description: &str) -> OAuthError {
    OAuthError::BadRequest {
        code: "invalid_request",
        description: description.to_string(),
    }
}

pub fn invalid_grant(description: &str) -> OAuthError {
    OAuthError::BadRequest {
        code: "invalid_grant",
        description: description.to_string(),
    }
}

/// 400 with a caller-specified OAuth error code (for codes without a dedicated
/// helper, e.g. `unsupported_grant_type`, `invalid_client_metadata`).
pub fn bad_request_code(code: &'static str, description: &str) -> OAuthError {
    OAuthError::BadRequest {
        code,
        description: description.to_string(),
    }
}

pub fn unauthorized(description: &str) -> OAuthError {
    OAuthError::Unauthorized(description.to_string())
}

pub fn forbidden(description: &str) -> OAuthError {
    OAuthError::Forbidden(description.to_string())
}

pub fn too_many_requests(retry_after_secs: u64) -> OAuthError {
    OAuthError::RateLimited {
        code: "too_many_requests",
        description: format!("too many failed attempts; retry in {retry_after_secs}s"),
        retry_after: retry_after_secs,
    }
}

/// DCR client-registration rate limit (429, `temporarily_unavailable`).
pub fn dcr_rate_limited(retry_after: Duration) -> OAuthError {
    let secs = retry_after.as_secs().max(1);
    OAuthError::RateLimited {
        code: "temporarily_unavailable",
        description: format!("too many client registrations; retry in {secs}s"),
        retry_after: secs,
    }
}

/// 503 for a bounded registry that is full (`server_error`).
pub fn capacity_exceeded(description: &str) -> OAuthError {
    OAuthError::Unavailable {
        code: "server_error",
        description: description.to_string(),
    }
}

/// Logs the underlying cause server-side and returns an opaque 500 to the client.
pub fn server_error(context: &str, err: impl std::fmt::Display) -> OAuthError {
    tracing::error!(context, error = %err, "internal error");
    OAuthError::Internal
}
