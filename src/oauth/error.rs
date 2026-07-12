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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn bad_request_maps_to_400_invalid_request() {
        let err = bad_request("bad input");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.message(), "bad input");
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn invalid_grant_maps_to_400() {
        let err = invalid_grant("nope");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        // The rendered Display carries the code for logs.
        assert!(err.to_string().starts_with("invalid_grant:"));
    }

    #[test]
    fn bad_request_code_carries_the_supplied_code() {
        let err = bad_request_code("unsupported_grant_type", "no such grant");
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
        assert_eq!(err.message(), "no such grant");
        assert!(err.to_string().starts_with("unsupported_grant_type:"));
    }

    #[test]
    fn unauthorized_maps_to_401() {
        let err = unauthorized("who are you");
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.message(), "who are you");
    }

    #[test]
    fn forbidden_maps_to_403() {
        let err = forbidden("not allowed");
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        assert_eq!(err.message(), "not allowed");
    }

    #[test]
    fn too_many_requests_maps_to_429_with_retry_after_header() {
        let err = too_many_requests(42);
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(err.message().contains("42s"));

        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
    }

    #[test]
    fn dcr_rate_limited_floors_retry_after_at_one_second() {
        // A sub-second remaining duration must still advertise at least 1s.
        let err = dcr_rate_limited(Duration::from_millis(200));
        match &err {
            OAuthError::RateLimited { retry_after, .. } => assert_eq!(*retry_after, 1),
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);

        let resp = dcr_rate_limited(Duration::from_secs(90)).into_response();
        assert_eq!(
            resp.headers()
                .get(header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("90")
        );
    }

    #[test]
    fn capacity_exceeded_maps_to_503() {
        let err = capacity_exceeded("registry full");
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.message(), "registry full");
        assert_eq!(
            err.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn server_error_hides_the_cause_behind_a_generic_500() {
        let err = server_error("while doing X", "secret detail leaked in logs only");
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // The body/message must never disclose the underlying cause.
        assert_eq!(err.message(), "internal error");
        assert_eq!(err.to_string(), "server_error");
        assert_eq!(
            err.into_response().status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
