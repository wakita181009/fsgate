//! Shared JSON error responses for the OAuth/WebAuthn endpoints.
//!
//! Bodies follow the OAuth 2.0 error shape (`error` + `error_description`) so
//! both Claude's token client and the browser ceremony JS can read them
//! uniformly. Messages are deliberately generic — they never disclose whether a
//! password was wrong versus a user unknown.

use axum::Json;
use axum::http::StatusCode;
use serde_json::{Value, json};

pub type OAuthError = (StatusCode, Json<Value>);

pub fn error(status: StatusCode, code: &str, description: &str) -> OAuthError {
    (
        status,
        Json(json!({ "error": code, "error_description": description })),
    )
}

pub fn bad_request(description: &str) -> OAuthError {
    error(StatusCode::BAD_REQUEST, "invalid_request", description)
}

pub fn invalid_grant(description: &str) -> OAuthError {
    error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

pub fn unauthorized(description: &str) -> OAuthError {
    error(StatusCode::UNAUTHORIZED, "access_denied", description)
}

pub fn forbidden(description: &str) -> OAuthError {
    error(StatusCode::FORBIDDEN, "access_denied", description)
}

pub fn too_many_requests(retry_after_secs: u64) -> OAuthError {
    error(
        StatusCode::TOO_MANY_REQUESTS,
        "too_many_requests",
        &format!("too many failed attempts; retry in {retry_after_secs}s"),
    )
}

/// Logs the underlying cause server-side and returns an opaque 500 to the client.
pub fn server_error(context: &str, err: impl std::fmt::Display) -> OAuthError {
    tracing::error!(context, error = %err, "internal error");
    error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "internal error",
    )
}
