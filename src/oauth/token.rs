//! `/token` — exchanges an authorization code (with PKCE proof) or a refresh
//! token for a short-lived JWT access token. Refresh tokens rotate on every use.

use axum::Json;
use axum::extract::{Form, State};
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::auth::jwt;
use crate::auth::pkce;
use crate::auth::session::Refresh;
use crate::oauth::error::{OAuthError, bad_request_code, invalid_grant, server_error};

/// Access-token lifetime. Short by design; the refresh token carries longevity.
const ACCESS_TTL_SECS: u64 = 15 * 60;

/// OAuth 2.1 token request (`application/x-www-form-urlencoded`). One struct
/// covers both grants; presence is checked per grant type.
#[derive(Deserialize)]
pub struct TokenRequest {
    #[serde(default)]
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
}

pub async fn token(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthError> {
    match req.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(&state, req),
        "refresh_token" => refresh_token_grant(&state, req),
        other => Err(bad_request_code(
            "unsupported_grant_type",
            &format!("unsupported grant_type: {other}"),
        )),
    }
}

fn authorization_code_grant(
    state: &AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let code = req.code.ok_or_else(|| invalid_grant("code is required"))?;
    let verifier = req
        .code_verifier
        .ok_or_else(|| invalid_grant("code_verifier is required"))?;
    let client_id = req
        .client_id
        .ok_or_else(|| invalid_grant("client_id is required"))?;
    let redirect_uri = req
        .redirect_uri
        .ok_or_else(|| invalid_grant("redirect_uri is required"))?;

    let stored = state
        .sessions()
        .take_auth_code(&code)
        .ok_or_else(|| invalid_grant("authorization code is invalid or expired"))?;

    if stored.client_id != client_id {
        return Err(invalid_grant("client_id mismatch"));
    }
    if stored.redirect_uri != redirect_uri {
        return Err(invalid_grant("redirect_uri mismatch"));
    }
    if !pkce::verify_s256(&verifier, &stored.code_challenge) {
        return Err(invalid_grant("PKCE verification failed"));
    }

    // `resource` (RFC 8707) is captured at /authorize; audience enforcement
    // against it is a hardening follow-up. Access tokens currently bind `aud` to
    // the public origin, which is the canonical resource for this server.
    tracing::debug!(resource = ?stored.resource, %client_id, "issuing tokens for authorization code");
    issue_tokens(state, &client_id)
}

fn refresh_token_grant(
    state: &AppState,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, OAuthError> {
    let token = req
        .refresh_token
        .ok_or_else(|| invalid_grant("refresh_token is required"))?;

    // Single-use: taking it here rotates it out. A replay of the old token fails.
    let stored = state
        .sessions()
        .take_refresh(&token)
        .ok_or_else(|| invalid_grant("refresh token is invalid or expired"))?;

    if let Some(client_id) = &req.client_id
        && client_id != &stored.client_id
    {
        return Err(invalid_grant("client_id mismatch"));
    }

    issue_tokens(state, &stored.client_id)
}

/// Mints a fresh access JWT and a rotated refresh token bound to `client_id`.
fn issue_tokens(state: &AppState, client_id: &str) -> Result<Json<TokenResponse>, OAuthError> {
    let (signing_key, owner_handle) =
        state.with_creds(|c| (c.token_signing_key.clone(), c.owner_handle.clone()));
    let signing_key =
        signing_key.ok_or_else(|| server_error("signing_key", "token signing key missing"))?;
    let owner_handle =
        owner_handle.ok_or_else(|| server_error("owner_handle", "owner handle missing"))?;

    let origin = state.origin();
    let access_token = jwt::issue(
        &signing_key,
        &owner_handle,
        &origin,
        &origin,
        ACCESS_TTL_SECS,
    )
    .map_err(|e| server_error("issue access token", e))?;

    let refresh_token = state.sessions().put_refresh(Refresh {
        client_id: client_id.to_string(),
    });

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_SECS,
        refresh_token,
    }))
}
