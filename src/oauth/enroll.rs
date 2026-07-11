//! Passkey enrollment — the one moment an attacker could inject *their* key and
//! become "you". Therefore it is password-gated and self-locking: once a single
//! passkey exists, `/enroll` refuses to add more without a fresh owner ceremony.

use axum::Json;
use axum::extract::State;
use axum::response::Html;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, Passkey, RegisterPublicKeyCredential};

use crate::app::AppState;
use crate::auth::password;
use crate::credentials::StoredPasskey;
use crate::oauth::error::{
    OAuthError, bad_request, forbidden, server_error, too_many_requests, unauthorized,
};
use crate::oauth::{now_rfc3339, pages};

pub async fn page() -> Result<Html<String>, OAuthError> {
    pages::enroll_page().map_err(|e| server_error("render enrollment page", e))
}

#[derive(Deserialize)]
pub struct StartRequest {
    password: String,
}

#[derive(Serialize)]
pub struct StartResponse {
    sid: String,
    options: CreationChallengeResponse,
}

pub async fn start(
    State(state): State<AppState>,
    Json(req): Json<StartRequest>,
) -> Result<Json<StartResponse>, OAuthError> {
    // Gate 1: recovery password. Gate 2: self-lock once any passkey is enrolled.
    let (hash, handle, already_enrolled) = state.with_creds(|c| {
        (
            c.recovery_password_hash.clone(),
            c.owner_handle.clone(),
            !c.passkeys.is_empty(),
        )
    });

    if already_enrolled {
        return Err(forbidden("enrollment is locked: a passkey already exists"));
    }
    if let Some(remaining) = state.sessions().password_lock_remaining() {
        return Err(too_many_requests(remaining.as_secs()));
    }
    let hash = hash.ok_or_else(|| forbidden("enrollment gate is not configured"))?;
    if !password::verify(&req.password, &hash) {
        state.sessions().record_password_failure();
        return Err(unauthorized("invalid recovery password"));
    }
    state.sessions().record_password_success();

    let handle = handle
        .as_deref()
        .and_then(|h| Uuid::parse_str(h).ok())
        .ok_or_else(|| server_error("owner_handle", "missing or unparseable owner handle"))?;

    let (ccr, reg_state) = state
        .webauthn()
        .start_passkey_registration(handle, "fsgate owner", "fsgate owner", None)
        .map_err(|e| server_error("start_passkey_registration", e))?;

    let sid = state.sessions().put_registration(reg_state);
    Ok(Json(StartResponse { sid, options: ccr }))
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    sid: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<Value>, OAuthError> {
    let reg_state = state
        .sessions()
        .take_registration(&req.sid)
        .ok_or_else(|| bad_request("enrollment ceremony expired or unknown"))?;

    let passkey: Passkey = state
        .webauthn()
        .finish_passkey_registration(&req.credential, &reg_state)
        .map_err(|e| {
            tracing::warn!(error = %e, "passkey registration failed verification");
            unauthorized("passkey registration failed verification")
        })?;

    // Re-check the self-lock under the write lock to close a concurrent-enroll race.
    let stored = state
        .mutate_creds(|c| {
            if !c.passkeys.is_empty() {
                return false;
            }
            c.passkeys.push(StoredPasskey {
                credential: passkey,
                nickname: None,
                created_at: now_rfc3339(),
            });
            true
        })
        .map_err(|e| server_error("persist passkey", e))?;

    if !stored {
        return Err(forbidden("enrollment is locked: a passkey already exists"));
    }

    tracing::info!("passkey enrolled");
    Ok(Json(json!({ "status": "ok" })))
}
