//! Bearer-token middleware guarding the MCP transport.
//!
//! Every MCP request must carry `Authorization: Bearer <jwt>` where the JWT was
//! issued by `/token`, is unexpired, and is bound to this resource
//! (`aud`/`iss` = the public origin) and to the owner (`sub` = owner handle). A
//! failure returns `401` with an RFC 9728 `WWW-Authenticate` challenge so an
//! unauthenticated client can bootstrap discovery.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::app::AppState;
use crate::auth::jwt;
use crate::oauth::discovery;

pub async fn require_owner_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if authenticate(&state, &request).is_ok() {
        next.run(request).await
    } else {
        unauthorized(&state)
    }
}

fn authenticate(state: &AppState, request: &Request) -> Result<(), ()> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(())?;

    let (signing_key, owner_handle) =
        state.with_creds(|c| (c.token_signing_key.clone(), c.owner_handle.clone()));
    let signing_key = signing_key.ok_or(())?;
    let owner_handle = owner_handle.ok_or(())?;

    let origin = state.origin();
    let claims = jwt::verify(&signing_key, token, &origin, &origin).map_err(|_| ())?;
    if claims.sub != owner_handle {
        return Err(());
    }
    Ok(())
}

fn unauthorized(state: &AppState) -> Response {
    let metadata = discovery::resource_metadata_url(state);
    let challenge = format!("Bearer resource_metadata=\"{metadata}\"");
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, challenge)],
        Json(json!({
            "error": "unauthorized",
            "error_description": "a valid owner access token is required",
        })),
    )
        .into_response()
}
