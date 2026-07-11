use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

use crate::app::AppState;
use crate::oauth::ALLOWED_REDIRECT_HOSTS;
use crate::state::OAuthClient;

/// RFC 7591 Dynamic Client Registration request (permissive subset).
///
/// fsgate is single-user, so it does not maintain a real client directory — it
/// only records the `redirect_uris` it must later exact-match, and issues a
/// fresh public `client_id`.
#[derive(Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegistrationResponse {
    client_id: String,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: &'static str,
    grant_types: Vec<&'static str>,
    response_types: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_name: Option<String>,
}

type DcrError = (StatusCode, Json<Value>);

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<RegistrationResponse>), DcrError> {
    validate_redirect_uris(&req.redirect_uris)?;

    let client_id = format!("client_{}", uuid::Uuid::new_v4().simple());
    let redirect_uris = req.redirect_uris.clone();

    state
        .mutate_creds(|c| {
            c.oauth_clients.insert(
                client_id.clone(),
                OAuthClient {
                    redirect_uris: redirect_uris.clone(),
                },
            );
        })
        .map_err(internal)?;

    tracing::info!(%client_id, "registered oauth client via DCR");

    Ok((
        StatusCode::CREATED,
        Json(RegistrationResponse {
            client_id,
            redirect_uris: req.redirect_uris,
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            client_name: req.client_name,
        }),
    ))
}

/// Every redirect target must be https and hosted on an allowed Claude domain.
/// This is the guard against open-redirect-based code theft.
fn validate_redirect_uris(uris: &[String]) -> Result<(), DcrError> {
    if uris.is_empty() {
        return Err(invalid("redirect_uris is required and must be non-empty"));
    }
    for uri in uris {
        let parsed =
            Url::parse(uri).map_err(|_| invalid(&format!("invalid redirect_uri: {uri}")))?;
        if parsed.scheme() != "https" {
            return Err(invalid(&format!("redirect_uri must be https: {uri}")));
        }
        let host = parsed.host_str().unwrap_or_default();
        let allowed = ALLOWED_REDIRECT_HOSTS
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")));
        if !allowed {
            return Err(invalid(&format!("redirect_uri host not allowed: {host}")));
        }
    }
    Ok(())
}

fn invalid(msg: &str) -> DcrError {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_client_metadata", "error_description": msg })),
    )
}

fn internal(err: anyhow::Error) -> DcrError {
    tracing::error!(error = %err, "DCR persistence failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "server_error" })),
    )
}
