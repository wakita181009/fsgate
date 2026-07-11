use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::app::AppState;
use crate::credentials::{Credentials, OAuthClient};
use crate::oauth::ALLOWED_REDIRECT_HOSTS;
use crate::oauth::error::{
    OAuthError, bad_request_code, capacity_exceeded, dcr_rate_limited, server_error,
};

const MAX_OAUTH_CLIENTS: usize = 64;
const MAX_REDIRECT_URIS: usize = 4;
const MAX_REDIRECT_URI_LEN: usize = 2048;
const MAX_CLIENT_NAME_LEN: usize = 256;

/// RFC 7591 Dynamic Client Registration request (permissive subset).
///
/// fsgate is single-user, so it does not maintain a real client directory — it
/// only records the `redirect_uris` it must later exact-match. Identical metadata
/// reuses the same public `client_id` so retries cannot grow durable state.
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

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegistrationRequest>,
) -> Result<(StatusCode, Json<RegistrationResponse>), OAuthError> {
    let redirect_uris = validate(&req)?;

    // Registration metadata is idempotent. Claude may retry a DCR request after
    // losing the response; returning the existing public client avoids growing
    // durable state or consuming the creation rate limit.
    if let Some(client_id) = find_existing_client(&state, &redirect_uris) {
        return Ok(response(
            StatusCode::CREATED,
            client_id,
            redirect_uris,
            req.client_name,
        ));
    }

    state
        .sessions()
        .allow_dcr_registration()
        .map_err(dcr_rate_limited)?;

    let client_id = format!("client_{}", uuid::Uuid::new_v4().simple());
    let outcome = state
        .mutate_creds_if(|credentials| register_client(credentials, &client_id, &redirect_uris))
        .map_err(|e| server_error("DCR persistence", e))?;

    let (status, client_id) = match outcome {
        RegistrationOutcome::Created => {
            tracing::info!(%client_id, "registered oauth client via DCR");
            (StatusCode::CREATED, client_id)
        }
        // A concurrent identical request won the race. Reuse its id and do not
        // rewrite the state file.
        RegistrationOutcome::Existing(existing) => (StatusCode::CREATED, existing),
        RegistrationOutcome::Full => {
            return Err(capacity_exceeded("oauth client registry is full"));
        }
    };

    Ok(response(status, client_id, redirect_uris, req.client_name))
}

fn response(
    status: StatusCode,
    client_id: String,
    redirect_uris: Vec<String>,
    client_name: Option<String>,
) -> (StatusCode, Json<RegistrationResponse>) {
    (
        status,
        Json(RegistrationResponse {
            client_id,
            redirect_uris,
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            client_name,
        }),
    )
}

fn validate(req: &RegistrationRequest) -> Result<Vec<String>, OAuthError> {
    if req
        .client_name
        .as_ref()
        .is_some_and(|name| name.len() > MAX_CLIENT_NAME_LEN)
    {
        return Err(invalid("client_name is too long"));
    }
    validate_redirect_uris(&req.redirect_uris)
}

/// Every redirect target must be https and hosted on an allowed Claude domain.
/// This is the guard against open-redirect-based code theft.
fn validate_redirect_uris(uris: &[String]) -> Result<Vec<String>, OAuthError> {
    if uris.is_empty() {
        return Err(invalid("redirect_uris is required and must be non-empty"));
    }
    if uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid("too many redirect_uris"));
    }

    let mut normalized = Vec::with_capacity(uris.len());
    for uri in uris {
        if uri.len() > MAX_REDIRECT_URI_LEN {
            return Err(invalid("redirect_uri is too long"));
        }
        let parsed =
            Url::parse(uri).map_err(|_| invalid(&format!("invalid redirect_uri: {uri}")))?;
        if parsed.scheme() != "https" {
            return Err(invalid(&format!("redirect_uri must be https: {uri}")));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(invalid("redirect_uri must not contain user information"));
        }
        if parsed.fragment().is_some() {
            return Err(invalid("redirect_uri must not contain a fragment"));
        }
        let host = parsed.host_str().unwrap_or_default();
        let allowed = ALLOWED_REDIRECT_HOSTS
            .iter()
            .any(|h| host == *h || host.ends_with(&format!(".{h}")));
        if !allowed {
            return Err(invalid(&format!("redirect_uri host not allowed: {host}")));
        }
        normalized.push(parsed.to_string());
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

/// 400 `invalid_client_metadata` — the RFC 7591 error code for a malformed
/// registration request.
fn invalid(msg: &str) -> OAuthError {
    bad_request_code("invalid_client_metadata", msg)
}

fn find_existing_client(state: &AppState, redirect_uris: &[String]) -> Option<String> {
    state.with_creds(|credentials| {
        credentials
            .oauth_clients
            .iter()
            .find(|(_, client)| client.redirect_uris == redirect_uris)
            .map(|(client_id, _)| client_id.clone())
    })
}

#[derive(Debug, PartialEq, Eq)]
enum RegistrationOutcome {
    Created,
    Existing(String),
    Full,
}

fn register_client(
    credentials: &mut Credentials,
    candidate_id: &str,
    redirect_uris: &[String],
) -> (RegistrationOutcome, bool) {
    if let Some((client_id, _)) = credentials
        .oauth_clients
        .iter()
        .find(|(_, client)| client.redirect_uris == redirect_uris)
    {
        return (RegistrationOutcome::Existing(client_id.clone()), false);
    }
    if credentials.oauth_clients.len() >= MAX_OAUTH_CLIENTS {
        return (RegistrationOutcome::Full, false);
    }

    credentials.oauth_clients.insert(
        candidate_id.to_string(),
        OAuthClient {
            redirect_uris: redirect_uris.to_vec(),
        },
    );
    (RegistrationOutcome::Created, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uris(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn redirect_uris_are_bounded_normalized_and_deduplicated() {
        let normalized = validate_redirect_uris(&uris(&[
            "https://claude.com/callback",
            "https://claude.ai/callback",
            "https://claude.com/callback",
        ]))
        .unwrap();

        assert_eq!(
            normalized,
            uris(&["https://claude.ai/callback", "https://claude.com/callback"])
        );
        assert!(validate_redirect_uris(&["x".repeat(MAX_REDIRECT_URI_LEN + 1)]).is_err());
        assert!(validate_redirect_uris(&uris(&["https://claude.ai/callback#fragment"])).is_err());
    }

    #[test]
    fn duplicate_registration_reuses_existing_client_without_mutation() {
        let mut credentials = Credentials::default();
        let redirect_uris = uris(&["https://claude.ai/callback"]);
        credentials.oauth_clients.insert(
            "client_existing".to_string(),
            OAuthClient {
                redirect_uris: redirect_uris.clone(),
            },
        );

        let result = register_client(&mut credentials, "client_new", &redirect_uris);
        assert_eq!(
            result,
            (
                RegistrationOutcome::Existing("client_existing".to_string()),
                false
            )
        );
        assert_eq!(credentials.oauth_clients.len(), 1);
    }

    #[test]
    fn client_registry_never_grows_past_its_limit() {
        let mut credentials = Credentials::default();
        for index in 0..MAX_OAUTH_CLIENTS {
            credentials.oauth_clients.insert(
                format!("client_{index}"),
                OAuthClient {
                    redirect_uris: uris(&[&format!("https://claude.ai/callback/{index}")]),
                },
            );
        }

        let result = register_client(
            &mut credentials,
            "client_overflow",
            &uris(&["https://claude.ai/overflow"]),
        );
        assert_eq!(result, (RegistrationOutcome::Full, false));
        assert_eq!(credentials.oauth_clients.len(), MAX_OAUTH_CLIENTS);
    }
}
