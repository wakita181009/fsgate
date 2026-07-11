use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::app::AppState;

/// RFC 9728 Protected Resource Metadata.
///
/// Claude fetches this after the initial `401 + WWW-Authenticate` to discover
/// which authorization server guards this resource. fsgate is both, so the AS
/// it points to is itself.
#[derive(Serialize)]
pub struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Vec<String>,
}

/// RFC 8414 Authorization Server Metadata.
#[derive(Serialize)]
pub struct AuthorizationServerMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    registration_endpoint: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
}

pub async fn protected_resource(State(state): State<AppState>) -> Json<ProtectedResourceMetadata> {
    let origin = origin(&state);
    Json(ProtectedResourceMetadata {
        resource: origin.clone(),
        authorization_servers: vec![origin],
        bearer_methods_supported: vec!["header".to_string()],
    })
}

pub async fn authorization_server(
    State(state): State<AppState>,
) -> Json<AuthorizationServerMetadata> {
    let origin = origin(&state);
    Json(AuthorizationServerMetadata {
        issuer: origin.clone(),
        authorization_endpoint: endpoint(&origin, "authorize"),
        token_endpoint: endpoint(&origin, "token"),
        registration_endpoint: endpoint(&origin, "register"),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        // OAuth 2.1 / MCP: only S256 PKCE is acceptable.
        code_challenge_methods_supported: vec!["S256".to_string()],
        // Claude registers as a public client (no client secret).
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
    })
}

/// URL of the resource metadata document, advertised in the `WWW-Authenticate`
/// challenge so an unauthenticated client can begin discovery.
pub fn resource_metadata_url(state: &AppState) -> String {
    endpoint(&origin(state), ".well-known/oauth-protected-resource")
}

fn origin(state: &AppState) -> String {
    state
        .config()
        .public_origin
        .as_str()
        .trim_end_matches('/')
        .to_string()
}

fn endpoint(origin: &str, path: &str) -> String {
    format!("{origin}/{path}")
}
