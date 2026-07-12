//! `/authorize` — where the **resource owner** (you) is authenticated. A valid
//! `client_id`/`redirect_uri`/PKCE request renders a login page; a successful
//! passkey assertion (or password fallback) mints a single-use authorization
//! code bound to the request.

use axum::Json;
use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RequestChallengeResponse};

use crate::app::AppState;
use crate::auth::password;
use crate::auth::session::{AuthCode, AuthorizeContext};
use crate::oauth::error::{
    OAuthError, bad_request, forbidden, server_error, too_many_requests, unauthorized,
};
use crate::oauth::pages;

/// OAuth 2.1 authorization request parameters. Echoed verbatim into the login
/// page and revalidated on every POST — the browser is never trusted to have
/// preserved them.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizeParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

/// GET /authorize — validate, then render the login page (or an error page).
pub async fn page(
    State(state): State<AppState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    match validate(&state, &params) {
        Ok(_) => {
            let allow_password = state.config().allow_password_auth;
            match pages::authorize_page(&params, allow_password) {
                Ok(page) => page.into_response(),
                Err(err) => {
                    tracing::error!(error = %err, "cannot render authorization page");
                    (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        Html(error_page("internal error")),
                    )
                        .into_response()
                }
            }
        }
        Err(err) => (err.status(), Html(error_page(err.message()))).into_response(),
    }
}

#[derive(Serialize)]
pub struct StartResponse {
    sid: String,
    options: RequestChallengeResponse,
}

/// POST /authorize/start — begin the passkey assertion ceremony.
pub async fn start(
    State(state): State<AppState>,
    Json(params): Json<AuthorizeParams>,
) -> Result<Json<StartResponse>, OAuthError> {
    let ctx = validate(&state, &params)?;

    let passkeys: Vec<Passkey> =
        state.with_creds(|c| c.passkeys.iter().map(|p| p.credential.clone()).collect());
    if passkeys.is_empty() {
        return Err(forbidden("no passkey is enrolled; use the password option"));
    }

    let (rcr, auth_state) = state
        .webauthn()
        .start_passkey_authentication(&passkeys)
        .map_err(|e| server_error("start_passkey_authentication", e))?;

    let sid = state.sessions().put_authentication(auth_state, ctx);
    Ok(Json(StartResponse { sid, options: rcr }))
}

#[derive(Deserialize)]
pub struct FinishRequest {
    sid: String,
    credential: PublicKeyCredential,
}

/// POST /authorize/finish — verify the assertion, update the credential's sign
/// counter, and mint an authorization code.
pub async fn finish(
    State(state): State<AppState>,
    Json(req): Json<FinishRequest>,
) -> Result<Json<Value>, OAuthError> {
    let (auth_state, ctx) = state
        .sessions()
        .take_authentication(&req.sid)
        .ok_or_else(|| bad_request("authorization ceremony expired or unknown"))?;

    let result = state
        .webauthn()
        .finish_passkey_authentication(&req.credential, &auth_state)
        .map_err(|e| {
            tracing::warn!(error = %e, "passkey assertion failed verification");
            unauthorized("passkey verification failed")
        })?;

    // Apply the authenticator's new sign counter (clone detection lives in
    // `update_credential`). `Some(_)` means the credential id matched one we hold.
    let matched = state
        .mutate_creds(|c| {
            c.passkeys
                .iter_mut()
                .any(|p| p.credential.update_credential(&result).is_some())
        })
        .map_err(|e| server_error("persist sign counter", e))?;

    if !matched {
        return Err(unauthorized("passkey verification failed"));
    }

    let redirect = mint_code_and_redirect(&state, ctx)?;
    Ok(Json(json!({ "redirect": redirect })))
}

/// POST /authorize/password — password fallback (only when enabled).
pub async fn password_login(
    State(state): State<AppState>,
    Json(body): Json<PasswordRequest>,
) -> Result<Json<Value>, OAuthError> {
    let ctx = validate(&state, &body.params)?;

    if !state.config().allow_password_auth {
        return Err(forbidden("password authentication is disabled"));
    }

    if let Some(remaining) = state.sessions().password_lock_remaining() {
        return Err(too_many_requests(remaining.as_secs()));
    }
    let hash = state
        .with_creds(|c| c.recovery_password_hash.clone())
        .ok_or_else(|| forbidden("password authentication is not configured"))?;
    if !password::verify(&body.password, &hash) {
        state.sessions().record_password_failure();
        return Err(unauthorized("invalid recovery password"));
    }
    state.sessions().record_password_success();

    let redirect = mint_code_and_redirect(&state, ctx)?;
    Ok(Json(json!({ "redirect": redirect })))
}

#[derive(Deserialize)]
pub struct PasswordRequest {
    password: String,
    #[serde(flatten)]
    params: AuthorizeParams,
}

/// Validates the OAuth request against registered client metadata and PKCE
/// requirements, producing the context an authorization code will be bound to.
fn validate(state: &AppState, params: &AuthorizeParams) -> Result<AuthorizeContext, OAuthError> {
    if params.response_type != "code" {
        return Err(bad_request("response_type must be 'code'"));
    }
    if params.code_challenge_method != "S256" {
        return Err(bad_request("code_challenge_method must be 'S256'"));
    }
    if params.code_challenge.is_empty() {
        return Err(bad_request("code_challenge is required"));
    }

    let redirect_ok = state.with_creds(|c| {
        c.oauth_clients
            .get(&params.client_id)
            .is_some_and(|client| {
                client
                    .redirect_uris
                    .iter()
                    .any(|u| u == &params.redirect_uri)
            })
    });
    if !redirect_ok {
        // A bad client or redirect must never be echoed back via a redirect.
        return Err(bad_request("unknown client_id or redirect_uri mismatch"));
    }

    Ok(AuthorizeContext {
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        code_challenge: params.code_challenge.clone(),
        resource: params.resource.clone(),
        state: params.state.clone(),
    })
}

fn mint_code_and_redirect(state: &AppState, ctx: AuthorizeContext) -> Result<String, OAuthError> {
    let mut redirect = Url::parse(&ctx.redirect_uri)
        .map_err(|_| bad_request("redirect_uri is not a valid URL"))?;

    let code = state.sessions().put_auth_code(AuthCode {
        client_id: ctx.client_id.clone(),
        redirect_uri: ctx.redirect_uri.clone(),
        code_challenge: ctx.code_challenge.clone(),
        resource: ctx.resource.clone(),
    });

    redirect.query_pairs_mut().append_pair("code", &code);
    if let Some(s) = &ctx.state {
        redirect.query_pairs_mut().append_pair("state", s);
    }
    Ok(redirect.to_string())
}

fn error_page(message: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fsgate — authorization error</title>
<style>body{{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#0b0d12;color:#e7e9ee;margin:0;min-height:100dvh;display:grid;place-items:center;padding:24px}}
.card{{max-width:380px;background:#151922;border:1px solid #232936;border-radius:16px;padding:28px}}
h1{{font-size:18px;margin:0 0 8px}}p{{color:#9aa3b2;font-size:14px;margin:0}}</style></head>
<body><main class="card"><h1>Authorization error</h1><p>{message}</p></main></body></html>"#,
        message = html_escape(message),
    )
}

/// Minimal HTML-attribute/body escaping for the one interpolated error string.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use axum::http::StatusCode;

    use super::*;
    use crate::app::AppState;
    use crate::auth::random_token;
    use crate::config::Config;
    use crate::credentials::{Credentials, OAuthClient};

    const CLIENT_ID: &str = "client_test";
    const REDIRECT_URI: &str = "https://claude.ai/cb";

    fn state_with_client() -> (AppState, PathBuf) {
        let dir = std::env::temp_dir().join(format!("fsgate-authz-test-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = Config {
            root: dir.clone(),
            public_origin: Url::parse("https://fsgate.example").unwrap(),
            state_dir: dir.clone(),
            oauth_password: None,
            allow_password_auth: true,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            mcp_path: "/".to_string(),
            token_signing_key: Some("k".to_string()),
        };
        let mut creds = Credentials {
            owner_handle: Some("owner".to_string()),
            token_signing_key: Some("k".to_string()),
            ..Credentials::default()
        };
        creds.oauth_clients.insert(
            CLIENT_ID.to_string(),
            OAuthClient {
                redirect_uris: vec![REDIRECT_URI.to_string()],
            },
        );
        let webauthn = crate::auth::webauthn::build(&config).unwrap();
        (AppState::new(config, creds, webauthn), dir)
    }

    fn valid_params() -> AuthorizeParams {
        AuthorizeParams {
            response_type: "code".to_string(),
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            resource: None,
            state: None,
        }
    }

    #[test]
    fn validate_accepts_a_well_formed_request_for_a_registered_client() {
        let (state, dir) = state_with_client();
        let ctx = validate(&state, &valid_params()).expect("valid request");
        assert_eq!(ctx.client_id, CLIENT_ID);
        assert_eq!(ctx.redirect_uri, REDIRECT_URI);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_rejects_bad_response_type_method_and_missing_challenge() {
        let (state, dir) = state_with_client();

        let mut p = valid_params();
        p.response_type = "token".to_string();
        assert_eq!(
            validate(&state, &p).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );

        let mut p = valid_params();
        p.code_challenge_method = "plain".to_string();
        assert!(validate(&state, &p).is_err());

        let mut p = valid_params();
        p.code_challenge = String::new();
        assert!(validate(&state, &p).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_rejects_unknown_client_and_redirect_mismatch() {
        let (state, dir) = state_with_client();

        let mut p = valid_params();
        p.client_id = "client_unknown".to_string();
        assert!(validate(&state, &p).is_err());

        let mut p = valid_params();
        p.redirect_uri = "https://claude.ai/other".to_string();
        assert!(validate(&state, &p).is_err());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mint_code_appends_the_code_and_optional_state() {
        let (state, dir) = state_with_client();

        let ctx = AuthorizeContext {
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            code_challenge: "challenge".to_string(),
            resource: None,
            state: None,
        };
        let redirect = mint_code_and_redirect(&state, ctx).unwrap();
        assert!(redirect.starts_with("https://claude.ai/cb?code="));
        assert!(!redirect.contains("state="));

        let ctx_state = AuthorizeContext {
            client_id: CLIENT_ID.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            code_challenge: "challenge".to_string(),
            resource: Some("https://fsgate.example".to_string()),
            state: Some("xyz-state".to_string()),
        };
        let redirect = mint_code_and_redirect(&state, ctx_state).unwrap();
        assert!(redirect.contains("code="));
        assert!(redirect.contains("state=xyz-state"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mint_code_rejects_an_unparseable_redirect_uri() {
        let (state, dir) = state_with_client();
        let ctx = AuthorizeContext {
            client_id: CLIENT_ID.to_string(),
            redirect_uri: "not a url".to_string(),
            code_challenge: "challenge".to_string(),
            resource: None,
            state: None,
        };
        assert!(mint_code_and_redirect(&state, ctx).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn error_page_escapes_html_metacharacters() {
        let page = error_page("<b>&\"bad\"</b>");
        assert!(page.contains("&lt;b&gt;&amp;"));
        assert!(!page.contains("<b>&"));
        // html_escape is exercised directly too.
        assert_eq!(html_escape("a<b>&c"), "a&lt;b&gt;&amp;c");
    }

    #[test]
    fn authorization_page_escapes_script_terminators_in_oauth_params() {
        let payload = "</script><script>alert('xss')</script>";
        let params = AuthorizeParams {
            response_type: "code".to_string(),
            client_id: "client_test".to_string(),
            redirect_uri: "https://claude.ai/api/mcp/auth_callback".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            resource: None,
            state: Some(payload.to_string()),
        };

        let Html(page) = pages::authorize_page(&params, true).unwrap();
        assert!(!page.contains(payload));
        assert!(page.contains(r"\u003c/script\u003e"));
    }
}
