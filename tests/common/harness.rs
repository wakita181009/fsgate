//! Shared harness for fsgate integration tests.
//!
//! Pulled into each test binary with `#[path = "common/harness.rs"] mod common;`
//! — a plain file (not a `mod.rs`, per the project's 2024-edition module rule)
//! kept in a subdirectory so Cargo does not compile it as its own test binary.
//! Any given binary uses only a subset of these helpers, so `dead_code` here is
//! expected.
//!
//! Builds the exact production router (`fsgate::build_router`) over throwaway
//! temp directories, with a fixed token signing key and owner handle so tests
//! can mint valid owner access tokens and seed authorization codes directly —
//! no WebAuthn ceremony required.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use url::Url;

use fsgate::app::AppState;
use fsgate::auth::{self, webauthn};
use fsgate::config::Config;
use fsgate::credentials::Credentials;
use fsgate::notes::Notes;

pub const SIGNING_KEY: &str = "integration-test-signing-key-do-not-ship";
pub const OWNER_HANDLE: &str = "test-owner-handle";
pub const ORIGIN: &str = "https://fsgate.test.example";
pub const MCP_PATH: &str = "/mcp";

/// A fully wired test server plus the temp dirs it owns. Dropping it removes the
/// directories so tests leave nothing behind.
pub struct TestServer {
    state: AppState,
    notes: Arc<Notes>,
    root_dir: PathBuf,
    state_dir: PathBuf,
}

impl TestServer {
    /// Minimal wiring for router-level tests: owner handle + signing key present
    /// (so the Bearer gate and `/token` can operate), no verifier required.
    pub fn new() -> Self {
        let unique = auth::random_token();
        let root_dir = std::env::temp_dir().join(format!("fsgate-it-root-{unique}"));
        let state_dir = std::env::temp_dir().join(format!("fsgate-it-state-{unique}"));
        std::fs::create_dir_all(&root_dir).expect("create test root dir");
        std::fs::create_dir_all(&state_dir).expect("create test state dir");

        let config = Config {
            root: root_dir.clone(),
            public_origin: Url::parse(ORIGIN).expect("parse test origin"),
            state_dir: state_dir.clone(),
            oauth_password: None,
            allow_password_auth: true,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            mcp_path: MCP_PATH.to_string(),
            token_signing_key: Some(SIGNING_KEY.to_string()),
        };

        let creds = Credentials {
            owner_handle: Some(OWNER_HANDLE.to_string()),
            token_signing_key: Some(SIGNING_KEY.to_string()),
            ..Credentials::default()
        };

        let webauthn = webauthn::build(&config).expect("build test webauthn");
        let notes = Arc::new(Notes::new(&root_dir).expect("open test root"));
        let state = AppState::new(config, creds, webauthn);

        Self {
            state,
            notes,
            root_dir,
            state_dir,
        }
    }

    pub fn state(&self) -> &AppState {
        &self.state
    }

    /// A fresh router built from the shared state; each request needs its own
    /// because `oneshot` consumes the router.
    pub fn router(&self) -> Router {
        fsgate::build_router(self.state.clone(), self.notes.clone())
    }

    /// A valid owner access token bound to this server's origin and owner.
    pub fn owner_token(&self) -> String {
        auth::jwt::issue(SIGNING_KEY, OWNER_HANDLE, ORIGIN, ORIGIN, 300).expect("issue owner token")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

/// Sends one request through a fresh router and returns the status and body.
pub async fn send(server: &TestServer, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = server.router().oneshot(req).await.expect("router response");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, bytes)
}

/// Sends one request and returns the status plus the full response (headers).
pub async fn send_full(server: &TestServer, req: Request<Body>) -> axum::response::Response {
    server.router().oneshot(req).await.expect("router response")
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build GET request")
}

pub fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&body).expect("serialize json"),
        ))
        .expect("build POST request")
}

pub fn post_form(uri: &str, pairs: &[(&str, &str)]) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter().copied())
        .finish();
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .expect("build form request")
}

pub fn parse_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("response body is valid json")
}
