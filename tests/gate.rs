//! The Bearer gate is the security boundary: the MCP transport must be
//! unreachable without a valid owner access token. These tests exercise the
//! real middleware wired into the production router.

#[path = "common/harness.rs"]
mod common;

use axum::http::{StatusCode, header};
use common::{MCP_PATH, ORIGIN, TestServer, get, send, send_full};
use fsgate::auth::jwt;

fn bearer(uri: &str, token: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(axum::body::Body::empty())
        .expect("build request")
}

#[tokio::test]
async fn rejects_mcp_without_a_token() {
    let server = TestServer::new();
    let resp = send_full(&server, get(MCP_PATH)).await;

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let challenge = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        challenge.contains("resource_metadata"),
        "401 must advertise resource metadata for discovery, got: {challenge:?}"
    );
}

#[tokio::test]
async fn rejects_a_malformed_bearer_token() {
    let server = TestServer::new();
    let (status, _) = send(&server, bearer(MCP_PATH, "not-a-jwt")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_a_token_signed_with_the_wrong_key() {
    let server = TestServer::new();
    let forged = jwt::issue("attacker-key", "test-owner-handle", ORIGIN, ORIGIN, 300).unwrap();
    let (status, _) = send(&server, bearer(MCP_PATH, &forged)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_a_token_for_a_different_audience() {
    let server = TestServer::new();
    // Signed with the real key, but audience is another resource server.
    let wrong_aud = jwt::issue(
        common::SIGNING_KEY,
        "test-owner-handle",
        "https://evil.example",
        "https://evil.example",
        300,
    )
    .unwrap();
    let (status, _) = send(&server, bearer(MCP_PATH, &wrong_aud)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_a_token_for_a_different_subject() {
    let server = TestServer::new();
    // Correct key/audience, but not the owner handle.
    let not_owner = jwt::issue(common::SIGNING_KEY, "someone-else", ORIGIN, ORIGIN, 300).unwrap();
    let (status, _) = send(&server, bearer(MCP_PATH, &not_owner)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_owner_token_passes_the_gate() {
    let server = TestServer::new();
    let (status, _) = send(&server, bearer(MCP_PATH, &server.owner_token())).await;
    // Past the gate, the MCP transport handles (and may reject) the bare GET on
    // its own protocol terms — the point is that it is no longer a 401.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "a valid owner token must clear the Bearer gate"
    );
}
