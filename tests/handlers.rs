//! HTTP-level coverage of the owner-facing ceremony endpoints: the enrollment
//! and authorization pages and their POST handlers. The WebAuthn success paths
//! need a real authenticator and are exercised manually (see the README threat
//! model); everything up to — and every rejection around — the ceremony is
//! driven here through the production router.

#[path = "common/harness.rs"]
mod common;

use axum::http::StatusCode;
use common::{TestServer, get, parse_json, post_json, send};

const CLIENT_ID: &str = "client_test";
const REDIRECT_URI: &str = "https://claude.ai/cb";

/// A minimally well-formed attestation credential. It deserializes into
/// `RegisterPublicKeyCredential` (the CBOR inside is only parsed later, during
/// the ceremony), which lets the handler run far enough to reject an unknown sid.
fn fake_attestation() -> serde_json::Value {
    serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" },
        "type": "public-key"
    })
}

/// A minimally well-formed assertion credential (for `/authorize/finish`).
fn fake_assertion() -> serde_json::Value {
    serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        },
        "type": "public-key"
    })
}

fn authorize_uri(response_type: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", response_type)
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("code_challenge", "challenge")
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("/authorize?{query}")
}

fn authorize_params() -> serde_json::Value {
    serde_json::json!({
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_challenge": "challenge",
        "code_challenge_method": "S256"
    })
}

// --- Enrollment -----------------------------------------------------------

#[tokio::test]
async fn enroll_page_renders() {
    let server = TestServer::new();
    let (status, body) = send(&server, get("/enroll")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("Enroll a passkey"));
}

#[tokio::test]
async fn enroll_start_is_forbidden_without_a_recovery_password() {
    let server = TestServer::new();
    let (status, body) = send(
        &server,
        post_json(
            "/enroll/start",
            serde_json::json!({ "password": "anything" }),
        ),
    )
    .await;
    // No recovery-password hash is configured: the gate is not set up.
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(parse_json(&body)["error"], "access_denied");
}

#[tokio::test]
async fn enroll_start_rejects_a_wrong_password() {
    let server = TestServer::new();
    server.set_recovery_password("correct horse");
    let (status, _) = send(
        &server,
        post_json("/enroll/start", serde_json::json!({ "password": "wrong" })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_start_locks_out_after_repeated_failures() {
    let server = TestServer::new();
    server.set_recovery_password("correct horse");

    // Five failures arm the lockout; the sixth attempt is rate-limited.
    for _ in 0..5 {
        let (status, _) = send(
            &server,
            post_json("/enroll/start", serde_json::json!({ "password": "wrong" })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send(
        &server,
        post_json("/enroll/start", serde_json::json!({ "password": "wrong" })),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn enroll_start_succeeds_and_returns_a_registration_challenge() {
    let server = TestServer::new();
    // Enrollment parses the owner handle as a UUID before starting the ceremony.
    server.set_owner_handle(&uuid::Uuid::new_v4().to_string());
    server.set_recovery_password("correct horse");

    let (status, body) = send(
        &server,
        post_json(
            "/enroll/start",
            serde_json::json!({ "password": "correct horse" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let resp = parse_json(&body);
    assert!(resp["sid"].as_str().is_some(), "a ceremony sid is returned");
    assert!(
        resp["options"]["publicKey"]["challenge"].as_str().is_some(),
        "a creation challenge is returned"
    );
}

#[tokio::test]
async fn enroll_verify_rejects_an_unknown_ceremony() {
    let server = TestServer::new();
    let (status, body) = send(
        &server,
        post_json(
            "/enroll/verify",
            serde_json::json!({ "sid": "no-such-sid", "credential": fake_attestation() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "invalid_request");
}

// --- Authorization --------------------------------------------------------

#[tokio::test]
async fn authorize_page_renders_the_login_page_for_a_registered_client() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    let (status, body) = send(&server, get(&authorize_uri("code"))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("Authorize access"));
}

#[tokio::test]
async fn authorize_page_shows_an_error_for_an_invalid_request() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    // response_type=token is rejected before any login is offered.
    let (status, body) = send(&server, get(&authorize_uri("token"))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("Authorization error"));
}

#[tokio::test]
async fn authorize_start_is_forbidden_when_no_passkey_is_enrolled() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    let (status, _) = send(&server, post_json("/authorize/start", authorize_params())).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn authorize_finish_rejects_an_unknown_ceremony() {
    let server = TestServer::new();
    let (status, body) = send(
        &server,
        post_json(
            "/authorize/finish",
            serde_json::json!({ "sid": "no-such-sid", "credential": fake_assertion() }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "invalid_request");
}

#[tokio::test]
async fn password_login_is_forbidden_when_disabled() {
    let server = TestServer::with_password_auth(false);
    server.register_client(CLIENT_ID, REDIRECT_URI);
    server.set_recovery_password("correct horse");

    let mut body = authorize_params();
    body["password"] = serde_json::json!("correct horse");
    let (status, resp) = send(&server, post_json("/authorize/password", body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(parse_json(&resp)["error"], "access_denied");
}

#[tokio::test]
async fn password_login_is_forbidden_when_not_configured() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    // Password auth is enabled but no recovery password hash exists.
    let mut body = authorize_params();
    body["password"] = serde_json::json!("whatever");
    let (status, _) = send(&server, post_json("/authorize/password", body)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn password_login_rejects_a_wrong_password() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    server.set_recovery_password("correct horse");

    let mut body = authorize_params();
    body["password"] = serde_json::json!("wrong");
    let (status, _) = send(&server, post_json("/authorize/password", body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn password_login_locks_out_after_repeated_failures() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    server.set_recovery_password("correct horse");

    let mut wrong = authorize_params();
    wrong["password"] = serde_json::json!("wrong");
    for _ in 0..5 {
        let (status, _) = send(&server, post_json("/authorize/password", wrong.clone())).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = send(&server, post_json("/authorize/password", wrong)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn password_login_succeeds_and_returns_a_redirect_with_a_code() {
    let server = TestServer::new();
    server.register_client(CLIENT_ID, REDIRECT_URI);
    server.set_recovery_password("correct horse");

    let mut body = authorize_params();
    body["password"] = serde_json::json!("correct horse");
    body["state"] = serde_json::json!("client-state-123");

    let (status, resp) = send(&server, post_json("/authorize/password", body)).await;
    assert_eq!(status, StatusCode::OK);
    let redirect = parse_json(&resp)["redirect"]
        .as_str()
        .expect("redirect url")
        .to_string();
    assert!(redirect.starts_with(REDIRECT_URI));
    assert!(redirect.contains("code="));
    assert!(redirect.contains("state=client-state-123"));
}
