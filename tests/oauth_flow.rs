//! OAuth surface: discovery metadata, Dynamic Client Registration guards, and
//! the `/token` endpoint (authorization-code + PKCE, refresh rotation). The
//! WebAuthn ceremony is bypassed by seeding authorization codes directly, which
//! lets these tests cover the token machinery without a browser.

#[path = "common/harness.rs"]
mod common;

use axum::http::StatusCode;
use common::{ORIGIN, TestServer, get, parse_json, post_form, post_json, send};
use fsgate::auth::jwt;
use fsgate::auth::session::AuthCode;

// RFC 7636 S256 test vector: challenge == BASE64URL(SHA256(verifier)).
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT_URI: &str = "https://claude.ai/cb";
const CLIENT_ID: &str = "client_test";

#[tokio::test]
async fn healthz_is_open() {
    let server = TestServer::new();
    let (status, body) = send(&server, get("/healthz")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"ok");
}

#[tokio::test]
async fn advertises_authorization_server_metadata() {
    let server = TestServer::new();
    let (status, body) = send(&server, get("/.well-known/oauth-authorization-server")).await;
    assert_eq!(status, StatusCode::OK);

    let meta = parse_json(&body);
    assert_eq!(meta["issuer"], ORIGIN);
    assert_eq!(meta["token_endpoint"], format!("{ORIGIN}/token"));
    assert_eq!(meta["registration_endpoint"], format!("{ORIGIN}/register"));
    // OAuth 2.1 / MCP requires S256 PKCE and nothing weaker.
    assert_eq!(
        meta["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
}

#[tokio::test]
async fn advertises_protected_resource_metadata() {
    let server = TestServer::new();
    let (status, body) = send(&server, get("/.well-known/oauth-protected-resource")).await;
    assert_eq!(status, StatusCode::OK);

    let meta = parse_json(&body);
    assert_eq!(meta["resource"], ORIGIN);
    assert_eq!(meta["authorization_servers"], serde_json::json!([ORIGIN]));
}

#[tokio::test]
async fn dcr_registers_an_allowed_redirect_uri() {
    let server = TestServer::new();
    let (status, body) = send(
        &server,
        post_json(
            "/register",
            serde_json::json!({ "redirect_uris": [REDIRECT_URI] }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    let resp = parse_json(&body);
    assert!(
        resp["client_id"].as_str().unwrap().starts_with("client_"),
        "client_id should be a generated public id"
    );
    assert_eq!(resp["redirect_uris"], serde_json::json!([REDIRECT_URI]));
}

#[tokio::test]
async fn dcr_rejects_non_https_redirect() {
    let server = TestServer::new();
    let (status, _) = send(
        &server,
        post_json(
            "/register",
            serde_json::json!({ "redirect_uris": ["http://claude.ai/cb"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dcr_rejects_a_disallowed_host() {
    let server = TestServer::new();
    let (status, _) = send(
        &server,
        post_json(
            "/register",
            serde_json::json!({ "redirect_uris": ["https://evil.example/cb"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dcr_rejects_empty_redirect_uris() {
    let server = TestServer::new();
    let (status, _) = send(
        &server,
        post_json("/register", serde_json::json!({ "redirect_uris": [] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dcr_is_idempotent_for_identical_metadata() {
    let server = TestServer::new();
    let body = serde_json::json!({ "redirect_uris": [REDIRECT_URI] });

    let (s1, b1) = send(&server, post_json("/register", body.clone())).await;
    let (s2, b2) = send(&server, post_json("/register", body)).await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::CREATED);
    assert_eq!(
        parse_json(&b1)["client_id"],
        parse_json(&b2)["client_id"],
        "identical registrations must reuse the same client_id"
    );
}

#[tokio::test]
async fn token_rejects_unsupported_grant_type() {
    let server = TestServer::new();
    let (status, body) = send(&server, post_form("/token", &[("grant_type", "password")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn authorization_code_grant_reports_each_missing_parameter() {
    let server = TestServer::new();

    // Each required parameter is checked in turn before the code is looked up.
    let cases: &[(&[(&str, &str)], &str)] = &[
        (&[("grant_type", "authorization_code")], "code"),
        (
            &[("grant_type", "authorization_code"), ("code", "c")],
            "code_verifier",
        ),
        (
            &[
                ("grant_type", "authorization_code"),
                ("code", "c"),
                ("code_verifier", "v"),
            ],
            "client_id",
        ),
        (
            &[
                ("grant_type", "authorization_code"),
                ("code", "c"),
                ("code_verifier", "v"),
                ("client_id", "client_test"),
            ],
            "redirect_uri",
        ),
    ];
    for (pairs, needle) in cases {
        let (status, body) = send(&server, post_form("/token", pairs)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{needle}");
        assert_eq!(parse_json(&body)["error"], "invalid_grant");
        assert!(
            parse_json(&body)["error_description"]
                .as_str()
                .unwrap()
                .contains(needle),
            "expected description to mention {needle}"
        );
    }
}

#[tokio::test]
async fn refresh_token_grant_requires_a_refresh_token() {
    let server = TestServer::new();
    let (status, body) = send(
        &server,
        post_form("/token", &[("grant_type", "refresh_token")]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn refresh_token_grant_rejects_a_client_id_mismatch() {
    let server = TestServer::new();
    let code = seed_code(&server);
    // Obtain a genuine refresh token bound to CLIENT_ID.
    let (_, body) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
            ],
        ),
    )
    .await;
    let refresh = parse_json(&body)["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Presenting it under a different client_id is rejected.
    let (status, resp) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", "client_other"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&resp)["error"], "invalid_grant");
}

/// Seeds an authorization code so `/token` can be exercised end-to-end.
fn seed_code(server: &TestServer) -> String {
    server.state().sessions().put_auth_code(AuthCode {
        client_id: CLIENT_ID.to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
        code_challenge: CHALLENGE.to_string(),
        resource: None,
    })
}

#[tokio::test]
async fn authorization_code_grant_issues_a_valid_owner_token() {
    let server = TestServer::new();
    let code = seed_code(&server);

    let (status, body) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
            ],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    let resp = parse_json(&body);
    assert_eq!(resp["token_type"], "Bearer");
    let access = resp["access_token"].as_str().expect("access_token");
    let claims = jwt::verify(common::SIGNING_KEY, access, ORIGIN, ORIGIN).expect("valid token");
    assert_eq!(claims.sub, common::OWNER_HANDLE);
    assert!(
        resp["refresh_token"].as_str().is_some(),
        "a refresh token must be issued"
    );
}

#[tokio::test]
async fn authorization_code_is_single_use() {
    let server = TestServer::new();
    let code = seed_code(&server);
    let pairs = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", VERIFIER),
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT_URI),
    ];

    let (first, _) = send(&server, post_form("/token", &pairs)).await;
    let (second, _) = send(&server, post_form("/token", &pairs)).await;
    assert_eq!(first, StatusCode::OK);
    assert_eq!(
        second,
        StatusCode::BAD_REQUEST,
        "a consumed code must not work twice"
    );
}

#[tokio::test]
async fn authorization_code_grant_rejects_a_bad_pkce_verifier() {
    let server = TestServer::new();
    let code = seed_code(&server);

    let (status, body) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", "wrong-verifier"),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
            ],
        ),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(parse_json(&body)["error"], "invalid_grant");
}

#[tokio::test]
async fn authorization_code_grant_rejects_a_redirect_uri_mismatch() {
    let server = TestServer::new();
    let code = seed_code(&server);

    let (status, _) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", CLIENT_ID),
                ("redirect_uri", "https://claude.ai/other"),
            ],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refresh_token_rotates_and_the_old_one_is_rejected() {
    let server = TestServer::new();
    let code = seed_code(&server);

    let (_, body) = send(
        &server,
        post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("client_id", CLIENT_ID),
                ("redirect_uri", REDIRECT_URI),
            ],
        ),
    )
    .await;
    let refresh = parse_json(&body)["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_string();

    // First use succeeds and rotates the token.
    let (rotated, _) = send(
        &server,
        post_form(
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
        ),
    )
    .await;
    assert_eq!(rotated, StatusCode::OK);

    // Replaying the now-consumed refresh token must fail.
    let (replayed, _) = send(
        &server,
        post_form(
            "/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &refresh)],
        ),
    )
    .await;
    assert_eq!(
        replayed,
        StatusCode::BAD_REQUEST,
        "refresh tokens are single-use"
    );
}
