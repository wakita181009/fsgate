//! The fail-closed startup contract: fsgate must refuse to run in any
//! configuration where the owner could never authenticate (no verifier) or
//! would be permanently locked out (password auth disabled with no passkey).

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use fsgate::config::Config;
use fsgate::credentials::Credentials;
use fsgate::enforce_fail_closed;
use url::Url;

/// A config whose paths are never touched by `enforce_fail_closed`; only
/// `oauth_password` and `allow_password_auth` matter here.
fn config(oauth_password: Option<&str>, allow_password_auth: bool) -> Config {
    Config {
        root: PathBuf::from("/nonexistent"),
        public_origin: Url::parse("https://fsgate.test.example").unwrap(),
        state_dir: PathBuf::from("/nonexistent"),
        oauth_password: oauth_password.map(str::to_string),
        allow_password_auth,
        host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 0,
        mcp_path: "/".to_string(),
        token_signing_key: None,
    }
}

#[test]
fn refuses_to_start_with_no_owner_verifier_and_no_password() {
    let creds = Credentials::default();
    let result = enforce_fail_closed(&config(None, true), &creds);
    assert!(
        result.is_err(),
        "no verifier and no recovery password must abort startup"
    );
}

#[test]
fn allows_startup_when_a_recovery_password_enables_enrollment() {
    // No passkey yet, but a recovery password is set, so the owner can enroll.
    let creds = Credentials::default();
    let result = enforce_fail_closed(&config(Some("hunter2"), true), &creds);
    assert!(
        result.is_ok(),
        "a recovery password is a valid path to first enrollment"
    );
}

#[test]
fn refuses_lockout_when_password_disabled_without_a_passkey() {
    // A verifier exists (password hash), but password auth is turned off and no
    // passkey is enrolled — the owner would be locked out.
    let creds = Credentials {
        recovery_password_hash: Some("argon2-hash-placeholder".to_string()),
        ..Credentials::default()
    };
    let result = enforce_fail_closed(&config(None, false), &creds);
    assert!(
        result.is_err(),
        "disabling password auth with no passkey must abort startup"
    );
}
