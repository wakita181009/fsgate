use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::Passkey;

const CREDENTIALS_FILE: &str = "credentials.json";
#[cfg(unix)]
const STATE_PERMS: u32 = 0o600;

/// Persistent owner-identity and OAuth state.
///
/// This is the durable anchor of "it's me": passkey public keys (safe to store)
/// plus a hashed recovery password. It is written with `0600` perms because a
/// leak of the signing key or password hash weakens the whole gate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Credentials {
    /// Fixed single-user identifier, used as the WebAuthn user handle and JWT `sub`.
    #[serde(default)]
    pub owner_handle: Option<String>,
    /// Argon2id hash of `FSGATE_OAUTH_PASSWORD`; the enrollment gate and fallback login.
    #[serde(default)]
    pub recovery_password_hash: Option<String>,
    #[serde(default)]
    pub passkeys: Vec<StoredPasskey>,
    #[serde(default)]
    pub oauth_clients: std::collections::BTreeMap<String, OAuthClient>,
    /// HS256 secret for access tokens; generated and persisted on first run.
    #[serde(default)]
    pub token_signing_key: Option<String>,
}

/// A registered passkey. The `credential` is the `webauthn-rs` type, which owns
/// the public key and signature counter and performs clone detection on its own;
/// fsgate only adds display metadata around it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub credential: Passkey,
    #[serde(default)]
    pub nickname: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    pub redirect_uris: Vec<String>,
}

impl Credentials {
    /// True once at least one owner verifier exists (passkey or recovery password).
    pub fn has_owner_verifier(&self) -> bool {
        !self.passkeys.is_empty() || self.recovery_password_hash.is_some()
    }
}

/// Loads `credentials.json` from `state_dir`, returning defaults if it does not
/// yet exist. Ensures the state directory exists first.
pub fn load(state_dir: &Path) -> Result<Credentials> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("cannot create state dir: {}", state_dir.display()))?;

    let path = credentials_path(state_dir);
    if !path.exists() {
        return Ok(Credentials::default());
    }

    verify_perms(&path)?;
    let bytes = std::fs::read(&path).with_context(|| format!("cannot read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is corrupt", path.display()))
}

/// Atomically persists credentials with `0600` perms (write-temp-then-rename).
pub fn save(state_dir: &Path, creds: &Credentials) -> Result<()> {
    let path = credentials_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(creds).context("cannot serialize credentials")?;

    std::fs::write(&tmp, &bytes).with_context(|| format!("cannot write {}", tmp.display()))?;
    set_perms(&tmp)?;
    std::fs::rename(&tmp, &path).with_context(|| format!("cannot finalize {}", path.display()))?;
    Ok(())
}

fn credentials_path(state_dir: &Path) -> PathBuf {
    state_dir.join(CREDENTIALS_FILE)
}

#[cfg(unix)]
fn set_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(STATE_PERMS);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("cannot set {STATE_PERMS:o} perms on {}", path.display()))
}

#[cfg(not(unix))]
fn set_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn verify_perms(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("cannot stat {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    // Refuse to trust credentials readable by group/other.
    if mode & 0o077 != 0 {
        bail!(
            "{} has insecure perms {mode:o}; expected 600. Run: chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_perms(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::random_token;

    fn temp_state_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fsgate-creds-test-{}", random_token()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn has_owner_verifier_tracks_passkeys_and_recovery_password() {
        let mut creds = Credentials::default();
        assert!(!creds.has_owner_verifier());
        creds.recovery_password_hash = Some("hash".to_string());
        assert!(creds.has_owner_verifier());
    }

    #[test]
    fn load_returns_defaults_when_file_is_absent() {
        let dir = temp_state_dir();
        let loaded = load(&dir).unwrap();
        assert!(loaded.owner_handle.is_none());
        assert!(loaded.oauth_clients.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_creates_a_missing_state_dir() {
        // A state dir that does not exist yet must be created by `load`.
        let dir = std::env::temp_dir().join(format!("fsgate-creds-mk-{}", random_token()));
        assert!(!dir.exists());
        let _ = load(&dir).unwrap();
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_then_load_round_trips_all_fields() {
        let dir = temp_state_dir();
        let mut creds = Credentials {
            owner_handle: Some("owner-42".to_string()),
            recovery_password_hash: Some("argon2-hash".to_string()),
            token_signing_key: Some("signing-key".to_string()),
            ..Credentials::default()
        };
        creds.oauth_clients.insert(
            "client_a".to_string(),
            OAuthClient {
                redirect_uris: vec!["https://claude.ai/cb".to_string()],
            },
        );

        save(&dir, &creds).unwrap();
        let loaded = load(&dir).unwrap();
        assert_eq!(loaded.owner_handle.as_deref(), Some("owner-42"));
        assert_eq!(loaded.token_signing_key.as_deref(), Some("signing-key"));
        assert_eq!(loaded.oauth_clients.len(), 1);
        assert_eq!(
            loaded.oauth_clients["client_a"].redirect_uris,
            vec!["https://claude.ai/cb".to_string()]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_reports_a_corrupt_credentials_file() {
        let dir = temp_state_dir();
        std::fs::write(credentials_path(&dir), b"{ not valid json").unwrap();
        #[cfg(unix)]
        set_perms(&credentials_path(&dir)).unwrap();
        let err = load(&dir).unwrap_err().to_string();
        assert!(err.contains("corrupt"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn save_writes_the_file_with_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_state_dir();
        save(&dir, &Credentials::default()).unwrap();
        let mode = std::fs::metadata(credentials_path(&dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, STATE_PERMS);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_world_readable_credentials_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_state_dir();
        let path = credentials_path(&dir);
        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let err = load(&dir).unwrap_err().to_string();
        assert!(err.contains("insecure perms"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
