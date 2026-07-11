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
