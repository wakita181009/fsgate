use std::sync::{Arc, Mutex};

use anyhow::Result;
use webauthn_rs::Webauthn;

use crate::auth::session::Sessions;
use crate::config::Config;
use crate::credentials::{self, Credentials};

/// Shared, cloneable application state handed to every axum handler.
///
/// Credential mutations (DCR registration, passkey enrollment, refresh-token
/// rotation) are rare and are guarded by a std `Mutex`; the guard is never held
/// across an `.await`. Each mutation persists synchronously via `credentials::save`.
#[derive(Clone)]
pub struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    config: Config,
    creds: Mutex<Credentials>,
    webauthn: Arc<Webauthn>,
    sessions: Sessions,
}

impl AppState {
    pub fn new(config: Config, creds: Credentials, webauthn: Arc<Webauthn>) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                creds: Mutex::new(creds),
                webauthn,
                sessions: Sessions::default(),
            }),
        }
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub fn webauthn(&self) -> &Webauthn {
        &self.inner.webauthn
    }

    pub fn sessions(&self) -> &Sessions {
        &self.inner.sessions
    }

    /// The public origin without a trailing slash; used as OAuth issuer, token
    /// audience, and the base for advertised endpoint URLs.
    pub fn origin(&self) -> String {
        self.inner
            .config
            .public_origin
            .as_str()
            .trim_end_matches('/')
            .to_string()
    }

    /// Runs `f` against a read-only snapshot region of the credentials.
    pub fn with_creds<T>(&self, f: impl FnOnce(&Credentials) -> T) -> T {
        let guard = self.inner.creds.lock().expect("credentials mutex poisoned");
        f(&guard)
    }

    /// Mutates a clone of the credentials, persists it, then publishes it in
    /// memory. A failed save therefore cannot leave memory ahead of disk.
    /// The closure must not perform blocking I/O or `.await`.
    pub fn mutate_creds<T>(&self, f: impl FnOnce(&mut Credentials) -> T) -> Result<T> {
        self.mutate_creds_if(|creds| (f(creds), true))
    }

    /// Like `mutate_creds`, but lets the closure report that no state changed.
    /// No-op outcomes avoid rewriting `credentials.json`, which is important for
    /// rejecting abusive DCR requests once the client registry is full.
    pub fn mutate_creds_if<T>(&self, f: impl FnOnce(&mut Credentials) -> (T, bool)) -> Result<T> {
        let mut guard = self.inner.creds.lock().expect("credentials mutex poisoned");
        let mut next = guard.clone();
        let (out, changed) = f(&mut next);
        if changed {
            credentials::save(&self.inner.config.state_dir, &next)?;
            *guard = next;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use url::Url;

    use super::*;
    use crate::auth::random_token;

    /// Builds an `AppState` over a throwaway state dir. The returned path must be
    /// cleaned up by the caller (kept alive for the test's duration).
    fn state_with_origin(origin: &str) -> (AppState, std::path::PathBuf) {
        let state_dir = std::env::temp_dir().join(format!("fsgate-app-test-{}", random_token()));
        std::fs::create_dir_all(&state_dir).unwrap();

        let config = Config {
            root: state_dir.clone(),
            public_origin: Url::parse(origin).unwrap(),
            state_dir: state_dir.clone(),
            oauth_password: None,
            allow_password_auth: true,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            mcp_path: "/".to_string(),
            token_signing_key: None,
        };
        let webauthn = crate::auth::webauthn::build(&config).unwrap();
        (
            AppState::new(config, Credentials::default(), webauthn),
            state_dir,
        )
    }

    #[test]
    fn origin_strips_a_trailing_slash() {
        let (state, dir) = state_with_origin("https://fsgate.example/");
        assert_eq!(state.origin(), "https://fsgate.example");
        assert_eq!(state.config().mcp_path, "/");
        // Exercise the accessors handlers depend on.
        let _ = state.webauthn();
        let _ = state.sessions();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn with_creds_reads_a_snapshot() {
        let (state, dir) = state_with_origin("https://fsgate.example");
        assert!(state.with_creds(|c| c.owner_handle.clone()).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mutate_creds_persists_and_publishes() {
        let (state, dir) = state_with_origin("https://fsgate.example");
        state
            .mutate_creds(|c| c.owner_handle = Some("owner-1".to_string()))
            .unwrap();

        // In memory.
        assert_eq!(
            state.with_creds(|c| c.owner_handle.clone()),
            Some("owner-1".to_string())
        );
        // And on disk: a fresh load sees the same handle.
        let reloaded = credentials::load(&dir).unwrap();
        assert_eq!(reloaded.owner_handle.as_deref(), Some("owner-1"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn mutate_creds_if_skips_the_write_when_unchanged() {
        let (state, dir) = state_with_origin("https://fsgate.example");
        // changed == false: nothing is persisted, so no credentials.json appears.
        let out = state.mutate_creds_if(|_| (7, false)).unwrap();
        assert_eq!(out, 7);
        assert!(
            !dir.join("credentials.json").exists(),
            "a no-op mutation must not write the state file"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
