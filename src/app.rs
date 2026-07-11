use std::sync::{Arc, Mutex};

use anyhow::Result;
use webauthn_rs::Webauthn;

use crate::auth::session::Sessions;
use crate::config::Config;
use crate::state::{self, Credentials};

/// Shared, cloneable application state handed to every axum handler.
///
/// Credential mutations (DCR registration, passkey enrollment, refresh-token
/// rotation) are rare and are guarded by a std `Mutex`; the guard is never held
/// across an `.await`. Each mutation persists synchronously via `state::save`.
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

    /// Mutates the credentials under lock, then persists the result atomically.
    /// The closure must not perform blocking I/O or `.await`.
    pub fn mutate_creds<T>(&self, f: impl FnOnce(&mut Credentials) -> T) -> Result<T> {
        let mut guard = self.inner.creds.lock().expect("credentials mutex poisoned");
        let out = f(&mut guard);
        state::save(&self.inner.config.state_dir, &guard)?;
        Ok(out)
    }
}
