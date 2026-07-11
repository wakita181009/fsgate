use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::auth::random_token;

const CEREMONY_TTL: Duration = Duration::from_secs(5 * 60);
const AUTH_CODE_TTL: Duration = Duration::from_secs(60);
const REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Consecutive password failures that trigger a lockout, and how long it lasts.
/// The server is single-user, so a global counter is the right granularity —
/// there is exactly one legitimate password.
const MAX_PASSWORD_FAILURES: u32 = 5;
const PASSWORD_LOCKOUT: Duration = Duration::from_secs(5 * 60);
const DCR_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_DCR_REGISTRATIONS_PER_WINDOW: usize = 10;

/// OAuth parameters captured at `/authorize` and carried through the passkey
/// ceremony until an authorization code is minted.
#[derive(Debug, Clone)]
pub struct AuthorizeContext {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: Option<String>,
    pub state: Option<String>,
}

/// A minted authorization code, single-use, bound to the originating request.
#[derive(Debug, Clone)]
pub struct AuthCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub resource: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Refresh {
    pub client_id: String,
}

enum Ceremony {
    Registration(PasskeyRegistration),
    Authentication(Box<PasskeyAuthentication>, AuthorizeContext),
}

/// All ephemeral, in-memory security state. None of it is serde-serialisable by
/// design — WebAuthn ceremony state must never round-trip through disk (replay
/// risk), and codes/refresh tokens are short-lived. A restart invalidates
/// in-flight logins, which is acceptable.
#[derive(Default)]
pub struct Sessions {
    ceremonies: Mutex<HashMap<String, (Ceremony, Instant)>>,
    auth_codes: Mutex<HashMap<String, (AuthCode, Instant)>>,
    refresh_tokens: Mutex<HashMap<String, (Refresh, Instant)>>,
    password_attempts: Mutex<PasswordAttempts>,
    dcr_registrations: Mutex<VecDeque<Instant>>,
}

/// Brute-force guard state for recovery-password checks.
#[derive(Default)]
struct PasswordAttempts {
    failures: u32,
    locked_until: Option<Instant>,
}

impl Sessions {
    // --- WebAuthn registration ceremony ---

    pub fn put_registration(&self, state: PasskeyRegistration) -> String {
        let sid = random_token();
        self.ceremonies
            .lock()
            .unwrap()
            .insert(sid.clone(), (Ceremony::Registration(state), Instant::now()));
        sid
    }

    pub fn take_registration(&self, sid: &str) -> Option<PasskeyRegistration> {
        let mut map = self.ceremonies.lock().unwrap();
        prune(&mut map, CEREMONY_TTL);
        match map.remove(sid) {
            Some((Ceremony::Registration(state), _)) => Some(state),
            Some((other, ts)) => {
                // Wrong ceremony type for this sid; put it back untouched.
                map.insert(sid.to_string(), (other, ts));
                None
            }
            None => None,
        }
    }

    // --- WebAuthn authentication ceremony ---

    pub fn put_authentication(
        &self,
        state: PasskeyAuthentication,
        ctx: AuthorizeContext,
    ) -> String {
        let sid = random_token();
        self.ceremonies.lock().unwrap().insert(
            sid.clone(),
            (
                Ceremony::Authentication(Box::new(state), ctx),
                Instant::now(),
            ),
        );
        sid
    }

    pub fn take_authentication(
        &self,
        sid: &str,
    ) -> Option<(PasskeyAuthentication, AuthorizeContext)> {
        let mut map = self.ceremonies.lock().unwrap();
        prune(&mut map, CEREMONY_TTL);
        match map.remove(sid) {
            Some((Ceremony::Authentication(state, ctx), _)) => Some((*state, ctx)),
            Some((other, ts)) => {
                map.insert(sid.to_string(), (other, ts));
                None
            }
            None => None,
        }
    }

    // --- Authorization codes ---

    pub fn put_auth_code(&self, code_data: AuthCode) -> String {
        let code = random_token();
        self.auth_codes
            .lock()
            .unwrap()
            .insert(code.clone(), (code_data, Instant::now()));
        code
    }

    pub fn take_auth_code(&self, code: &str) -> Option<AuthCode> {
        let mut map = self.auth_codes.lock().unwrap();
        prune(&mut map, AUTH_CODE_TTL);
        map.remove(code).map(|(data, _)| data)
    }

    // --- Refresh tokens (rotated on use) ---

    pub fn put_refresh(&self, data: Refresh) -> String {
        let token = random_token();
        self.refresh_tokens
            .lock()
            .unwrap()
            .insert(token.clone(), (data, Instant::now()));
        token
    }

    pub fn take_refresh(&self, token: &str) -> Option<Refresh> {
        let mut map = self.refresh_tokens.lock().unwrap();
        prune(&mut map, REFRESH_TTL);
        map.remove(token).map(|(data, _)| data)
    }

    // --- Password brute-force guard ---

    /// Remaining lockout duration, or `None` if password checks are allowed.
    pub fn password_lock_remaining(&self) -> Option<Duration> {
        let guard = self.password_attempts.lock().unwrap();
        guard
            .locked_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
            .filter(|d| !d.is_zero())
    }

    /// Records a failed password attempt, arming a lockout at the threshold.
    pub fn record_password_failure(&self) {
        let mut guard = self.password_attempts.lock().unwrap();
        guard.failures += 1;
        if guard.failures >= MAX_PASSWORD_FAILURES {
            guard.locked_until = Some(Instant::now() + PASSWORD_LOCKOUT);
            guard.failures = 0;
        }
    }

    /// Clears the failure counter after a successful password check.
    pub fn record_password_success(&self) {
        let mut guard = self.password_attempts.lock().unwrap();
        guard.failures = 0;
        guard.locked_until = None;
    }

    // --- Dynamic client registration rate limit ---

    /// Records a state-creating DCR request, or returns how long the caller must
    /// wait. Reuse of existing registrations is checked before this method and
    /// does not consume the small single-user registration budget.
    pub fn allow_dcr_registration(&self) -> Result<(), Duration> {
        let now = Instant::now();
        let mut attempts = self.dcr_registrations.lock().unwrap();
        while attempts
            .front()
            .is_some_and(|started| now.duration_since(*started) >= DCR_RATE_WINDOW)
        {
            attempts.pop_front();
        }

        if attempts.len() >= MAX_DCR_REGISTRATIONS_PER_WINDOW {
            let retry_at =
                *attempts.front().expect("rate-limited queue is non-empty") + DCR_RATE_WINDOW;
            return Err(retry_at.saturating_duration_since(now));
        }

        attempts.push_back(now);
        Ok(())
    }
}

/// Drops entries older than `ttl`. Called on every access; the maps stay tiny
/// for a single-user server so linear pruning is fine.
fn prune<V>(map: &mut HashMap<String, (V, Instant)>, ttl: Duration) {
    let now = Instant::now();
    map.retain(|_, (_, ts)| now.duration_since(*ts) < ttl);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dcr_rate_limit_caps_state_creating_requests() {
        let sessions = Sessions::default();
        for _ in 0..MAX_DCR_REGISTRATIONS_PER_WINDOW {
            assert!(sessions.allow_dcr_registration().is_ok());
        }
        assert!(sessions.allow_dcr_registration().is_err());
    }
}
