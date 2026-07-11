use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// Access-token claims. `aud` binds the token to fsgate's resource URL (RFC 8707)
/// so it cannot be replayed against another MCP server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub exp: u64,
    pub iat: u64,
}

pub fn issue(signing_key: &str, sub: &str, aud: &str, iss: &str, ttl_secs: u64) -> Result<String> {
    let now = unix_now();
    let claims = Claims {
        sub: sub.to_string(),
        aud: aud.to_string(),
        iss: iss.to_string(),
        exp: now + ttl_secs,
        iat: now,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(signing_key.as_bytes()),
    )
    .context("cannot sign access token")
}

/// Verifies signature, expiry, audience, and issuer. Any failure -> Err.
pub fn verify(signing_key: &str, token: &str, aud: &str, iss: &str) -> Result<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[aud]);
    validation.set_issuer(&[iss]);
    validation.set_required_spec_claims(&["exp", "aud", "iss", "sub"]);
    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(signing_key.as_bytes()),
        &validation,
    )
    .context("invalid access token")?;
    Ok(data.claims)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "test-signing-key-do-not-use-in-prod";
    const AUD: &str = "https://fsgate.example.ts.net";
    const ISS: &str = "https://fsgate.example.ts.net";

    #[test]
    fn round_trips_a_valid_token() {
        let token = issue(KEY, "owner", AUD, ISS, 60).unwrap();
        let claims = verify(KEY, &token, AUD, ISS).unwrap();
        assert_eq!(claims.sub, "owner");
    }

    #[test]
    fn rejects_wrong_audience() {
        let token = issue(KEY, "owner", AUD, ISS, 60).unwrap();
        assert!(verify(KEY, &token, "https://evil.example", ISS).is_err());
    }

    #[test]
    fn rejects_tampered_key() {
        let token = issue(KEY, "owner", AUD, ISS, 60).unwrap();
        assert!(verify("other-key", &token, AUD, ISS).is_err());
    }
}
