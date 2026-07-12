use anyhow::{Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand::Rng;

/// Argon2id hash of a password, suitable for persisting to `credentials.json`.
pub fn hash(password: &str) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| anyhow!("salt: {e}"))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("argon2 hash: {e}"))?
        .to_string();
    Ok(hash)
}

/// Constant-time verification via Argon2's own comparison. Returns false on any
/// parse or mismatch — never leaks the reason.
pub fn verify(password: &str, stored_hash: &str) -> bool {
    match PasswordHash::new(stored_hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_correct_password() {
        let h = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &h));
    }

    #[test]
    fn rejects_wrong_password() {
        let h = hash("secret").unwrap();
        assert!(!verify("guess", &h));
    }

    #[test]
    fn rejects_malformed_hash() {
        assert!(!verify("secret", "not-a-hash"));
        assert!(!verify("secret", ""));
    }

    #[test]
    fn each_hash_uses_a_fresh_salt() {
        // Argon2 salts are random, so hashing the same password twice must not
        // produce identical encoded hashes, yet both must verify.
        let a = hash("same-password").unwrap();
        let b = hash("same-password").unwrap();
        assert_ne!(a, b);
        assert!(verify("same-password", &a));
        assert!(verify("same-password", &b));
    }
}
