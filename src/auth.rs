pub mod jwt;
pub mod password;
pub mod pkce;
pub mod session;
pub mod webauthn;

use rand::Rng;

/// Generates a 256-bit URL-safe random token for codes, session ids, and
/// refresh tokens.
pub fn random_token() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
