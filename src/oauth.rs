pub mod authorize;
pub mod bearer;
pub mod dcr;
pub mod discovery;
pub mod enroll;
pub mod error;
pub mod pages;
pub mod token;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Hosts fsgate will accept as OAuth `redirect_uri` targets during Dynamic
/// Client Registration. Claude's hosted connector callback lives under these.
pub const ALLOWED_REDIRECT_HOSTS: &[&str] = &["claude.ai", "claude.com"];

/// Current UTC time as an RFC 3339 string, for credential timestamps.
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
