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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_rfc3339_is_a_parseable_utc_timestamp() {
        let ts = now_rfc3339();
        let parsed = OffsetDateTime::parse(&ts, &Rfc3339).expect("valid rfc3339");
        assert_eq!(parsed.offset(), time::UtcOffset::UTC);
    }

    #[test]
    fn allowed_redirect_hosts_are_the_claude_domains() {
        assert!(ALLOWED_REDIRECT_HOSTS.contains(&"claude.ai"));
        assert!(ALLOWED_REDIRECT_HOSTS.contains(&"claude.com"));
    }
}
