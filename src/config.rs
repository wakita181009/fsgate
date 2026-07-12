use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use url::Url;

const DEFAULT_PORT: u16 = 8420;
const DEFAULT_MCP_PATH: &str = "/";

/// Runtime configuration, read once from the environment at startup.
///
/// Every field is validated here so the rest of the process can assume it is
/// well-formed. The fail-closed contract (no owner verifier -> no tokens) is
/// enforced in `main` once the credential state is also known.
#[derive(Debug, Clone)]
pub struct Config {
    pub root: PathBuf,
    pub public_origin: Url,
    pub state_dir: PathBuf,
    pub oauth_password: Option<String>,
    pub allow_password_auth: bool,
    pub host: IpAddr,
    pub port: u16,
    pub mcp_path: String,
    /// Optional operator-supplied HS256 secret. When absent, a random key is
    /// generated and persisted to `credentials.json` on first run.
    pub token_signing_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let root = require_path("FSGATE_ROOT")?;
        if !root.is_absolute() {
            bail!(
                "FSGATE_ROOT must be an absolute path, got: {}",
                root.display()
            );
        }
        if !root.is_dir() {
            bail!(
                "FSGATE_ROOT does not point to a directory: {}",
                root.display()
            );
        }

        let public_origin = require_var("FSGATE_PUBLIC_ORIGIN")?;
        let public_origin = Url::parse(&public_origin)
            .with_context(|| format!("FSGATE_PUBLIC_ORIGIN is not a valid URL: {public_origin}"))?;
        // WebAuthn assertions are only trustworthy over an authenticated origin.
        if public_origin.scheme() != "https" {
            bail!("FSGATE_PUBLIC_ORIGIN must be https, got: {public_origin}");
        }

        let state_dir = require_path("FSGATE_STATE_DIR")?;

        Ok(Self {
            root,
            public_origin,
            state_dir,
            oauth_password: optional_var("FSGATE_OAUTH_PASSWORD"),
            allow_password_auth: parse_bool("FSGATE_ALLOW_PASSWORD_AUTH", true)?,
            host: parse_host("FSGATE_HOST", IpAddr::V4(Ipv4Addr::LOCALHOST))?,
            port: parse_port("FSGATE_PORT", DEFAULT_PORT)?,
            mcp_path: optional_var("FSGATE_MCP_PATH")
                .unwrap_or_else(|| DEFAULT_MCP_PATH.to_string()),
            token_signing_key: optional_var("FSGATE_TOKEN_SIGNING_KEY"),
        })
    }

    /// RP ID for WebAuthn: the registrable domain of the public origin.
    pub fn rp_id(&self) -> Result<String> {
        self.public_origin
            .host_str()
            .map(str::to_owned)
            .context("FSGATE_PUBLIC_ORIGIN has no host component")
    }
}

fn require_var(key: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => bail!("required env var {key} is unset or empty"),
    }
}

fn optional_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.trim().is_empty())
}

fn require_path(key: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(require_var(key)?))
}

fn parse_bool(key: &str, default: bool) -> Result<bool> {
    match optional_var(key) {
        None => Ok(default),
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => bail!("{key} must be a boolean, got: {other}"),
        },
    }
}

fn parse_port(key: &str, default: u16) -> Result<u16> {
    match optional_var(key) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .with_context(|| format!("{key} is not a valid port: {v}")),
    }
}

fn parse_host(key: &str, default: IpAddr) -> Result<IpAddr> {
    match optional_var(key) {
        None => Ok(default),
        Some(v) => v
            .parse()
            .with_context(|| format!("{key} is not a valid IP address: {v}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // `from_env` and the helpers read process-wide env vars. Mutating those from
    // multiple threads is unsound, so every env-touching test serializes here.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn set(key: &str, value: &str) {
        // SAFETY: all env access in these tests is serialized via ENV_LOCK, and
        // no other thread reads these keys concurrently.
        unsafe { std::env::set_var(key, value) };
    }

    fn unset(key: &str) {
        // SAFETY: see `set`.
        unsafe { std::env::remove_var(key) };
    }

    #[test]
    fn require_var_rejects_missing_and_blank() {
        let _g = lock();
        unset("FSGATE_T_REQ");
        assert!(require_var("FSGATE_T_REQ").is_err());
        set("FSGATE_T_REQ", "   ");
        assert!(require_var("FSGATE_T_REQ").is_err());
        set("FSGATE_T_REQ", "value");
        assert_eq!(require_var("FSGATE_T_REQ").unwrap(), "value");
        unset("FSGATE_T_REQ");
    }

    #[test]
    fn optional_var_treats_blank_as_absent() {
        let _g = lock();
        unset("FSGATE_T_OPT");
        assert_eq!(optional_var("FSGATE_T_OPT"), None);
        set("FSGATE_T_OPT", "  ");
        assert_eq!(optional_var("FSGATE_T_OPT"), None);
        set("FSGATE_T_OPT", "x");
        assert_eq!(optional_var("FSGATE_T_OPT").as_deref(), Some("x"));
        unset("FSGATE_T_OPT");
    }

    #[test]
    fn parse_bool_accepts_common_spellings_and_rejects_garbage() {
        let _g = lock();
        unset("FSGATE_T_BOOL");
        assert!(parse_bool("FSGATE_T_BOOL", true).unwrap());
        assert!(!parse_bool("FSGATE_T_BOOL", false).unwrap());

        for truthy in ["true", "1", "YES", "On"] {
            set("FSGATE_T_BOOL", truthy);
            assert!(parse_bool("FSGATE_T_BOOL", false).unwrap(), "{truthy}");
        }
        for falsy in ["false", "0", "no", "OFF"] {
            set("FSGATE_T_BOOL", falsy);
            assert!(!parse_bool("FSGATE_T_BOOL", true).unwrap(), "{falsy}");
        }
        set("FSGATE_T_BOOL", "maybe");
        assert!(parse_bool("FSGATE_T_BOOL", true).is_err());
        unset("FSGATE_T_BOOL");
    }

    #[test]
    fn parse_port_uses_default_and_rejects_non_numeric() {
        let _g = lock();
        unset("FSGATE_T_PORT");
        assert_eq!(parse_port("FSGATE_T_PORT", 8420).unwrap(), 8420);
        set("FSGATE_T_PORT", "9001");
        assert_eq!(parse_port("FSGATE_T_PORT", 8420).unwrap(), 9001);
        set("FSGATE_T_PORT", "not-a-port");
        assert!(parse_port("FSGATE_T_PORT", 8420).is_err());
        unset("FSGATE_T_PORT");
    }

    #[test]
    fn parse_host_uses_default_and_rejects_bad_ip() {
        let _g = lock();
        let default = IpAddr::V4(Ipv4Addr::LOCALHOST);
        unset("FSGATE_T_HOST");
        assert_eq!(parse_host("FSGATE_T_HOST", default).unwrap(), default);
        set("FSGATE_T_HOST", "0.0.0.0");
        assert_eq!(
            parse_host("FSGATE_T_HOST", default).unwrap(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        set("FSGATE_T_HOST", "not-an-ip");
        assert!(parse_host("FSGATE_T_HOST", default).is_err());
        unset("FSGATE_T_HOST");
    }

    #[test]
    fn rp_id_is_the_origin_host() {
        let config = Config {
            root: PathBuf::from("/"),
            public_origin: Url::parse("https://notes.example.ts.net").unwrap(),
            state_dir: PathBuf::from("/"),
            oauth_password: None,
            allow_password_auth: true,
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 0,
            mcp_path: "/".to_string(),
            token_signing_key: None,
        };
        assert_eq!(config.rp_id().unwrap(), "notes.example.ts.net");
    }

    /// Sets a full valid environment, runs `body`, then restores the env. Requires
    /// the caller to already hold the env lock.
    fn with_full_env(root: &std::path::Path, body: impl FnOnce()) {
        set("FSGATE_ROOT", &root.to_string_lossy());
        set("FSGATE_PUBLIC_ORIGIN", "https://fsgate.example");
        set("FSGATE_STATE_DIR", "/tmp/fsgate-state");
        body();
        for key in [
            "FSGATE_ROOT",
            "FSGATE_PUBLIC_ORIGIN",
            "FSGATE_STATE_DIR",
            "FSGATE_OAUTH_PASSWORD",
            "FSGATE_ALLOW_PASSWORD_AUTH",
            "FSGATE_HOST",
            "FSGATE_PORT",
            "FSGATE_MCP_PATH",
            "FSGATE_TOKEN_SIGNING_KEY",
        ] {
            unset(key);
        }
    }

    #[test]
    fn from_env_reads_a_valid_configuration_with_defaults() {
        let _g = lock();
        let root = std::env::temp_dir();
        with_full_env(&root, || {
            let config = Config::from_env().expect("valid config");
            assert_eq!(config.public_origin.as_str(), "https://fsgate.example/");
            assert_eq!(config.port, DEFAULT_PORT);
            assert_eq!(config.mcp_path, DEFAULT_MCP_PATH);
            assert!(config.allow_password_auth);
            assert!(config.oauth_password.is_none());
            assert_eq!(config.host, IpAddr::V4(Ipv4Addr::LOCALHOST));
        });
    }

    #[test]
    fn from_env_honors_optional_overrides() {
        let _g = lock();
        let root = std::env::temp_dir();
        with_full_env(&root, || {
            set("FSGATE_OAUTH_PASSWORD", "hunter2");
            set("FSGATE_ALLOW_PASSWORD_AUTH", "false");
            set("FSGATE_PORT", "9443");
            set("FSGATE_MCP_PATH", "/mcp");
            set("FSGATE_TOKEN_SIGNING_KEY", "operator-key");
            let config = Config::from_env().expect("valid config");
            assert_eq!(config.oauth_password.as_deref(), Some("hunter2"));
            assert!(!config.allow_password_auth);
            assert_eq!(config.port, 9443);
            assert_eq!(config.mcp_path, "/mcp");
            assert_eq!(config.token_signing_key.as_deref(), Some("operator-key"));
        });
    }

    #[test]
    fn from_env_rejects_a_relative_root() {
        let _g = lock();
        set("FSGATE_ROOT", "relative/path");
        set("FSGATE_PUBLIC_ORIGIN", "https://fsgate.example");
        set("FSGATE_STATE_DIR", "/tmp/fsgate-state");
        let err = Config::from_env().unwrap_err().to_string();
        assert!(err.contains("absolute"), "{err}");
        for k in ["FSGATE_ROOT", "FSGATE_PUBLIC_ORIGIN", "FSGATE_STATE_DIR"] {
            unset(k);
        }
    }

    #[test]
    fn from_env_rejects_a_root_that_is_not_a_directory() {
        let _g = lock();
        // A path that is absolute but does not resolve to a directory.
        set("FSGATE_ROOT", "/nonexistent/fsgate/root/xyz");
        set("FSGATE_PUBLIC_ORIGIN", "https://fsgate.example");
        set("FSGATE_STATE_DIR", "/tmp/fsgate-state");
        let err = Config::from_env().unwrap_err().to_string();
        assert!(err.contains("does not point to a directory"), "{err}");
        for k in ["FSGATE_ROOT", "FSGATE_PUBLIC_ORIGIN", "FSGATE_STATE_DIR"] {
            unset(k);
        }
    }

    #[test]
    fn from_env_requires_https_origin() {
        let _g = lock();
        let root = std::env::temp_dir();
        set("FSGATE_ROOT", &root.to_string_lossy());
        set("FSGATE_PUBLIC_ORIGIN", "http://fsgate.example");
        set("FSGATE_STATE_DIR", "/tmp/fsgate-state");
        let err = Config::from_env().unwrap_err().to_string();
        assert!(err.contains("https"), "{err}");

        set("FSGATE_PUBLIC_ORIGIN", "not a url");
        let err = Config::from_env().unwrap_err().to_string();
        assert!(err.contains("not a valid URL"), "{err}");
        for k in ["FSGATE_ROOT", "FSGATE_PUBLIC_ORIGIN", "FSGATE_STATE_DIR"] {
            unset(k);
        }
    }
}
