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
