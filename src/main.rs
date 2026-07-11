mod app;
mod auth;
mod config;
mod credentials;
mod mcp;
mod notes;
mod oauth;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::{get, post};
use tracing_subscriber::EnvFilter;

use crate::app::AppState;
use crate::config::Config;
use crate::notes::Notes;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "fsgate=info".into()))
        .init();

    let config = Config::from_env().context("invalid configuration")?;
    let creds = credentials::load(&config.state_dir).context("cannot load credential state")?;

    enforce_fail_closed(&config, &creds)?;

    let webauthn = auth::webauthn::build(&config).context("cannot initialize WebAuthn")?;

    let notes = Arc::new(Notes::new(&config.root).context("cannot open served root")?);

    let addr = SocketAddr::new(config.host, config.port);
    let state = AppState::new(config, creds, webauthn);
    initialize_owner_state(&state).context("cannot initialize owner state")?;
    let app = build_router(state.clone(), notes);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("cannot bind {addr}"))?;
    tracing::info!(
        %addr,
        origin = %state.config().public_origin,
        root = %state.config().root.display(),
        "fsgate listening"
    );

    axum::serve(listener, app).await.context("server error")?;
    Ok(())
}

/// Fail-closed contract: with no owner verifier provisioned, the server is
/// unusable by design. Enrolling the first passkey requires the recovery
/// password, so refuse to start when neither exists — otherwise fsgate would be
/// reachable with no way to ever authenticate the owner.
fn enforce_fail_closed(config: &Config, creds: &credentials::Credentials) -> Result<()> {
    if !creds.has_owner_verifier() && config.oauth_password.is_none() {
        anyhow::bail!(
            "fail-closed: no owner verifier. Set FSGATE_OAUTH_PASSWORD to enroll your first \
             passkey, or restore a credentials.json containing an enrolled passkey."
        );
    }
    if !config.allow_password_auth && creds.passkeys.is_empty() {
        anyhow::bail!(
            "FSGATE_ALLOW_PASSWORD_AUTH=false but no passkey is enrolled; you would be locked \
             out. Enroll a passkey first, then disable password auth."
        );
    }
    Ok(())
}

fn build_router(state: AppState, notes: Arc<Notes>) -> Router {
    let mcp_path = state.config().mcp_path.clone();
    let mcp_service = mcp::service(notes, state.config());

    // The MCP transport is a self-contained tower service; the Bearer middleware
    // (carrying its own AppState) gates it. Mounted on its own router so the
    // guard does not touch the OAuth/discovery endpoints below.
    let mcp_router = Router::new()
        .route_service(&mcp_path, mcp_service)
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            oauth::bearer::require_owner_token,
        ));

    let oauth_router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth::discovery::protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::discovery::authorization_server),
        )
        .route("/register", post(oauth::dcr::register))
        .route("/enroll", get(oauth::enroll::page))
        .route("/enroll/start", post(oauth::enroll::start))
        .route("/enroll/verify", post(oauth::enroll::verify))
        .route("/authorize", get(oauth::authorize::page))
        .route("/authorize/start", post(oauth::authorize::start))
        .route("/authorize/finish", post(oauth::authorize::finish))
        .route(
            "/authorize/password",
            post(oauth::authorize::password_login),
        )
        .route("/token", post(oauth::token::token))
        .with_state(state);

    oauth_router.merge(mcp_router)
}

/// First-run bootstrap of the durable owner anchor. Generates and persists the
/// owner handle, the HS256 token signing key, and (from `FSGATE_OAUTH_PASSWORD`)
/// the recovery password hash. Idempotent — only fills what is missing, so a
/// restored `credentials.json` is never overwritten.
fn initialize_owner_state(state: &AppState) -> Result<()> {
    let (need_handle, need_key, need_pw) = state.with_creds(|c| {
        (
            c.owner_handle.is_none(),
            c.token_signing_key.is_none(),
            c.recovery_password_hash.is_none(),
        )
    });
    if !(need_handle || need_key || need_pw) {
        return Ok(());
    }

    let new_handle = need_handle.then(|| uuid::Uuid::new_v4().to_string());
    let new_key = need_key.then(|| {
        state
            .config()
            .token_signing_key
            .clone()
            .unwrap_or_else(auth::random_token)
    });
    let new_pw_hash = match (need_pw, state.config().oauth_password.as_deref()) {
        (true, Some(pw)) => {
            Some(auth::password::hash(pw).context("cannot hash recovery password")?)
        }
        _ => None,
    };

    state.mutate_creds(|c| {
        if let Some(h) = new_handle {
            c.owner_handle = Some(h);
        }
        if let Some(k) = new_key {
            c.token_signing_key = Some(k);
        }
        if let Some(p) = new_pw_hash {
            c.recovery_password_hash = Some(p);
        }
    })?;
    Ok(())
}
