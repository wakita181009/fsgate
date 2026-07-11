use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;

use fsgate::app::AppState;
use fsgate::auth::webauthn;
use fsgate::config::Config;
use fsgate::notes::Notes;
use fsgate::{build_router, credentials, enforce_fail_closed, initialize_owner_state};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "fsgate=info".into()))
        .init();

    let config = Config::from_env().context("invalid configuration")?;
    let creds = credentials::load(&config.state_dir).context("cannot load credential state")?;

    enforce_fail_closed(&config, &creds)?;

    let webauthn = webauthn::build(&config).context("cannot initialize WebAuthn")?;

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
