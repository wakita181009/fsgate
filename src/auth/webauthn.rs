use std::sync::Arc;

use anyhow::{Context, Result};
use webauthn_rs::{Webauthn, WebauthnBuilder};

use crate::config::Config;

/// Builds the relying-party instance from the public origin. The RP ID is the
/// origin's host; assertions are only trusted when the browser reports this same
/// origin, which is why `FSGATE_PUBLIC_ORIGIN` (not the bind address) is used.
pub fn build(config: &Config) -> Result<Arc<Webauthn>> {
    let rp_id = config.rp_id()?;
    let webauthn = WebauthnBuilder::new(&rp_id, &config.public_origin)
        .context("invalid WebAuthn relying-party configuration")?
        .rp_name("fsgate")
        .build()
        .context("cannot build WebAuthn instance")?;
    Ok(Arc::new(webauthn))
}
