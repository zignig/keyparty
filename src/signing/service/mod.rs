// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

// has
// Sign( BLOB )
// Signature ( Signature )
// Status
// Errors from the signing machine
mod auth;
mod irpc;

use anyhow::Result;
use iroh::{
    Endpoint,
    endpoint::presets,
    protocol::{AcceptError, ProtocolHandler, RouterBuilder},
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::Config;
use irpc_iroh::{IrohLazyRemoteConnection, read_request};

pub async fn run(config: Config) -> Result<()> {
    info!("run the external service");
    let secret_key = config.get_service_key();

    let (hook,proto) = auth::outgoing();

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .hooks(hook)
        .bind()
        .await?;

    let _router = RouterBuilder::new(endpoint.clone())
        .accept(auth::ALPN, proto)
        .spawn();
    tokio::signal::ctrl_c().await?;

    Ok(())
}
