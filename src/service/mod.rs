// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

mod auth;
mod caps;
mod irpc;

use anyhow::Result;
use iroh::{Endpoint, endpoint::presets, protocol::RouterBuilder};
use tracing::info;

use crate::config::Config;

pub async fn run(config: Config) -> Result<()> {
    let c = caps::Caps::issue();
    info!("CAPABILITY => {:#?}", c);
    info!("{}", c.as_text());

    info!("run the external service");
    let secret_key = config.get_service_key();
    println!("service id {}", secret_key.public());

    let (hook, proto) = auth::incoming();

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .hooks(hook)
        .bind()
        .await?;

    // make a rcan for testing
    // let rc = c.make(secret_key,endpoint.id())?;
    let enc = c.encoded(secret_key, endpoint.id())?;
    info!("the rcan => {:}", enc);
    // check the decode
    info!("decoded = {:#?}",caps::Caps::decode(enc.into_bytes()));

    let _router = RouterBuilder::new(endpoint.clone())
        .accept(auth::ALPN, proto)
        .spawn();
    tokio::signal::ctrl_c().await?;

    Ok(())
}
