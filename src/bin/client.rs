// Basic example of a keyparty client

use keyparty::KeyClient;


use tracing::error;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    error!("working!!");
    let _client = KeyClient::new();
    Ok(())
}
