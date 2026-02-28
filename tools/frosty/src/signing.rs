// Signing can be done with a gossip channel

use n0_error::Result;
use tracing::info;

use crate::{cli::Args, config::Config};

pub async fn run(config: Config, args: Args, file: String) -> Result<()> {
    info!("Start the signing party");
    let _ = args;
    let _ = config;
    let _ = file;
    
    Ok(())
}
