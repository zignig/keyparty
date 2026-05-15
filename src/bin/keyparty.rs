// Frosty generator

use clap::Parser;
use n0_error::Result;
use tracing::info;

use keyparty::{Args, Command, Config, keygen, service, signing};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    info!("Starting Keyparty");
    let args = Args::parse();
    let mut filter = Targets::new();
    match args.verbose {
        0 => filter = filter.with_target("keyparty", LevelFilter::INFO),
        1 => filter = filter.with_target("keyparty", LevelFilter::DEBUG),
        2 => {
            filter = filter
                .with_target("iroh", LevelFilter::DEBUG)
                .with_target("keyparty", LevelFilter::DEBUG)
        }
        _ => {}
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().compact())
        .with(filter)
        .init();

    // Mode switch keygen / signing party
    let config = Config::load()?;
    let _ = match args.command {
        Command::Generate { .. } | Command::Join { .. } => {
            // run key generation
            keygen::run(config.clone(), args).await
        }
        Command::Sign { service } => {
            // Set up the signing system
            signing::run(config, args.clone(), service).await
        }
        Command::Issue { .. } => {
            // issue  new rbac
            service::issue(config.clone(), args.clone())
            // signing::run(config, args.clone(), true).await
        }
    };
    Ok(())
}
