// Frosty generator

use clap::Parser;
use n0_error::Result;
use tracing::info;

mod cli;
mod config;
mod keygen;
mod signing;
mod ticket;

use cli::{Args, Command};
use config::Config;

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
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    // Mode switch keygen / signing party
    let config = Config::load()?;
    let res = match args.command {
        Command::Generate { .. } | Command::Join { .. } => {
            // So it gets dropped
            {
                keygen::run(config.clone(), args).await
            }
            // FIX , run up the signer in base mode.
            // use preparty to generate RBAC keys
            // let new_args = cli::Args {
            //     command: Command::Sign { message: None },
            //     verbose: 0,
            // };
            // signing::run(config, new_args, None).await
        }
        Command::Sign { ref message, service } => signing::run(config, args.clone(), message.clone(),service).await,
    };
    info!("{:#?}", res);
    Ok(())
}
