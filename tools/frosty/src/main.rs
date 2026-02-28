// Frosty generator

use clap::Parser;
use n0_error::Result;
use tracing::info;

mod cli;
mod config;
mod frostyrpc;
mod keygen;
mod process;
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
        0 => filter = filter.with_target("frosty", LevelFilter::INFO),
        1 => filter = filter.with_target("frosty", LevelFilter::DEBUG),
        2 => {
            filter = filter
                .with_target("iroh", LevelFilter::DEBUG)
                .with_target("frosty", LevelFilter::DEBUG)
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
        Command::Server { .. } | Command::Client { .. } => keygen::run(config, args).await,
        Command::Sign { ref file } => signing::run(config, args.clone(), file).await,
    };
    info!("{:#?}", res);
    Ok(())
}
