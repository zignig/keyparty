// Frosty generator

use clap::Parser;
use iroh::Endpoint;
use iroh_tickets::Ticket;
use n0_error::Result;
use tokio::task;
use tracing::{error, info};

mod cli;
mod config;
mod frostyrpc;
mod process;
mod ticket;

use cli::Args;
use config::Config;
use frostyrpc::FrostyServer;
use process::DistributedKeyGeneration;

use crate::{frostyrpc::FrostyClient, ticket::FrostyTicket};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // println!("{:#?}", args);

    let (config, endpoint) = match Config::load() {
        Ok(config) => {
            let endpoint = Endpoint::builder()
                .secret_key(config.secret())
                .bind()
                .await?;
            (config, endpoint)
        }
        Err(e) => {
            error!("{:?}", e);
            let endpoint = Endpoint::builder().bind().await?;
            let config = Config::new(endpoint.secret_key().clone());
            (config, endpoint)
        }
    };

    // get online
    let _ = endpoint.online().await;

    // info!("{:#?}", config);
    info!("{}", &endpoint.id());

    // set up the rpc

    let (token, max) = match args.command {
        cli::Command::Server { ref token, max, .. } => (token.clone(), max),
        cli::Command::Client { ref ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            (ticket.token.clone(), ticket.max_shares)
        }
    };

    // make the frosty server
    let frosty_rpc = FrostyServer::new(token.clone(), max as usize, endpoint.id());

    // create a local client
    let local_rpc = frosty_rpc.clone().local();

    let router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    // create the process based on the mode
    let (process_client, ticket) = match args.command {
        cli::Command::Server { token, max, min } => {
            let ticket = FrostyTicket::new(endpoint.id(), token.clone(), max, min);
            let val = ticket.serialize();
            println!("---| Ticket for client |---");
            println!("{}", val);
            println!("---------------------------");
            let bork = FrostyTicket::deserialize(val.as_str())?;
            println!("{:#?}", bork);
            (local_rpc.clone(), ticket)
        }
        cli::Command::Client { ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            // task::spawn(test_rpc(endpoint.clone(), ticket.clone(), config));
            (FrostyClient::connect(endpoint.clone(), ticket.addr), ticket)
        }
    };

    // Kick off the process
    // Create the generator
    let dkg =
        DistributedKeyGeneration::new(endpoint.clone(), local_rpc, process_client, ticket, config);
    // Spawn a new runner
    let handle = task::spawn(dkg.run());
    let _res = handle.await;

    // tokio::signal::ctrl_c().await?;

    let _ = router.shutdown().await;
    Ok(())
}
