// Frosty generator

use clap::Parser;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey};
use iroh_tickets::Ticket;
use n0_error::Result;
use tracing::{error, info, warn};

mod cli;
mod config;
mod frostyrpc;
mod ticket;

use cli::Args;
use config::Config;
use frostyrpc::FrostyServer;

use crate::{frostyrpc::FrostyClient, ticket::FrostyTicket};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    println!("{:#?}", args);

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
            let config = Config::new(endpoint.secret_key().clone(), endpoint.id());
            (config, endpoint)
        }
    };
    let _ = endpoint.online().await;

    info!("{:#?}", config);
    info!("{}", &endpoint.id());

    // set up the rpc

    let frosty_rpc = FrostyServer::new(config.token().to_string());
    let _router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    match args.command {
        cli::Command::Server => {
            let ticket = FrostyTicket::new(endpoint.id(),config.token(), 5, 3);
            let val = ticket.serialize();
            println!("----------");
            println!("{}",val);
            println!("----------");
            let bork = FrostyTicket::deserialize(val.as_str())?;
            println!("{:#?}",bork)
        }
        cli::Command::Client{ ticket } => {
            let t =  FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            // let addr = match config.mother_ship() {
            //     Some(addr) => addr,
            //     None => endpoint.id(),
            // };
            // warn!("endpoint attach {:#?}", addr as EndpointId);
            test_rpc(endpoint.clone(),t.addr, t.token.as_str()).await?;
        }
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn test_rpc(endpoint: Endpoint, addr: EndpointId, auth: &str) -> Result<()> {
    let client = FrostyClient::connect(endpoint, addr);
    let _ = client.auth(auth).await?;

    let mut peers = client.peers().await?;
    while let Some(value) = peers.recv().await? {
        warn!("peers value = {value:?}");
    }
    Ok(())
}
