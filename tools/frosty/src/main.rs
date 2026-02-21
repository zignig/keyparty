// Frosty generator

use std::time::Duration;

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
            let config = Config::new(endpoint.secret_key().clone());
            (config, endpoint)
        }
    };
    let _ = endpoint.online().await;

    info!("{:#?}", config);
    info!("{}", &endpoint.id());

    // set up the rpc
    let token = match args.command {
        cli::Command::Server { ref token } => token.clone(),
        cli::Command::Client { ref ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            ticket.token.clone()
        }
    };

    let frosty_rpc = FrostyServer::new(token, endpoint.id());
    let router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    match args.command {
        cli::Command::Server { token } => {
            let ticket = FrostyTicket::new(endpoint.id(), token.clone(), 4, 1);
            let val = ticket.serialize();
            println!("----------");
            println!("{}", val);
            println!("----------");
            let bork = FrostyTicket::deserialize(val.as_str())?;
            println!("{:#?}", bork);
            // test_rpc(endpoint.clone(), ticket.clone(), config).await?;
        }
        cli::Command::Client { ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            test_rpc(endpoint.clone(), ticket.clone(), config).await?;
        }
    }
    tokio::signal::ctrl_c().await?;

    router.shutdown();
    Ok(())
}

// Testing for runnigng logic

async fn test_rpc(endpoint: Endpoint, ticket: FrostyTicket, mut config: Config) -> Result<()> {
    let client = FrostyClient::connect(endpoint.clone(), ticket.addr);

    let _ = client.auth(ticket.token.as_str()).await?;

    let count = client.count().await?;
    println!("count of clients {}", count);

    let mut loop_count = 0;

    tokio::pin!(client);
    loop {
        let count = client.count().await?;
        println!("{}", count);
        if count == ticket.max_shares {
            println!("needed clients");
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        loop_count += 1;
        if loop_count > 500 {
            break;
        }
    }
    // Get the peer list
    let mut peer_list: Vec<PublicKey> = Vec::new();
    let mut peers = client.peers().await?;
    while let Some(peer) = peers.recv().await? {
        // warn!("peer id {peer:?}");
        peer_list.push(peer);
    }
    // println!("{:?}", &peer_list);
    config.set_peers(peer_list.clone());

    let my_id = endpoint.id();
    // strip out my own key
    peer_list.retain(|&key| key != my_id);

    // collect the clients
    let mut clients: Vec<(EndpointId, FrostyClient)> = Vec::new();

    for peer in peer_list {
        let client = FrostyClient::connect(endpoint.clone(), peer);
        match client.auth(ticket.token.as_str()).await {
            Ok(()) => {
                info!("connection for {:?} worked", peer);
                clients.push((peer, client));
            }
            Err(e) => {
                error!("connection for {:?} failed with {:?}", peer, e);
                error!("{:?}", ticket)
            }
        }
    }
    // println!("{:?}", clients);
    tokio::pin!(clients);
    loop {
        for i in clients.iter() {
            match i.1.boop().await {
                Ok(v) => println!("{:?} -- {:?}", i.0, v),
                Err(e) => error!("boop loop connection for {:?} failed with {:?}", i.0, e),
            }
        }
        println!("-");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tokio::signal::ctrl_c().await?;

    Ok(())
}
