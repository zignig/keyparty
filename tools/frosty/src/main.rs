// Frosty generator

use std::time::Duration;

use clap::Parser;
use iroh::{Endpoint, EndpointId, PublicKey};
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

    // make the frosty server
    let frosty_rpc = FrostyServer::new(token.clone(), 3, endpoint.id());
    // create a local client
    let local_rpc = frosty_rpc.clone().local();

    let router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    // create the process based on the mode
    let (process_client, ticket) = match args.command {
        cli::Command::Server { token } => {
            let ticket = FrostyTicket::new(endpoint.id(), token.clone(), 3, 2);
            let val = ticket.serialize();
            println!("----------");
            println!("{}", val);
            println!("----------");
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

    // task::spawn(local(process_client,token));
    // tokio::signal::ctrl_c().await?;

    let _ = router.shutdown().await;
    Ok(())
}

// Testing for running logic
#[allow(dead_code)]
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
        if count == ticket.max_shares as usize {
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
    // this is sync so it will stop if any of the nodes fail
    tokio::pin!(clients);
    let mut fail_count = 0;
    const MAX_FAIL: i32 = 5;
    loop {
        for i in clients.iter() {
            match i.1.boop().await {
                Ok(v) => println!("{:?} -- {:?}", i.0, v),
                Err(e) => {
                    error!("boop {:?} failed {:?} with {:?}", i.0, fail_count, e);
                    fail_count += 1;
                    if fail_count >= MAX_FAIL {
                        return Ok(());
                    }
                    // try to reauth
                    // let _ = i.1.auth(ticket.token.as_str()).await;
                }
            }
        }
        println!("-");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
