// Key set generation mode

mod frostyrpc;
mod process;

use frostyrpc::{FrostyClient, FrostyServer};
use process::DistributedKeyGeneration;

use crate::{
    cli::{Args, Command},
    config::Config,
    ticket::FrostyTicket,
};

use iroh::Endpoint;
use iroh_tickets::Ticket;
use n0_error::Result;
use tokio::task;
use tracing::info;

pub async fn run(config: Config, args: Args) -> Result<()> {
    let endpoint = Endpoint::builder()
        // .secret_key(config.secret())
        .bind()
        .await?;

    // let endpoint = Endpoint::builder()
    //     .secret_key(config.secret())
    //     .relay_mode(RelayMode::Disabled)
    //     .bind()
    //     .await?;

    // // temp until the internet is fixed

    // let mdns = MdnsAddressLookup::builder().build(endpoint.id()).unwrap();
    // endpoint.address_lookup().add(mdns.clone());

    // get online
    info!("Get online");
    let _ = endpoint.online().await;
    println!("{:#?}", args);
    info!("{}", &endpoint.id());

    // set up the rpc

    let (token, max) = match args.command {
        Command::Generate { ref token, max, .. } => (token.clone(), max),
        Command::Join { ref ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            (ticket.token.clone(), ticket.max_shares)
        }
        Command::Sign { .. } => return Ok(()),
    };

    // make the frosty server
    let secondary = config.secondary().public();
    let frosty_rpc = FrostyServer::new(token.clone(), max as usize, endpoint.id(), secondary);

    // create a local client
    let local_rpc = frosty_rpc.clone().local();

    // spawn the router
    let router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    // create the process based on the mode
    let (process_client, ticket) = match args.command {
        Command::Generate { token, max, min } => {
            let ticket = FrostyTicket::new(endpoint.id(), token.clone(), max, min);
            let val = ticket.serialize();
            println!("-----------------------------------------------------");
            println!("");
            println!("  Ticket to share: {}", val);
            println!("");
            println!("-----------------------------------------------------");

            let bork = FrostyTicket::deserialize(val.as_str())?;
            println!("{:#?}", bork);

            (local_rpc.clone(), ticket)
        }
        Command::Join { ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            (FrostyClient::connect(endpoint.clone(), ticket.addr), ticket)
        }
        Command::Sign { .. } => return Ok(()),
    };

    // Kick off the process
    // Create the generator

    let dkg =
        DistributedKeyGeneration::new(endpoint.clone(), local_rpc, process_client, ticket, config);
    // Spawn a new runner
    let handle = task::spawn(dkg.run());
    let _res = handle.await;

    let _ = router.shutdown().await;
    Ok(())
}
