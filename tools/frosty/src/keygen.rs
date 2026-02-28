// Key set generation mode

use crate::{
    cli::{Args, Command},
    config::Config,
    frostyrpc::{self, FrostyClient, FrostyServer},
    process::DistributedKeyGeneration,
    ticket::FrostyTicket,
};

use iroh::Endpoint;
use n0_error::Result;
use tokio::task;
use tracing::info;
use iroh_tickets::Ticket;

pub async fn run(config: Config, args: Args) -> Result<()> {
    let endpoint = Endpoint::builder()
        .secret_key(config.secret())
        .bind()
        .await?;

    // get online
    info!("Get online");
    let _ = endpoint.online().await;
    println!("{:#?}", args);
    info!("{}", &endpoint.id());

    // set up the rpc

    let (token, max) = match args.command {
        Command::Server { ref token, max, .. } => (token.clone(), max),
        Command::Client { ref ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            (ticket.token.clone(), ticket.max_shares)
        },
        Command::Sign { .. } => return Ok(())
    };

    // make the frosty server
    let frosty_rpc = FrostyServer::new(token.clone(), max as usize, endpoint.id());

    // create a local client
    let local_rpc = frosty_rpc.clone().local();

    // spawn the router
    let router = iroh::protocol::RouterBuilder::new(endpoint.clone())
        .accept(frostyrpc::ALPN, frosty_rpc)
        .spawn();

    // create the process based on the mode
    let (process_client, ticket) = match args.command {
        Command::Server { token, max, min } => {
            let ticket = FrostyTicket::new(endpoint.id(), token.clone(), max, min);
            let val = ticket.serialize();
            println!("Ticket to share: {}", val);
            let bork = FrostyTicket::deserialize(val.as_str())?;
            println!("{:#?}", bork);
            (local_rpc.clone(), ticket)
        }
        Command::Client { ticket } => {
            let ticket = FrostyTicket::deserialize(ticket.as_str()).expect("bad ticket");
            (FrostyClient::connect(endpoint.clone(), ticket.addr), ticket)
        }
        Command::Sign { .. } => return Ok(())
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
