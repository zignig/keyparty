// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

mod auth;

pub mod irpc;
pub mod caps;
pub mod ticket;

use anyhow::Result;
use iroh::{Endpoint, endpoint::presets, protocol::RouterBuilder};
use iroh_tickets::Ticket;

use n0_error::{AnyError, anyerr};
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{config::Config, id_store::IdClient, service::{irpc::ServiceMessage, ticket::ServiceTicket}};

pub use auth::ALPN as AUTH_ALPN;
pub use irpc::ALPN as SERVICE_ALPN;

pub async fn run(config: Config, id_client: IdClient, service_out: Sender<ServiceMessage>,token: CancellationToken) -> Result<()> {
    info!("run the external service");
    let secret_key = config.get_service_key();
    println!("service id {}", secret_key.public());

    // Create the authenication sets
    let (hook, proto) = auth::incoming(id_client.clone());

    let rpc = irpc::ServiceActor::new(id_client,service_out);

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .hooks(hook)
        .bind()
        .await?;

    let _router = RouterBuilder::new(endpoint.clone())
        .accept(auth::ALPN, proto)
        .accept(irpc::ALPN, rpc)
        .spawn();
    
    // wait for the upper to finish
    token.cancelled().await ;
    info!("Service runner finishing");
    Ok(())
}

pub fn issue(config: Config, args: super::cli::Args) -> Result<(), AnyError> {
    info!("Issue a rcan blob");
    match args.command {
        crate::cli::Command::Issue { key, .. } => {
            info!("issue an new ticket for {:}", key.fmt_short());
            let secret_key = config.get_service_key();
            if let Some(verify_key) = config.public_key() {
                debug!("issue rcan");
                let cap = caps::Caps::issue();
                let rc = cap.encoded(&secret_key, key)?;
                let ticket = ServiceTicket::new(secret_key.clone().public(), verify_key, rc);
                let val = ticket.serialize();
                println!("-------- ticket -------\n");
                println!("  {}", &val);
                println!("\n-----------------------");
                if args.verbose > 0 {
                    let un = ServiceTicket::deserialize(val.as_str())?;
                    println!("{:#?}", un);
                }
                return Ok(());
            }
            Err(anyerr!("missing verify key"))
        }
        _ => Ok(()),
    }
}
