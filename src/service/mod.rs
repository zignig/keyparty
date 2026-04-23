// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

mod auth;
mod irpc;

pub mod caps;
pub mod ticket;

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use iroh::{Endpoint, endpoint::presets, protocol::RouterBuilder};
use iroh_tickets::Ticket;

use n0_error::{AnyError, anyerr};
use tracing::info;

use crate::{config::Config, service::ticket::ServiceTicket};

pub async fn run(config: Config) -> Result<()> {
    info!("run the external service");
    let secret_key = config.get_service_key();
    println!("service id {}", secret_key.public());

    let (hook, proto) = auth::incoming();

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .hooks(hook)
        .bind()
        .await?;

    let _router = RouterBuilder::new(endpoint.clone())
        .accept(auth::ALPN, proto)
        .spawn();
    tokio::signal::ctrl_c().await?;

    Ok(())
}

pub fn issue(config: Config, args: super::cli::Args) -> Result<(), AnyError> {
    info!("Issue a rcan blob");
    match args.command {
        crate::cli::Command::Issue { key, all } => {
            let secret_key = config.get_service_key();
            if let Some(verify_key) = config.public_key() {
                let cap = caps::Caps::issue();
                let rc = cap.encoded(&secret_key,key)?;
                let ticket = ServiceTicket::new(secret_key.clone().public(), verify_key, rc);
                let val = ticket.serialize();
                println!("-------- ticket -------\n");
                println!("  {}", &val);
                println!("\n-----------------------");
                if args.verbose > 0 {
                    let un = ServiceTicket::deserialize(val.as_str())?;
                    println!("{:?}", un);
                }
                return Ok(());
            }
            Err(anyerr!("missing verify key"))
        }
        _ => Ok(()),
    }
}
