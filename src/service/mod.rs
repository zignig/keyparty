// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

mod auth;

pub mod caps;
pub mod irpc;
pub mod ticket;

use std::time::Duration;

use anyhow::Result;
use iroh::{Endpoint, endpoint::presets, protocol::RouterBuilder};
use iroh_tickets::Ticket;

use n0_error::{AnyError, anyerr};
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::{
    config::Config,
    id_store::IdClient,
    service::{irpc::ServiceMessage, ticket::ServiceTicket},
};

pub use auth::ALPN as AUTH_ALPN;
pub use irpc::ALPN as SERVICE_ALPN;

pub async fn run(
    config: Config,
    id_client: IdClient,
    service_out: Sender<ServiceMessage>,
    token: CancellationToken,
) -> Result<()> {
    info!("Run the external service");
    let secret_key = config.get_service_key();
    let my_id = secret_key.public();
    println!("\nService id = {}\n", &my_id);

    // Create the authenication sets

    let (hook, proto) = auth::incoming(id_client.clone(), my_id);

    let rpc = irpc::ServiceActor::new(id_client, service_out);

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
    token.cancelled().await;
    info!("Service runner finishing");
    Ok(())
}

pub fn issue(config: Config, args: super::cli::Args) -> Result<(), AnyError> {
    info!("Issue a rcan blob");
    match args.command {
        crate::cli::Command::Issue {
            key,
            duration,
            status,
            all,
        } => {
            info!("issue an new ticket for {:}", key.fmt_short());
            let dur = if let Some(duration) = duration {
                humantime::parse_duration(duration.as_str()).expect("Bad duration")
            } else {
                // 1 day
                Duration::from_mins(60 * 24)
            };
            info!("lifetime {:#?}", dur);
            info!("status {:#?}", status);
            let secret_key = config.get_service_key();
            if let Some(verify_key) = config.public_key() {
                debug!("issue rcan");
                let cap = if all {
                    caps::Caps::all()
                } else {
                    if status {
                        info!("status only ticket");
                        caps::Caps::status()
                    } else {
                        caps::Caps::issue()
                    }
                };
                let rc = cap.encoded(&secret_key, key, dur)?;
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
