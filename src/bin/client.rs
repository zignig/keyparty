// Basic example of a keyparty client

use clap::Parser;
use n0_error::Result;

use tracing::{info, warn};

mod config {
    use std::path::PathBuf;

    use iroh::{EndpointId, PublicKey, SecretKey};

    use iroh_tickets::Ticket;
    use keyparty::{Caps, ServiceTicket};
    use n0_error::{AnyError, Result};

    use serde::{Deserialize, Serialize};
    use tracing::info;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Settings {
        secret: SecretKey,
        target: Option<EndpointId>,
        rcan: Option<Caps>,
        #[serde(skip)]
        config_path: PathBuf,
    }

    impl Settings {
        pub fn load(config_path: PathBuf) -> Result<Settings, AnyError> {
            let config = match std::fs::read_to_string(&config_path) {
                Ok(content) => {
                    let content = content.as_str();
                    let config: Settings = toml::from_str(&content).expect("config broken");
                    config
                }
                Err(_e) => Settings::new(config_path),
            };
            Ok(config)
        }

        pub fn save(&self) {
            let contents = toml::to_string(&self).expect("borked config");
            std::fs::write(self.config_path.clone(), contents).expect("borked file");
        }

        pub fn new(config_path: PathBuf) -> Settings {
            let secret = SecretKey::generate(&mut new_rand::rng());
            let set = Settings {
                secret,
                target: None,
                rcan: None,
                config_path,
            };
            set.save();
            set
        }

        pub fn set_ticket(&mut self, ticket: String) -> Result<()> {
            info!("Save a new ticket");
            println!("{}", ticket);
            let  service_ticket: ServiceTicket = ServiceTicket::deserialize(ticket.as_str())?;
            
            Ok(())
        }

        pub fn secret(&self) -> SecretKey {
            self.clone().secret
        }

        pub fn public(&self) -> EndpointId {
            self.clone().secret.public()
        }

        pub fn get_target(&self) -> Option<PublicKey> {
            self.target.clone()
        }

        pub fn get_rcan(&self) -> Option<Caps> {
            self.rcan.clone()
        }
    }
}


// Command line interface
mod cli {
    use clap_derive::Parser;
    use std::path::PathBuf;

    #[derive(Parser, Clone, Debug)]
    pub struct Args {
        #[arg(short, long, default_value = "client.toml")]
        pub config: PathBuf,
        #[arg(long)]
        pub ticket: Option<String>,
    }
}


// The client test 
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Cli
    let args = cli::Args::parse();
    warn!("{:#?}", args);

    // Settings
    let mut settings = config::Settings::load(args.config)?;
    warn!("{:#?}", settings);

    // Show my public key
    println!("{:?}", settings.public());

    // is there a new ticket on the command line ?
    if let Some(ticket) = args.ticket {
        settings.set_ticket(ticket)?;
    }

    // Create the client...
    if let Some(target) = settings.get_target() {
        info!("create an endpoint and connect to {}", target);
    } else {
        println!("No target , need a ticket issued to work.")
    }

    // let _client = KeyClient::new();
    Ok(())
}
