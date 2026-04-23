// Basic example of a keyparty client

use clap::Parser;
use keyparty::KeyClient;
use n0_error::Result;

use tracing::{info, warn};

mod config {
    use std::path::PathBuf;

    use iroh::{EndpointId, PublicKey, SecretKey};

    use keyparty::{Caps, ServiceTicket};
    use n0_error::{AnyError, Result, anyerr};

    use rcan::Rcan;
    use serde::{Deserialize, Serialize};
    use tracing::{error, info};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Settings {
        secret: SecretKey,
        target: Option<EndpointId>,
        rcan: Option<String>,
        #[serde(skip)]
        config_path: PathBuf,
    }

    impl Settings {
        pub fn load(config_path: PathBuf) -> Result<Settings, AnyError> {
            let config = match std::fs::read_to_string(&config_path) {
                Ok(content) => {
                    let content = content.as_str();
                    let mut config: Settings = toml::from_str(&content).expect("config broken");
                    // set my own config path
                    config.config_path = config_path;
                    config
                }
                Err(_e) => Settings::new(config_path),
            };
            Ok(config)
        }

        pub fn save(&self) {
            error!("{:#?}",self);
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

        pub fn set_ticket(&mut self, ticket: ServiceTicket) -> Result<()> {
            info!("Save a new ticket");
            println!("{:#?}", ticket);    
            self.target = Some(ticket.target);
            self.rcan = Some(ticket.rcan);
            self.save();
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

        pub fn get_rcan(&self) -> Result<Rcan<Caps>> {
            if let Some(caps_string) = self.rcan.clone() { 
                let rc = Caps::decode(caps_string.into_bytes())?;
                return Ok(rc);
            } else { 
                return Err(anyerr!("failed rcan decode"));
            }
        }
    }
}


// Command line interface
mod cli {
    use clap_derive::Parser;
    use keyparty::ServiceTicket;
    use std::path::PathBuf;

    #[derive(Parser, Clone, Debug)]
    pub struct Args {
        #[arg(short, long, default_value = "client.toml")]
        pub config: PathBuf,
        #[arg(long)]
        pub ticket: Option<ServiceTicket>,
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

    // Connect, auth and sign

    // let _client = KeyClient::new();
    Ok(())
}
