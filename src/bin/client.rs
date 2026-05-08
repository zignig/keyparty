// Basic example of a keyparty client

use std::any;

use clap::Parser;
use iroh::{Endpoint, endpoint::presets};
use keyparty::KeyClient;
use n0_error::{Result, anyerr};
use tracing::{debug, error, info, warn};
// use tracing_subscriber::filter::{LevelFilter, Targets};
// use tracing_subscriber::prelude::*;

mod config {
    use iroh::{EndpointId, PublicKey, SecretKey};
    use std::path::PathBuf;

    use keyparty::ServiceTicket;
    use n0_error::{AnyError, Result};

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
            error!("{:#?}", self);
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

        pub fn get_rcan(&self) -> Option<String> {
            // if let Some(caps_string) = self.rcan.clone() {
            //     let rc = Caps::decode(caps_string.into_bytes())?;
            //     return Ok(rc);
            // } else {
            //     return Err(anyerr!("failed rcan decode"));
            // }
            self.rcan.clone()
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
    // let mut filter = Targets::new();
    // filter = filter.with_target("client", LevelFilter::DEBUG);
    // tracing_subscriber::registry()
    //     .with(tracing_subscriber::fmt::layer())
    //     .with(filter)
    //     .init();
    tracing_subscriber::fmt::init();

    // Cli
    let args = cli::Args::parse();
    debug!("{:#?}", args);

    // Settings
    let mut config = config::Settings::load(args.config)?;
    debug!("{:#?}", config);

    // Show my public key
    println!("{:?}", config.public());

    // is there a new ticket on the command line ?
    if let Some(ticket) = args.ticket {
        config.set_ticket(ticket)?;
    }

    // Create the client...
    if let Some(target) = config.get_target() {
        // Connect, auth and sign
        let secret_key = config.secret();
        if let Some(rcan) = config.get_rcan() {
            let endpoint = Endpoint::builder(presets::N0)
                .secret_key(secret_key.clone())
                .bind()
                .await?;
            // let _ = endpoint.online().await;
            // create the key client
            info!("create an endpoint and connect to {}", target.fmt_short());
            let mut client = KeyClient::new(endpoint.clone(), target, rcan);
            warn!("send auth");
            let mut exit = false;
            let mut count = 0;
            const MAX_COUNT: i32 = 5;
            while !exit {
                let val = match client.login().await {
                   Ok(val )  => {
                        warn!("auth returned {:?}", val);
                        exit = true;
                        val
                    }
                    Err(e) => {
                        error!("conn fail !! {:?} - {:?}", e, count);
                        count += 1;
                        if count == MAX_COUNT {
                            return Err(anyerr!("connection failed"));
                        }
                        0
                    }
                };
                println!("{:?}", val);
            }
            endpoint.close().await;
        } else {
            info!("no rcan");
        }
    } else {
        println!("No target , need a ticket issued to work.")
    }

    Ok(())
}
