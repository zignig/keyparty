use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use iroh::{Endpoint, endpoint::presets};
use tokio::time;
use tracing::{info, warn};



mod config {
    use iroh::{PublicKey, SecretKey};

    use n0_error::AnyError;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Settings {
        secret: SecretKey,
        target: Option<PublicKey>,
        rcan: String
    }

    impl Settings {
        pub const FILE_NAME: &str = "settings.toml";

        pub fn load() -> Result<Settings, AnyError> {
            let config = match std::fs::read_to_string(Settings::FILE_NAME) {
                Ok(content) => {
                    let content = content.as_str();
                    let config: Settings = toml::from_str(&content).expect("config broken");
                    config
                }
                Err(_e) => Settings::new(),
            };
            Ok(config)
        }

        pub fn save(&self) {
            let contents = toml::to_string(&self).expect("borked config");
            std::fs::write(Settings::FILE_NAME, contents).expect("borked file");
        }

        pub fn new() -> Settings {
            let secret = SecretKey::generate(&mut new_rand::rng());
            let set = Settings {
                secret,
                target: None,
                rcan: "".to_string(),
            };
            set.save();
            set
        }

        pub fn save_target(&mut self, public: PublicKey) {
            self.target = Some(public);
            self.save();
        }

        pub fn secret(&self) -> SecretKey {
            self.clone().secret
        }

        pub fn get_target(&self) -> Option<PublicKey> {
            self.target
        }

        pub fn get_rcan(&self) -> Vec<u8> { 
            self.rcan.clone().into_bytes()
        }

    }
}

mod cli {
    use bytes::Bytes;
    use clap_derive::Parser;
    use iroh::PublicKey;

    #[derive(Parser, Clone, Debug)]
    pub struct Args {
        #[arg(long)]
        pub target: Option<PublicKey>,
        pub sign: Option<Bytes>,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut settings = config::Settings::load()?;
    warn!("{:#?}", settings);

    let args = cli::Args::parse();
    warn!("{:#?}", args);

    if let Some(target) = args.target {
        settings.save_target(target);
    }

    if let Some(target) = settings.get_target() {
        let secret_key = settings.secret();
        let rcan = settings.get_rcan();
        warn!("public key {}",secret_key.public());

        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key.clone())
            .bind()
            .await?;

        // fake connection
        let mut exit = false;
        let mut counter = 0;
        const MAX: i32 = 5;
        while !exit {
            let f = endpoint.connect(target, b"liminal/auth/0").await?;
            let (mut send , mut recv )  = f.open_bi().await?; 

            // info!("{:?}",&rcan);

            send.write(&rcan).await?;
            send.finish()?;
            time::sleep(Duration::from_secs(2)).await;
            counter += 1;
            info!("{}", counter);
            if counter == MAX {
                exit = true;
            }
        }
        endpoint.close().await;
        // tokio::signal::ctrl_c().await?;
    }

    Ok(())
}
