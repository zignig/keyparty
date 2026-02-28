use iroh::{PublicKey, SecretKey};
use n0_error::{AnyError, Result};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    secret: SecretKey,
    peers: Option<Vec<PublicKey>>,
    key_package: Option<String>,
    public_package: Option<String>,
    verify_key: Option<String>,
}

impl Config {
    pub const FILE_NAME: &str = "frosty.toml";
    pub fn load() -> Result<Config, AnyError> {
        let config = match std::fs::read_to_string(Config::FILE_NAME) {
            Ok(content) => {
                let content = content.as_str();
                let config: Config = toml::from_str(&content).expect("config broken");
                config
            }
            Err(e) => {
                error!("config file {:}", e);
                Config::new()
            }
        };
        Ok(config)
    }

    pub fn save(&self) {
        let contents = toml::to_string(&self).expect("borked config");
        std::fs::write(Config::FILE_NAME, contents).expect("borked file");
    }

    pub fn new() -> Config {
        let secret_key = SecretKey::generate(&mut rand::rng());
        let config = Config {
            secret: secret_key,
            peers: None,
            key_package: None,
            public_package: None,
            verify_key: None,
        };
        config.save();
        config
    }

    #[allow(dead_code)]
    pub fn set_peers(&mut self, peers: Vec<PublicKey>) {
        self.peers = Some(peers);
        self.save();
    }

    pub fn peers(self) -> Vec<PublicKey> { 
        match self.peers {
            Some(peers) => peers,
            None => vec![],
        }
    }

    pub fn set_packages(&mut self, key_share: String, public_share: String, verify_key: String) {
        self.key_package = Some(key_share);
        self.public_package = Some(public_share);
        self.verify_key = Some(verify_key);
        self.save();
    }
    pub fn secret(&self) -> SecretKey {
        self.secret.clone()
    }
}
