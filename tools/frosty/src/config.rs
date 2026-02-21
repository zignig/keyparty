use iroh::{EndpointId, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use n0_error::{AnyError, Result, StdResultExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    token: String,
    mother_ship: Option<PublicKey>,
    secret: SecretKey,
}

impl Config {
    const FILE_NAME: &str = "frosty.toml";
    pub fn load() -> Result<Config, AnyError> {
        let content = std::fs::read_to_string(Config::FILE_NAME)?;
        let content = content.as_str();
        let config: Config = toml::from_str(&content).expect("config broken");
        Ok(config)
    }

    pub fn save(&self) {
        let contents = toml::to_string(&self).expect("borked config");
        std::fs::write(Config::FILE_NAME, contents).expect("borked file");
    }

    pub fn new(secret: SecretKey,addr: EndpointId) -> Config {
        let config = Config {
            token: "frosty".to_string(),
            mother_ship: Some(addr),
            secret: secret,
        };
        config.save();
        config
    }

    pub fn secret(&self) -> SecretKey { 
        self.secret.clone()
    }

    pub fn mother_ship(&self) -> Option<PublicKey>{ 
        self.mother_ship.clone()
    }

    pub fn token(&self) -> String { 
        self.token.clone()
    }
}