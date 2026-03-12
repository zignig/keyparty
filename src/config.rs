use frost_ed25519::{
    Identifier, VerifyingKey,
    keys::{KeyPackage, PublicKeyPackage},
};
use iroh::{PublicKey, SecretKey};
use n0_error::{AnyError, Result, anyerr};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    secondary_key: SecretKey,
    peers: Option<Vec<PublicKey>>,
    secondary_peers: Option<Vec<PublicKey>>,

    // encoded
    key_package: Option<String>,
    public_package: Option<String>,

    verify_key: Option<VerifyingKey>,
    max: u16,
    min: u16,
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
        // let secret_key = SecretKey::generate(&mut new_rand::rng());
        let secondary_key = SecretKey::generate(&mut new_rand::rng());
        let config = Config {
            // secret: secret_key,
            secondary_key: secondary_key,
            peers: None,
            secondary_peers: None,
            key_package: None,
            public_package: None,
            verify_key: None,
            max: 3,
            min: 2,
        };
        config.save();
        config
    }

    pub fn set_peers(&mut self, peers: Vec<PublicKey>) {
        self.peers = Some(peers);
        self.save();
    }

    pub fn get_key_pacakge(&self) -> Result<KeyPackage, AnyError> {
        match &self.key_package {
            Some(pack) => {
                let r = data_encoding::BASE32_NOPAD
                    .decode(pack.as_bytes())
                    .expect("bad package");
                let v: &[u8] = &r;
                let val = KeyPackage::deserialize(v).expect("borked");
                Ok(val)
            }
            None => Err(anyerr!("key package broken")),
        }
    }

    pub fn get_public_package(&self) -> Result<PublicKeyPackage, AnyError> {
        match &self.public_package {
            Some(pack) => {
                let r = data_encoding::BASE32_NOPAD
                    .decode(pack.as_bytes())
                    .expect("bad package");
                let v: &[u8] = &r;
                let val = PublicKeyPackage::deserialize(v).expect("borked");
                Ok(val)
            }
            None => Err(anyerr!("public package broken")),
        }
    }

    pub fn peers(self) -> Vec<PublicKey> {
        match self.peers {
            Some(peers) => peers,
            None => vec![],
        }
    }

    #[allow(dead_code)]
    pub fn secondaries(self) -> Vec<PublicKey> {
        match self.secondary_peers {
            Some(peers) => peers,
            None => vec![],
        }
    }

    pub fn set_packages(
        &mut self,
        key_share: String,
        public_share: String,
        verify_key: VerifyingKey,
    ) {
        self.key_package = Some(key_share);
        self.public_package = Some(public_share);
        self.verify_key = Some(verify_key);
        self.save();
    }

    pub fn set_max_min(&mut self, max: u16, min: u16) {
        self.max = max;
        self.min = min;
        self.save();
    }

    #[allow(dead_code)]
    pub fn public_key(&self) -> Option<VerifyingKey> {
        self.verify_key
    }

    pub fn secondary(&self) -> SecretKey {
        self.secondary_key.clone()
    }

    pub fn save_secondary(&mut self, secondaries: Vec<PublicKey>) {
        self.secondary_peers = Some(secondaries);
        self.save();
    }

    // pub fn secret(&self) -> SecretKey {
    //     self.secret.clone()
    // }

    pub fn min(&self) -> usize {
        self.min as usize
    }
}
