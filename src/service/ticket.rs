use std::str::FromStr;

use frost_ed25519::VerifyingKey;
use iroh_tickets::{ParseError, Ticket};

use iroh_base::EndpointId;
use rcan::Rcan;
use serde::{Deserialize, Serialize};

use crate::service::caps::Caps;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceTicket {
    pub target: EndpointId,
    pub origin: VerifyingKey,
    pub rcan: String,

}

impl Ticket for ServiceTicket {
    const KIND: &'static str = "keyparty";

    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("Bad service ticket")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, iroh_tickets::ParseError> {
        let res: ServiceTicket = postcard::from_bytes(bytes)?;
        Ok(res)
    }
}

impl FromStr for ServiceTicket {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ticket::deserialize(s)
    }
}

impl ServiceTicket {
    pub fn new(target: EndpointId, origin: VerifyingKey, rcan: String) -> Self {
        Self {
            target,
            origin,
            rcan,
        }
    }
}
