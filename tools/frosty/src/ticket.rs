use iroh_tickets::Ticket;

use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// #[display("{}", Ticket::serialize(self))]
pub struct FrostyTicket {
    pub addr: EndpointId,
    pub token: String,
    pub max_shares: u16,
    pub min_shares: u16,
}

impl Ticket for FrostyTicket {
    const KIND: &'static str = "frosty";

    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("frosty ticket fail")
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, iroh_tickets::ParseError> {
        let res: FrostyTicket = postcard::from_bytes(bytes)?;
        Ok(res)
    }
}

impl FrostyTicket {
    pub fn new(addr: EndpointId, token: String, max_shares: u16, min_shares: u16) -> Self {
        Self {
            addr,
            token,
            max_shares,
            min_shares,
        }
    }
}
