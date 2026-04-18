use iroh_tickets::Ticket;

use iroh_base::EndpointId;
use serde::{Deserialize, Serialize};

use crate::service::caps::Caps;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// #[display("{}", Ticket::serialize(self))]
pub struct ServiceTicket {
    pub target: EndpointId,
    pub rcan: Caps
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

impl ServiceTicket { 
    pub fn new(target: EndpointId,rcan: Caps) -> Self {
        Self { 
           target,
           rcan 
        }
    }
}