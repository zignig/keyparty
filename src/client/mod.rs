// Client tools for connecting to the keyparty service 

use iroh::{Endpoint, EndpointId};

pub struct KeyClient { 
    endpoint: Endpoint,
    target: EndpointId
} 

impl KeyClient { 
    pub fn  new(endpoint: Endpoint,target: EndpointId) -> Self { 
        Self { 
            endpoint,
            target,
        }
    }
}
