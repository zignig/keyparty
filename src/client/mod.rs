// Client tools for connecting to the keyparty service 

use iroh::{Endpoint, EndpointId};
use crate::service::AUTH_ALPN;
use anyhow::Result;

pub struct KeyClient { 
    endpoint: Endpoint,
    target: EndpointId,
    rcan: String,
    authed: bool,
} 

impl KeyClient { 
    pub fn  new(endpoint: Endpoint,target: EndpointId,rcan: String) -> Self { 
        Self { 
            endpoint,
            target,
            rcan,
            authed: false
        }
    }

    pub async fn auth(&self ) -> Result<bool> { 
        let conn = self.endpoint.connect(self.target,AUTH_ALPN).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        let buf = self.rcan.as_bytes();
        send.write(&buf).await?;
        send.finish()?;
        Ok(true)
    }
}
