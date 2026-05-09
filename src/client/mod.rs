// Client tools for connecting to the keyparty service

use crate::{ServiceClient, service::AUTH_ALPN};
use anyhow::Result;
use iroh::{Endpoint, EndpointId};
use tracing::{debug, info, warn};

pub struct KeyClient {
    endpoint: Endpoint,
    target: EndpointId,
    rcan: String,
    authed: bool,
}

impl KeyClient {
    pub fn new(endpoint: Endpoint, target: EndpointId, rcan: String) -> Self {
        Self {
            endpoint,
            target,
            rcan,
            authed: false,
        }
    }

    pub async fn signer(&self) -> ServiceClient {
        ServiceClient::connect(self.endpoint.clone(), self.target)
    }

    pub async fn login(&mut self) -> Result<u8> {
        debug!("endpoint auth send {}", self.target.fmt_short());
        let conn = self.endpoint.connect(self.target, AUTH_ALPN).await?;

        debug!("auth incoming");
        let (mut send, mut recv) = conn.open_bi().await?;

        // send the rcan up
        let buf = self.rcan.clone().into_bytes();

        // write
        let sent = send.write(&buf).await?;
        info!("send {} bytes", sent);
        send.finish()?;

        // get the response
        let msg = recv.read_to_end(10).await?;
        warn!("reply message {:?}", msg);
        if msg.len() == 1 {
            debug!("client is authenticated");
            self.authed = true;
            return Ok(msg[0]);
        }
        conn.close(1u8.into(), b"finished");
        Ok(0)
    }
}
