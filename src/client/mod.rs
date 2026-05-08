// Client tools for connecting to the keyparty service

use crate::service::AUTH_ALPN;
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

    pub async fn login(&mut self) -> Result<u8> {
        debug!("endpoint auth send {}", self.target.fmt_short());
        let conn = self.endpoint.connect(self.target, AUTH_ALPN).await?;

        debug!("auth incoming");
        let (mut send, mut recv) = conn.open_bi().await?;

        let buf = self.rcan.clone().into_bytes();

        let sent = send.write(&buf).await?;
        info!("send {} bytes", sent);
        send.finish()?;

        let msg = recv.read_to_end(10).await?;
        warn!("reply message {:?}", msg);
        if msg.len() == 1 {
            self.authed = true;
            return Ok(msg[0]);
        }
        info!("finished writing");
        conn.close(1u8.into(), b"finished");
        Ok(0)
    }
}
