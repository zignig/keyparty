// Client tools for connecting to the keyparty service

use std::time::Duration;

use crate::service::AUTH_ALPN;
use anyhow::Result;
use iroh::{Endpoint, EndpointId};
use tokio::time;
use tracing::{info, warn};

pub struct KeyClient {
    endpoint: Endpoint,
    target: EndpointId,
    rcan: String,
    // authed: bool,
}

impl KeyClient {
    pub fn new(endpoint: Endpoint, target: EndpointId, rcan: String) -> Self {
        Self {
            endpoint,
            target,
            rcan,
            // authed: false,
        }
    }

    pub async fn login(&self) -> Result<u8> {
        info!("endpoint auth send {}", self.target.fmt_short());
        let conn = self.endpoint.connect(self.target, AUTH_ALPN).await?;

        info!("connected");
        let (mut send, mut recv) = conn.open_bi().await?;

        let buf = self.rcan.clone().into_bytes();

        let sent = send.write(&buf).await?;
        info!("send {} bytes", sent);
        send.finish()?;

        let msg = recv.read_to_end(10).await?;
        warn!("reply message {:?}", msg);
        if msg.len() == 1 {
            return Ok(msg[0]);
        }
        info!("finished writing");
        conn.close(1u8.into(), b"finished");
        Ok(0)
    }
}
