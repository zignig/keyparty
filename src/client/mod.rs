// Client tools for connecting to the keyparty service

use crate::{ServiceClient, service::AUTH_ALPN};
use anyhow::Result;
use iroh::{Endpoint, EndpointId};
use n0_error::{AnyError, anyerr};
use tracing::{debug, error, info, warn};

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

    pub fn connected(&self) -> bool {
        self.authed
    }

    pub async fn signer(&self) -> ServiceClient {
        ServiceClient::connect(self.endpoint.clone(), self.target)
    }

    // multi try login
    pub async fn login(&mut self) -> Result<(), AnyError> {
        let mut counter = 0;
        const MAX_FAIL: i32 = 5;
        loop {
            match self.auth().await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    counter += 1;
                    if counter == MAX_FAIL {
                        error!("{:#?} - {} ", e, counter);
                        return Err(e.into());
                    }
                }
            };
        }
    }

    pub async fn auth(&mut self) -> Result<()> {
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
        let msg = recv.read_to_end(2).await?;
        debug!("reply message {:?}", msg);
        if msg.len() == 1 {
            if msg[0] == 1 { 
                self.authed = true;
                return Ok(())
            } else { 
                return Err(anyerr!("auth failed").into())
            }
        }
        conn.close(1u8.into(), b"finished");
        Err(anyerr!("auth failed").into())
    }
}
