// rcan based auth system.

pub const ALPN: &[u8] = b"liminal/auth/0";

use crate::service::caps;
use iroh::{
    EndpointAddr,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, ConnectionInfo, EndpointHooks},
    protocol::{AcceptError, ProtocolHandler},
};
use std::str;
use tracing::{info, warn};

pub fn incoming() -> (RCanAuth, AuthProtocol) {
    let rca = RCanAuth::new();
    let ap = AuthProtocol::new();
    (rca, ap)
}

#[derive(Debug)]
pub struct RCanAuth;

impl RCanAuth {
    pub fn new() -> Self {
        Self {}
    }
}

impl EndpointHooks for RCanAuth {
    async fn before_connect(
        &self,
        _remote_addr: &EndpointAddr,
        _alpn: &[u8],
    ) -> BeforeConnectOutcome {
        // Reject all outgoing
        BeforeConnectOutcome::Reject
    }

    async fn after_handshake(&self, conn: &ConnectionInfo) -> AfterHandshakeOutcome {
        let side = conn.side();
        let id = conn.remote_id();
        let alpn = conn.alpn();
        warn!(
            "{}, {:?} , {:?} ",
            id.fmt_short(),
            side,
            str::from_utf8(&alpn).unwrap()
        );
        AfterHandshakeOutcome::Accept
    }
}

#[derive(Debug)]
pub struct AuthProtocol;

impl AuthProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProtocolHandler for AuthProtocol {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        warn!(
            "auth connection from {:}",
            connection.remote_id().fmt_short()
        );
        let (mut send, mut recv) = connection.accept_bi().await?;
        let rcan_bytes = recv
            .read_to_end(254)
            .await
            .map_err(AcceptError::from_err)?;
        // info!("{:?}",rcan_bytes);
        let decode = caps::Caps::decode(rcan_bytes);
        match decode {
            Ok(d) => {
                info!("{:#?}", d);
            }
            Err(e) => info!("{:#?}", e),
        }
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}
