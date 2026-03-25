// rcan based auth system.

pub const ALPN: &[u8] = b"liminal/auth/0";

use crate::{
    service::caps::{self, Caps},
    signing::now,
};
use iroh::{
    EndpointAddr, PublicKey,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, Connection, ConnectionInfo, EndpointHooks},
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{AnyError, anyerr};
use rcan::Rcan;
use std::{str, time::SystemTime};
use tracing::{error, info, warn};

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
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        warn!(
            "auth connection from {:}",
            connection.remote_id().fmt_short()
        );
        let (mut send, mut recv) = connection.accept_bi().await?;
        let rcan_bytes = recv.read_to_end(254).await.map_err(AcceptError::from_err)?;
        // info!("{:?}",rcan_bytes);
        // decode checks the signature of the rcan.
        // so we know its good.
        let decode = caps::Caps::decode(rcan_bytes);
        match decode {
            Ok(d) => {
                info!("{:#?}", &d);
                match check_rcan(d,&connection) {
                    Ok(_) => info!("the rcan works"),
                    Err(e) => error!("rcan fail {}",e),
                }
            }
            Err(e) => info!("{:#?}", e),
        }
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}

fn check_rcan(rcan: Rcan<Caps>,conn: &Connection) -> Result<(), AnyError> {
    let time = SystemTime::now();
    if rcan.expires().is_valid_at(time) {
        info!("still valid");
        let pubkey = PublicKey::from_bytes(rcan.audience().as_bytes())?;
        if conn.remote_id() == pubkey {
            info!("remote id good");
            return Ok(());
        }
    }
    Err(anyerr!("rcan fail"))
}
