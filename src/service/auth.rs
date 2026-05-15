// rcan based auth system.


/// APLN for the rcan authenciation service
pub const ALPN: &[u8] = b"keyparty/auth/0";

use crate::{
    id_store::IdClient,
    service::caps::{self, Caps},
};
use iroh::{
    EndpointAddr, PublicKey,
    endpoint::{
        AfterHandshakeOutcome, BeforeConnectOutcome, Connection, ConnectionInfo, EndpointHooks,
    },
    protocol::{AcceptError, ProtocolHandler},
};
use n0_error::{AnyError, anyerr};
use rcan::Rcan;
use std::{str, time::SystemTime};
use tracing::{debug, error, info, warn};

pub fn incoming(id_client: IdClient, id: PublicKey) -> (RCanAuth, AuthProtocol) {
    let rca = RCanAuth::new(id_client.clone());
    let ap = AuthProtocol::new(id_client, id);
    (rca, ap)
}

#[derive(Debug)]
pub struct RCanAuth {
    client: IdClient,
}

impl RCanAuth {
    pub fn new(client: IdClient) -> Self {
        Self { client }
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

        // Allow anyone to access the auth
        if alpn == ALPN {
            return AfterHandshakeOutcome::Accept;
        }
        match self.client.get(id).await.unwrap() {
            Some(_) => {
                return AfterHandshakeOutcome::Accept;
            }
            None => {
                error!("no fren of mine");
                return AfterHandshakeOutcome::Reject {
                    error_code: 55u32.into(),
                    reason: b"unauthenticated".to_vec(),
                };
            }
        }
    }
}

#[derive(Debug)]
pub struct AuthProtocol {
    client: IdClient,
    my_id: PublicKey,
}

impl AuthProtocol {
    pub fn new(client: IdClient, my_id: PublicKey) -> Self {
        Self { client, my_id }
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
        // decode checks the signature of the rcan.
        // so we know its good.
        let decode = caps::Caps::decode(rcan_bytes);
        match decode {
            Ok(d) => {
                debug!("{:#?}", &d);
                match check_rcan(d.clone(), &connection,self.my_id) {
                    Ok(_) => {
                        info!("the rcan works");
                        self.client.new_fren(connection.remote_id(), d).await;
                        send.write(&[1]).await.unwrap();
                    }
                    Err(e) => {
                        send.write(&[0]).await.unwrap();
                        error!("rcan fail {}", e);
                    }
                }
            }
            Err(e) => {
                let _ = self.client.remove(connection.remote_id()).await;
                send.write(&[0]).await.unwrap();
                info!("{:#?}", e);
            }
        }
        send.finish()?;

        connection.closed().await;
        Ok(())
    }
}

fn check_rcan(rcan: Rcan<Caps>, conn: &Connection,my_id: PublicKey) -> Result<(), AnyError> {
    let time = SystemTime::now();
    if rcan.expires().is_valid_at(time) {
        info!("still valid");
        let pubkey = PublicKey::from_bytes(rcan.audience().as_bytes())?;
        if conn.remote_id() == pubkey {
            info!("remote id good");
            let target = PublicKey::from_bytes(rcan.issuer().as_bytes())?;
            if target == my_id { 
                info!("local is good");
                return Ok(());
            }   
        }
    }
    Err(anyerr!("rcan fail"))
}
