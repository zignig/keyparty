// rcan based auth system.

pub const ALPN: &[u8] = b"liminal/auth/0";

use iroh::{
    EndpointAddr,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, ConnectionInfo, EndpointHooks}, protocol::{AcceptError, ProtocolHandler},
};
use tracing::warn;

pub fn outgoing() -> (RCanAuth,AuthProtocol) { 
    let rca = RCanAuth::new();
    let ap = AuthProtocol::new();
    (rca,ap)
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
        warn!("{}, {:?} , {:?} ",id.fmt_short(),side,alpn);
        AfterHandshakeOutcome::Accept
    }
}

#[derive(Debug)]
pub struct AuthProtocol ; 

impl AuthProtocol { 
    pub fn new() -> Self { 
        Self {}
    }
}

impl ProtocolHandler for AuthProtocol {
    async fn accept(
        &self,
        _connection: iroh::endpoint::Connection,
    ) -> Result<(),AcceptError> {
        todo!()
    }
}