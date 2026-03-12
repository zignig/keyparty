// Authentication hook for the signer
// only accept from known key friends

use iroh::{
    EndpointAddr, PublicKey,
    endpoint::{AfterHandshakeOutcome, BeforeConnectOutcome, ConnectionInfo, EndpointHooks},
};
use tracing::{debug, warn};

#[derive(Debug)]
pub struct Authenticator {
    peers: Vec<PublicKey>,
}

impl Authenticator {
    pub fn new(peers: Vec<PublicKey>) -> Self {
        Self { peers }
    }
}

impl EndpointHooks for Authenticator {
    async fn before_connect(
        &self,
        remote_addr: &EndpointAddr,
        alpn: &[u8],
    ) -> BeforeConnectOutcome {
        debug!(?remote_addr, ?alpn, "attempting to connect");
        if self.peers.contains(&remote_addr.id) {
            return BeforeConnectOutcome::Accept;
        }
        warn!(?remote_addr, ?alpn, "reject connection");
        BeforeConnectOutcome::Reject
    }

    async fn after_handshake(&self, conn: &ConnectionInfo) -> AfterHandshakeOutcome {
        // This tells us whether `conn` is an incoming or outgoing connection.
        let side: iroh::endpoint::Side = conn.side();
        let remote = conn.remote_id().fmt_short();
        if self.peers.contains(&conn.remote_id()) {
            debug!(%remote, alpn=?conn.alpn(), ?side, "is peers");
            return AfterHandshakeOutcome::Accept;
        }
        warn!(%remote, alpn=?conn.alpn(), ?side, "reject connection");
        AfterHandshakeOutcome::Reject {
            error_code: 403u32.into(),
            reason: b"Die scum".to_vec(),
        }
    }
}
