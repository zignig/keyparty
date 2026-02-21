pub use self::frosted::ALPN;
pub use self::frosted::{FrostyClient, FrostyServer};
/// Base on irpc-iroh auth example
///
use anyhow::Result;
use iroh::endpoint::Endpoint;
use iroh::protocol::Router;
use tracing::warn;

mod frosted {
    use tracing::warn;

    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };

    use anyhow::Result;
    use iroh::{
        Endpoint, EndpointId, PublicKey,
        endpoint::Connection,
        protocol::{AcceptError, ProtocolHandler},
    };
    use irpc::{
        Client, WithChannels,
        channel::{mpsc, oneshot},
        rpc_requests,
    };
    // Import the macro
    use irpc_iroh::{IrohLazyRemoteConnection, read_request};
    use serde::{Deserialize, Serialize};
    use tracing::info;

    pub const ALPN: &[u8] = b"frosty-api/0";

    #[derive(Debug, Serialize, Deserialize)]
    struct Auth {
        token: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Peers;

    #[derive(Debug, Serialize, Deserialize)]
    struct PeerCount;

    #[derive(Debug, Serialize, Deserialize)]
    struct Boop;

    
    // Use the macro to generate both the StorageProtocol and StorageMessage enums
    // plus implement Channels for each type
    #[rpc_requests(message = FrostyMessage)]
    #[derive(Serialize, Deserialize, Debug)]
    enum FrostyProtocol {
        #[rpc(tx=oneshot::Sender<Result<(), String>>)]
        Auth(Auth),
        #[rpc(tx=mpsc::Sender<PublicKey>)]
        Peers(Peers),
        #[rpc(tx=oneshot::Sender<usize>)]
        PeerCount(PeerCount),
        #[rpc(tx=oneshot::Sender<usize>)]
        Boop(Boop),
    }

    #[derive(Debug, Clone)]
    pub struct FrostyServer {
        peers: Arc<Mutex<BTreeMap<EndpointId, String>>>,
        auth_token: String,
    }

    impl ProtocolHandler for FrostyServer {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let mut authed = false;
            while let Some(msg) = read_request::<FrostyProtocol>(&conn).await? {
                match msg {
                    FrostyMessage::Auth(msg) => {
                        let WithChannels { inner, tx, .. } = msg;
                        if authed {
                            conn.close(1u32.into(), b"invalid message");
                            break;
                        } else if inner.token != self.auth_token {
                            conn.close(1u32.into(), b"permission denied");
                            break;
                        } else {
                            authed = true;
                            self.peers
                                .lock()
                                .unwrap()
                                .insert(conn.remote_id().into(), "fren".to_string());
                            warn!("{:?}", &self.peers);
                            tx.send(Ok(())).await.ok();
                        }
                    }
                    msg => {
                        if !authed {
                            conn.close(1u32.into(), b"permission denied");
                            break;
                        } else {
                            self.handle_authenticated(msg).await;
                        }
                    }
                }
            }
            warn!("irpc exit");
            conn.closed().await;
            Ok(())
        }
    }

    impl FrostyServer {
        pub const ALPN: &[u8] = ALPN;

        pub fn new(auth_token: String, endp: EndpointId) -> Self {
            let s = Self {
                peers: Default::default(),
                auth_token,
            };
            s.peers.lock().unwrap().insert(endp, "myself".to_string());
            s
        }

        async fn handle_authenticated(&self, msg: FrostyMessage) {
            match msg {
                FrostyMessage::Auth(_) => unreachable!("handled in ProtocolHandler::accept"),
                FrostyMessage::Peers(peers) => {
                    info!("peers {:?}", peers);
                    let WithChannels { tx, .. } = peers;
                    let peer_list = {
                        let state = self.peers.lock().unwrap();
                        // TODO: use async lock to not clone here.
                        let values: Vec<_> =
                            state.iter().map(|(key, _value)| key.clone()).collect();
                        values
                    };
                    for value in peer_list {
                        if tx.send(value.clone()).await.is_err() {
                            break;
                        }
                    }
                }
                FrostyMessage::PeerCount(peer_count) => {
                    let WithChannels { tx, .. } = peer_count;
                    let count = self.peers.lock().unwrap().len();
                    tx.send(count).await.ok();
                },
                FrostyMessage::Boop(boop) => { 
                    let WithChannels {tx , .. } = boop;
                    tx.send(1).await.ok();
                }
            }
        }
    }

    #[derive(Debug)]
    pub struct FrostyClient {
        inner: Client<FrostyProtocol>,
    }

    impl FrostyClient {
        pub const ALPN: &[u8] = ALPN;

        pub fn connect(endpoint: Endpoint, addr: impl Into<iroh::EndpointAddr>) -> FrostyClient {
            let conn = IrohLazyRemoteConnection::new(endpoint, addr.into(), Self::ALPN.to_vec());
            FrostyClient {
                inner: Client::boxed(conn),
            }
        }

        pub async fn auth(&self, token: &str) -> Result<(), anyhow::Error> {
            self.inner
                .rpc(Auth {
                    token: token.to_string(),
                })
                .await?
                .map_err(|err| anyhow::anyhow!(err))
        }

        pub async fn peers(&self) -> Result<mpsc::Receiver<PublicKey>, irpc::Error> {
            self.inner.server_streaming(Peers, 10).await
        }

        pub async fn count(&self) -> Result<usize, irpc::Error> {
            self.inner.rpc(PeerCount {}).await
        }
        
        pub async fn boop(&self) -> Result<usize, irpc::Error> {
            self.inner.rpc(Boop {}).await
        }
    }
}
