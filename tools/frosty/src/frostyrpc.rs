pub use self::frosted::ALPN;
pub use self::frosted::{FrostyClient, FrostyServer,ProcessSteps};
/// Base on irpc-iroh auth example

mod frosted {
    use tokio::task;
    use tracing::{error, warn};

    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
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
    
    // Enum for the signing process 

    pub enum ProcessSteps { 
        Init,
        CreateMesh,
    }

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

    // Add in all the sections for the  tranport
    // these are all arced so they can be shared
    #[derive(Debug, Clone)]
    pub struct FrostyServer {
        max_peers: usize,
        peers: Arc<Mutex<BTreeMap<EndpointId, String>>>,
        peer_count: Arc<AtomicUsize>,
        counter: Arc<AtomicUsize>,
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
                            let peer_count = self.peer_count.fetch_add(1, Ordering::SeqCst);
                            if peer_count == self.max_peers {
                                error!("MAX CLIENTS REACHED");
                                // conn.close(1u32.into(), b"max_peers");
                                // break;
                            }
                            authed = true;
                            self.peers
                                .lock()
                                .unwrap()
                                .insert(conn.remote_id().into(), "fren".to_string());
                            warn!("auth succeced for {:?}", conn.remote_id());
                            // warn!("{:?}", &self.peers);
                            tx.send(Ok(())).await.ok();
                        }
                    }
                    msg => {
                        if !authed {
                            conn.close(1u32.into(), b"unauthed , try again");
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
        // pub const ALPN: &[u8] = ALPN;

        // Make a new frosty server
        pub fn new(auth_token: String,max_peers: usize) -> Self {
            Self {
                max_peers: max_peers,
                peers: Default::default(),
                peer_count: Arc::new(AtomicUsize::new(0)),
                counter: Arc::new(AtomicUsize::new(0)),
                auth_token,
            }
        }

        // Runner for local access
        // This is for the endpoint that is hosting the key party.
        async fn run(self, mut rx: tokio::sync::mpsc::Receiver<FrostyMessage>) {
            while let Some(msg) = rx.recv().await {
                self.handle_authenticated(msg).await;
            }
        }

        pub fn local(self) -> FrostyClient {
            // make a channel
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            task::spawn(self.run(rx));
            FrostyClient {
                is_local: true,
                inner: Client::local(tx),
            }
        }

        // Handle mesasges that have
        async fn handle_authenticated(&self, msg: FrostyMessage) {
            match msg {
                FrostyMessage::Auth(msg) => {
                    let WithChannels { tx, .. } = msg;
                    tx.send(Ok(())).await.ok();
                }
                FrostyMessage::Peers(peers) => {
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
                }
                FrostyMessage::Boop(boop) => {
                    let WithChannels { tx, .. } = boop;
                    let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                    tx.send(counter).await.ok();
                }
            }
        }
    }

    #[derive(Debug,Clone)]
    pub struct FrostyClient {
        is_local : bool,
        inner: Client<FrostyProtocol>,
    }

    impl FrostyClient {
        pub const ALPN: &[u8] = ALPN;

        // Remote
        pub fn connect(endpoint: Endpoint, addr: impl Into<iroh::EndpointAddr>) -> FrostyClient {
            let conn = IrohLazyRemoteConnection::new(endpoint, addr.into(), Self::ALPN.to_vec());
            FrostyClient {
                is_local: false,
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

        pub fn local(&self) -> bool { 
            self.is_local
        }
    }
}
