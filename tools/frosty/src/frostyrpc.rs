pub use self::frosted::ALPN;
pub use self::frosted::{FrostyClient, FrostyServer, ProcessSteps};
/// Base on irpc-iroh auth example
/// https://github.com/n0-computer/irpc/blob/main/irpc-iroh/examples/auth.rs

mod frosted {
    use tokio::task;
    use tracing::{error, info, warn};

    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use anyhow::Result;

    // Key Package imports
    use frost_ed25519::keys::dkg::round1::Package as r1package;

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
        Part1Send,
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

    #[derive(Debug, Serialize, Deserialize)]
    struct Part1Send { 
        pack: r1package
    }



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
        #[rpc(tx=oneshot::Sender<()>)]
        Part1Send(Part1Send),
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
        my_id: PublicKey,
        // Crypto bits
        r1packages: Arc<Mutex<BTreeMap<EndpointId,r1package>>>,
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
                            self.handle_authenticated(msg, conn.remote_id()).await;
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
        // Make a new frosty server
        pub fn new(auth_token: String, max_peers: usize, my_id: PublicKey) -> Self {
            let s = Self {
                max_peers: max_peers,
                peers: Default::default(),
                peer_count: Arc::new(AtomicUsize::new(0)),
                counter: Arc::new(AtomicUsize::new(0)),
                auth_token,
                my_id: my_id,
                r1packages: Default::default(),
            };
            s.peers.lock().unwrap().insert(my_id, "myself".to_string());
            s
        }

        // Runner for local access
        // This is for the endpoint that is hosting the key party.
        async fn run(self, mut rx: tokio::sync::mpsc::Receiver<FrostyMessage>) {
            while let Some(msg) = rx.recv().await {
                self.handle_authenticated(msg, self.my_id).await;
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
        async fn handle_authenticated(&self, msg: FrostyMessage, id: PublicKey) {
            // info!("msg_from {:?} of {:?}",id,msg);
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
                FrostyMessage::Part1Send(part1) => {
                    let WithChannels { inner, tx,  .. } = part1;
                    info!("part 1 package from {:?} -- {:?}", id,inner.pack);
                    self.r1packages.lock().unwrap().insert(id,inner.pack);
                    tx.send(()).await.ok();
                }
                
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct FrostyClient {
        is_local: bool,
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

        pub async fn round1(&self,pack1: r1package) -> Result<()> { 
            self.inner.rpc(Part1Send{ pack: pack1 }).await.expect("bad r1 pack");
            Ok(())
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
