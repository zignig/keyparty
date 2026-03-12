pub use self::frosted::ALPN;
pub use self::frosted::{FrostyClient, FrostyServer, ProcessSteps};
/// Base on irpc-iroh auth example
/// https://github.com/n0-computer/irpc/blob/main/irpc-iroh/examples/auth.rs

mod frosted {
    use tokio::task;
    use tracing::{debug, error, info, warn};

    use std::{
        collections::{BTreeMap},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use anyhow::Result;

    // Key Package imports
    use frost_ed25519::keys::dkg::round2::Package as R2Package;
    use frost_ed25519::{ keys::dkg::round1::Package as R1package};

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
        Secondaries,
        Part1Send,
        Part1Fetch,
        Part1Check,
        Part2Build,
        Part2Send,
        Part2Fetch,
        Part3Build,
        Finish,
    }

    pub const ALPN: &[u8] = b"frosty-api/0";

    // Irpc structs
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
        pack: R1package,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Part1Count;

    #[derive(Debug, Serialize, Deserialize)]
    struct Part1Fetch;

    #[derive(Debug, Serialize, Deserialize)]
    struct Part2Send {
        pack: R2Package,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Part2Count;

    #[derive(Debug, Serialize, Deserialize)]
    struct Part2Fetch;

    #[derive(Debug, Serialize, Deserialize)]
    struct Finish;

    #[derive(Debug, Serialize, Deserialize)]
    struct Ident;

    // Use the macro to generate both the messages and the protocol
    // plus implement Channels for each type
    #[rpc_requests(message = FrostyMessage)]
    #[derive(Serialize, Deserialize, Debug)]
    enum FrostyProtocol {
        // Inital Auth
        #[rpc(tx=oneshot::Sender<Result<(), String>>)]
        Auth(Auth),

        // Send a list of peers
        #[rpc(tx=mpsc::Sender<PublicKey>)]
        Peers(Peers),

        // Send the current peer count here
        #[rpc(tx=oneshot::Sender<usize>)]
        PeerCount(PeerCount),

        // Ping Stuff for testing
        #[rpc(tx=oneshot::Sender<usize>)]
        Boop(Boop),

        // Send part 1 of the key build out
        #[rpc(tx=oneshot::Sender<()>)]
        Part1Send(Part1Send),

        // Show the count of part 1 here
        #[rpc(tx=oneshot::Sender<usize>)]
        Part1Count(Part1Count),

        // Fetch all the part 1 sections
        #[rpc(tx=mpsc::Sender<(PublicKey,R1package)>)]
        Part1Fetch(Part1Fetch),

        // Send the part 2 data
        #[rpc(tx=oneshot::Sender<()>)]
        Part2Send(Part2Send),

        // Count the part 2 packages (local only)
        #[rpc(tx=oneshot::Sender<Result<usize,String>>)]
        Part2Count(Part2Count),

        // Fetch the part 2 pacakges (local only)
        #[rpc(tx=mpsc::Sender<Result<(PublicKey,R2Package),String>>)]
        Part2Fetch(Part2Fetch),

        // Get the ident of this node
        #[rpc(tx=oneshot::Sender<PublicKey>)]
        Ident(Ident),

        // Finish The Transaction
        #[rpc(tx=oneshot::Sender<()>)]
        Finish(Finish),
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
        new_id: PublicKey,
        // Crypto bits
        r1packages: Arc<Mutex<BTreeMap<EndpointId, R1package>>>,
        r2packages: Arc<Mutex<BTreeMap<EndpointId, R2Package>>>,
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
                                warn!("MAX CLIENTS REACHED");
                                // conn.close(1u32.into(), b"max_peers");
                                // break;
                            }
                            authed = true;
                            self.peers
                                .lock()
                                .unwrap()
                                .insert(conn.remote_id().into(), "fren".to_string());
                            debug!("auth succeced for {:?}", conn.remote_id());
                            debug!("{:?}", &self.peers);
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
        pub fn new(
            auth_token: String,
            max_peers: usize,
            my_id: PublicKey,
            new_id : PublicKey,
        ) -> Self {
            let s = Self {
                max_peers: max_peers,
                peers: Default::default(),
                peer_count: Arc::new(AtomicUsize::new(0)),
                counter: Arc::new(AtomicUsize::new(0)),
                auth_token,
                my_id,
                new_id,
                r1packages: Default::default(),
                r2packages: Default::default(),
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

        // access for me.
        pub fn local(self) -> FrostyClient {
            // make a channel
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            task::spawn(self.run(rx));
            FrostyClient {
                is_local: true,
                inner: Client::local(tx),
            }
        }

        // Handle mesasges that have been approved ( and local )
        async fn handle_authenticated(&self, msg: FrostyMessage, id: PublicKey) {
            debug!("msg_from {:?} of {:?}", id, msg);
            match msg {
                // remote clients go through the protocol handler
                // this is for the _local_ client
                FrostyMessage::Auth(msg) => {
                    let WithChannels { tx, .. } = msg;
                    tx.send(Ok(())).await.ok();
                }
                // get the list of peers
                FrostyMessage::Peers(peers) => {
                    let WithChannels { tx, .. } = peers;
                    let peer_list = {
                        let state = self.peers.lock().unwrap();
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
                //  how many peers do I hove , when this is max ; continue
                FrostyMessage::PeerCount(peer_count) => {
                    let WithChannels { tx, .. } = peer_count;
                    let count = self.peers.lock().unwrap().len();
                    tx.send(count).await.ok();
                }

                // Connectivity testing
                FrostyMessage::Boop(boop) => {
                    let WithChannels { tx, .. } = boop;
                    let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                    tx.send(counter).await.ok();
                }

                FrostyMessage::Part1Send(part1) => {
                    let WithChannels { inner, tx, .. } = part1;
                    debug!("part 1 package from {:?} -- {:?}", id, inner.pack);
                    self.r1packages.lock().unwrap().insert(id, inner.pack);
                    tx.send(()).await.ok();
                }
                FrostyMessage::Part1Count(count) => {
                    let WithChannels { tx, .. } = count;
                    let len = self.r1packages.lock().unwrap().len();
                    tx.send(len).await.ok();
                }
                FrostyMessage::Part1Fetch(part1) => {
                    let WithChannels { tx, .. } = part1;
                    let pack1_list: Vec<_> = self
                        .r1packages
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(id, pack)| (id.clone(), pack.clone()))
                        .collect();
                    for value in pack1_list {
                        if tx.send(value).await.is_err() {
                            break;
                        }
                    }
                }

                FrostyMessage::Part2Send(pack) => {
                    let WithChannels { inner, tx, .. } = pack;
                    debug!("part 2 package arrives {:?}", inner.pack);
                    self.r2packages.lock().unwrap().insert(id, inner.pack);
                    tx.send(()).await.ok();
                }

                // this is RPC but only accessed from the local
                // second round packs are sensitive
                FrostyMessage::Part2Count(count) => {
                    let WithChannels { tx, .. } = count;
                    if id != self.my_id {
                        error!("can't access remotely");
                        tx.send(Err("can't".into())).await.expect("Broken");
                        return;
                    }
                    let len = self.r2packages.lock().unwrap().len();
                    tx.send(Ok(len)).await.ok();
                }

                FrostyMessage::Part2Fetch(pack) => {
                    let WithChannels { tx, .. } = pack;
                    if id != self.my_id {
                        error!("can't access remotely");
                        tx.send(Err("can't".into())).await.expect("Broken");
                    }

                    let pack2_list: Vec<_> = self
                        .r2packages
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(id, pack)| (id.clone(), pack.clone()))
                        .collect();
                    for value in pack2_list {
                        if tx.send(Ok(value)).await.is_err() {
                            break;
                        }
                    }
                }

                // Send the new ID to friends
                FrostyMessage::Ident(tx) => {
                    let WithChannels { tx, .. } = tx;
                    tx.send(self.new_id).await.expect("bad ident");
                }
                
                FrostyMessage::Finish(fin) => {
                    warn!("Finishing Transaction");
                    let WithChannels { tx, .. } = fin;
                    tx.send(()).await.expect("finish failed")
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

        pub async fn round1(&self, pack1: R1package) -> Result<()> {
            self.inner
                .rpc(Part1Send { pack: pack1 })
                .await
                .expect("part1 fail");
            Ok(())
        }

        pub async fn round1_count(&self) -> Result<usize, irpc::Error> {
            self.inner.rpc(Part1Count {}).await
        }

        pub async fn round1_fetch(
            &self,
        ) -> Result<mpsc::Receiver<(PublicKey, R1package)>, irpc::Error> {
            self.inner.server_streaming(Part1Fetch {}, 10).await
        }

        pub async fn round2_count(&self) -> Result<usize, String> {
            self.inner
                .rpc(Part2Count {})
                .await
                .expect("round2 count broken")
        }

        pub async fn round2_fetch(
            &self,
        ) -> Result<mpsc::Receiver<Result<(PublicKey, R2Package), String>>, irpc::Error> {
            self.inner.server_streaming(Part2Fetch {}, 10).await
        }

        pub async fn round2(&self, pack2: R2Package) -> Result<()> {
            self.inner
                .rpc(Part2Send { pack: pack2 })
                .await
                .expect("part2 fail");
            Ok(())
        }

        pub async fn count(&self) -> Result<usize, irpc::Error> {
            self.inner.rpc(PeerCount {}).await
        }

        #[allow(unused)]
        pub async fn boop(&self) -> Result<usize, irpc::Error> {
            self.inner.rpc(Boop {}).await
        }

        pub async fn ident(&self) -> Result<PublicKey, irpc::Error> {
            self.inner.rpc(Ident {}).await
        }

        pub async fn finish(&self) -> Result<(), irpc::Error> {
            self.inner.rpc(Finish {}).await
        }

        pub fn local(&self) -> bool {
            self.is_local
        }
    }
}
