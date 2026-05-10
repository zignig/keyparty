use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519::Signature;
use frost_ed25519::keys::KeyPackage;
use frost_ed25519::keys::PublicKeyPackage;
// Actor and support for the signing sequence
// use frost_ed25519 as frost;
use iroh::PublicKey;
use n0_error::AnyError;
use n0_error::Result;
use n0_future::FuturesUnordered;
use n0_future::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::error;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::service::irpc::SigStatus;
use crate::signing::SigEvent;
use crate::signing::TransMessage;
use crate::signing::now;
use crate::signing::signer::SignerTask;

use super::{GossipMessage, SigEvents};

#[derive(Debug)]
pub enum QuorumSteps {
    Init,
    Preparty,
    Quorum,
}

#[derive(Debug)]
pub struct QuorumWatcher {
    my_id: PublicKey,
    config: Config,
    state: QuorumSteps,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<GossipMessage>,
    peers: BTreeSet<PublicKey>,
    token: CancellationToken,
    online_peers: BTreeSet<PublicKey>,
    transactions: BTreeMap<i64, Sender<(PublicKey, TransMessage)>>,
    tasks: FuturesUnordered<n0_future::boxed::BoxFuture<Result<(i64, Signature), (i64, AnyError)>>>,
    key_package: Option<KeyPackage>,
    public_package: Option<PublicKeyPackage>,
}

impl QuorumWatcher {
    // Make a new one.
    pub fn new(
        my_id: PublicKey,
        config: Config,
        outgoing: Sender<GossipMessage>,
        incoming: Receiver<SigEvents>,
        peers_vec: Vec<PublicKey>,
        token: CancellationToken,
    ) -> Self {
        let mut peer_set: BTreeSet<PublicKey> = Default::default();

        for peer in peers_vec.iter() {
            peer_set.insert(*peer);
        }

        Self {
            my_id,
            config,
            state: QuorumSteps::Init,
            incoming,
            outgoing,
            peers: peer_set,
            token,
            online_peers: Default::default(),
            transactions: Default::default(),
            tasks: FuturesUnordered::<
                n0_future::boxed::BoxFuture<Result<(i64, Signature), (i64, AnyError)>>,
            >::new(),
            key_package: None,
            public_package: None,
        }
    }

    // Need a diagram of the signing flow
    async fn handle_event(&mut self, event: SigEvents) -> Result<()> {
        // Match for state machine
        if self.peers.contains(&event.id) && !self.online_peers.contains(&event.id) {
            info!("adding peer {:?}", &event.id);
            self.online_peers.insert(event.id);
        };
        // Check for downed peers

        if event.message == GossipMessage::PeerDown {
            warn!("node down !!! : {:}", &event.id.fmt_short());
            self.online_peers.remove(&event.id);
            warn!("{:#?}", &self.online_peers);
            if self.online_peers.len() < (self.config.min()) {
                warn!("quorum lost!");
                self.state = QuorumSteps::Preparty;
                // Tell the main runner that we have lost quorum
                self.outgoing.send(GossipMessage::QuorumDown).await.unwrap();
                return Ok(());
            }
        }

        if event.message == GossipMessage::PeerUp {
            // new peer , say hello
            // this helps with getting quorum
            warn!("{:#?}", &self.online_peers);
            let _ = self
                .outgoing
                .send(GossipMessage::Hello { timestamp: now() })
                .await;
        }

        match &self.state {
            QuorumSteps::Init => {
                warn!("Init Mode");
                // let _ = self.outgoing.send(GossipMessage::Init).await;
                // invite myself to the party.
                self.online_peers.insert(self.my_id);
                self.peers.insert(self.my_id);
                self.state = QuorumSteps::Preparty;
            }
            QuorumSteps::Preparty => {
                warn!("PreParty");
                // if self.peers.contains(&event.id) && !self.online_peers.contains(&event.id) {
                warn!("peers {:#?}", self.online_peers.len());
                if self.online_peers.len() >= (self.config.min()) {
                    info!("Made Quorum");
                    info!("Peers {:?}", self.online_peers);
                    self.state = QuorumSteps::Quorum;
                    // Tell the main runner that we have quorum
                    self.outgoing.send(GossipMessage::QuorumUp).await.unwrap();
                };
            }

            QuorumSteps::Quorum => {
                debug!("Quorum Mode");

                debug!("transactions : {:?}", self.transactions.keys());
                debug!("event: {:#?}", &event.message);
                match event.message {
                    GossipMessage::Hello { timestamp } => {
                        debug!("hello {}", timestamp)
                    }
                    GossipMessage::Event { message } => {
                        let transaction_id = message.transaction_id;
                        let id = event.id;
                        match &message.event {
                            SigEvent::Start { sig_message } => {
                                // load the packages.
                                if self.key_package.is_none() {
                                    info!("key package loaded");
                                    self.key_package = Some(self.config.get_key_pacakge()?);
                                };

                                if self.public_package.is_none() {
                                    info!("public  package loaded");
                                    self.public_package = Some(self.config.get_public_package()?);
                                };
                                // this starts an actor on each endpoint
                                // through redirection
                                if !self.transactions.contains_key(&transaction_id) {
                                    warn!("Create the task {}", transaction_id);
                                    // error!("{:?}",&self.online_peers);
                                    let (tx, s) = SignerTask::new(
                                        self.my_id,
                                        transaction_id,
                                        sig_message.clone(),
                                        self.outgoing.clone(),
                                        self.key_package.clone(),
                                        self.public_package.clone(),
                                        self.online_peers.clone(),
                                    )
                                    .await;
                                    // push the start into the new signer
                                    let _ = tx.send((id, message)).await;
                                    self.tasks.push(Box::pin(s.run()));
                                    self.transactions.insert(transaction_id, tx);
                                } else {
                                    error!("Double start {}", transaction_id);
                                }
                            }
                            // Route everything but the start into the actor
                            _ => {
                                self.route(id, message).await?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    // take a message and route it to a running transaction.
    pub async fn route(&mut self, id: PublicKey, event: TransMessage) -> Result<(), AnyError> {
        if let Some(tx) = self.transactions.get(&event.transaction_id) {
            tx.send((id, event)).await.expect("bad routing");
        } else {
            error!("Missing transaction {}", &event.transaction_id);
            error!("Event {:#?}",&event.event);
            // return Err(anyerr!("missing transaction"));
        }
        Ok(())
    }

    // runner for the quorum
    pub async fn run(mut self) -> Result<()> {
        // Say hello to everyone.
        let _ = self
            .outgoing
            .send(GossipMessage::Hello { timestamp: now() })
            .await;
        loop {
            tokio::select! {
                // Cancel
                _ = self.token.cancelled() => {
                    info!("Quorum runner stopped");
                    return Ok(());
                }
                // messages from the gossip network
                Some(item) = self.incoming.recv() => {
                    self.handle_event(item).await?
                }
                // Signing transactions
                Some(val) = self.tasks.next(), if !self.tasks.is_empty() => {
                    debug!("task finish {:#?}",&val);
                    match val {
                        Ok((transaction_id,signature)) => {
                            info!("transaction {} finished",&transaction_id);
                            self.transactions.remove(&transaction_id);
                            let gm = GossipMessage::SigStatus {
                                transaction_id,
                                status: SigStatus::Sig {sig: signature}
                            };
                            self.outgoing.send(gm).await.unwrap();
                        }
                        Err((transaction_id,err)) => {
                            error!("transaction {} errored ",&transaction_id);
                            error!("{:#?}",err);
                            self.transactions.remove(&transaction_id);
                            let gm = GossipMessage::SigStatus{
                                transaction_id,
                                status : SigStatus::SigError { error: err.to_string() }
                            };
                            self.outgoing.send(gm).await.unwrap();
                        }
                    }
                }
            }
        }
    }
}
