use std::collections::{BTreeMap, BTreeSet};

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
use tracing::error;
use tracing::{debug, info, warn};

use crate::config::Config;
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
    online_peers: BTreeSet<PublicKey>,
    transactions: BTreeMap<i64, Sender<(PublicKey, TransMessage)>>,
    tasks: FuturesUnordered<n0_future::boxed::BoxFuture<Result<i64, (i64, AnyError)>>>,
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
            online_peers: Default::default(),
            transactions: Default::default(),
            tasks:
                FuturesUnordered::<n0_future::boxed::BoxFuture<Result<i64, (i64, AnyError)>>>::new(),
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
            if self.online_peers.len() <= (self.config.min()) {
                warn!("quorum lost!");
                self.state = QuorumSteps::Preparty;
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
                };
            }

            QuorumSteps::Quorum => {
                debug!("Quorum Mode");

                if self.key_package.is_none() {
                    info!("key package loaded");
                    self.key_package = Some(self.config.get_key_pacakge()?);
                };

                if self.public_package.is_none() {
                    info!("public  package loaded");
                    self.public_package = Some(self.config.get_public_package()?);
                };

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
            error!("Missign transaction {}", &event.transaction_id);
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
                // messages from the gossip network
                Some(item) = self.incoming.recv() => {
                    self.handle_event(item).await?
                }
                // Signing transactions
                val = self.tasks.next(), if !self.tasks.is_empty() => {
                    info!("task finish {:#?}",&val);
                    if let Some(val) = val {
                        match &val {
                            Ok(id) => {
                                info!("transaction {} finished",&id);
                                self.transactions.remove(id);
                            },
                            Err(e) => {
                                error!("transaction error {:?}",e);
                                self.transactions.remove(&e.0);
                            },
                        }
                    }
                }
            }
        }
    }
}
