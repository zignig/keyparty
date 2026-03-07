use std::collections::{BTreeMap, BTreeSet};

use frost_ed25519::keys::KeyPackage;
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
use crate::signing::now;
use crate::signing::signer::SignerTask;

use super::{SigEvents, SigningMessage};

#[derive(Debug)]
pub enum QuorumSteps {
    Preparty,
    Init,
    Quorum,
    Consensus,
}

#[derive(Debug)]
pub struct QuorumWatcher {
    my_id: PublicKey,
    config: Config,
    state: QuorumSteps,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<SigningMessage>,
    peers: BTreeSet<PublicKey>,
    online_peers: BTreeSet<PublicKey>,
    transactions: BTreeMap<i64, Sender<SigEvents>>,
    tasks: FuturesUnordered<n0_future::boxed::BoxFuture<Result<i64, AnyError>>>,
    key_package: Option<KeyPackage>,
}

impl QuorumWatcher {
    // Make a new one.
    pub fn new(
        my_id: PublicKey,
        config: Config,
        outgoing: Sender<SigningMessage>,
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
            state: QuorumSteps::Preparty,
            incoming,
            outgoing,
            peers: peer_set,
            online_peers: Default::default(),
            transactions: Default::default(),
            tasks: FuturesUnordered::<n0_future::boxed::BoxFuture<Result<i64, AnyError>>>::new(),
            key_package: None,
        }
    }

    // Need a diagram of the signing flow
    async fn handle_event(&mut self, event: SigEvents) -> Result<()> {
        // Match for state machine
        // Check for downed peers
        if event.message == SigningMessage::PeerDown {
            warn!("node down !!! : {:}", &event.id.fmt_short());
            self.online_peers.remove(&event.id);
            warn!("{:#?}", &self.online_peers);
            if self.online_peers.len() <= (self.config.min() - 1) {
                warn!("quorum lost!");
                self.state = QuorumSteps::Preparty;
                return Ok(());
            }
        }

        match &self.state {
            QuorumSteps::Preparty => {
                warn!("PreParty");
                // Collect the IDs,
                println!("{:?}", &event);
                if self.peers.contains(&event.id) && !self.online_peers.contains(&event.id) {
                    info!("adding peer {:?}", &event.id);
                    self.online_peers.insert(event.id);
                }
                warn!("peers {:#?}", self.online_peers.len());
                if self.online_peers.len() == (self.config.min() - 1) {
                    self.state = QuorumSteps::Init;
                }
                // if self.peers.eq(&self.online_peers) {
                //     self.state = QuorumSteps::Consensus;
                // }
            }
            QuorumSteps::Init => {
                warn!("Init Mode");
                let _ = self.outgoing.send(SigningMessage::Init).await;
                self.state = QuorumSteps::Quorum;
            }
            QuorumSteps::Quorum => {
                debug!("Quorum Mode");

                if self.key_package.is_none() {
                    info!("key package loaded");
                    self.key_package = Some(self.config.get_key_pacakge()?);
                };

                debug!("transactions : {:?}", self.transactions.keys());
                info!("event: {:#?}", &event.message);
                match event.message {
                    SigningMessage::Start {
                        transaction_id,
                        message,
                    } => {
                        // TODO fix up the logic here
                        // put incoming , map and route the
                        if !self.transactions.contains_key(&transaction_id) {
                            warn!("create the task");

                            let (tx, s) = SignerTask::new(
                                self.my_id,
                                transaction_id,
                                message.clone(),
                                self.outgoing.clone(),
                                self.key_package.clone(),
                            )
                            .await;
                            // push the start into the new signer
                            let _ = tx
                                .send(SigEvents {
                                    id: self.my_id,
                                    message: SigningMessage::Start {
                                        transaction_id,
                                        message,
                                    },
                                })
                                .await;
                            self.tasks.push(Box::pin(s.run()));
                            self.transactions.insert(transaction_id, tx);
                        } else {
                            error!("Double start {}", transaction_id);
                        }
                    }
                    SigningMessage::Round1 { transaction_id } => {
                        warn!("round 1 {}", transaction_id);
                        self.route(transaction_id.clone(), event.clone()).await?
                    }
                    SigningMessage::Round2 { transaction_id } => todo!(),
                    SigningMessage::Collect { transaction_id } => todo!(),
                    SigningMessage::Compare { transaction_id } => todo!(),
                    _ => {}
                }
            }
            QuorumSteps::Consensus => {}
        }
        Ok(())
    }

    // take a message and route it to a running transaction.
    pub async fn route(&mut self, transaction_id: i64, event: SigEvents) -> Result<(), AnyError> {
        if let Some(tx) = self.transactions.get(&transaction_id) {
            tx.send(event).await.expect("bad routing");
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        let _ = self
            .outgoing
            .send(SigningMessage::Hello { timestamp: now() })
            .await;
        loop {
            tokio::select! {
                Some(item) = self.incoming.recv() => {
                    self.handle_event(item).await?
                }
                val = self.tasks.next(), if !self.tasks.is_empty() => {
                    info!("task finish {:#?}",&val);
                    if let Some(val) = val {
                        let val = val?;
                        self.transactions.remove(&val);
                    }
                }
            }
        }
    }
}
