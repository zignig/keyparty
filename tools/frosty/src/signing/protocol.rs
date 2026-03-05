use std::collections::{BTreeMap, BTreeSet};

// Actor and support for the signing sequence
// use frost_ed25519 as frost;
use iroh::PublicKey;
use n0_error::AnyError;
use n0_error::Result;
use n0_future::FuturesUnordered;
use n0_future::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info, warn};

use crate::config::Config;
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
}

impl QuorumWatcher {
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
        }
    }

    // Need a diagram of the signing flow
    async fn handle_event(&mut self, event: SigEvents) -> Result<()> {
        // NEEDS a global timeout.
        // Match for state machine
        debug!("Event: {:#?}", event);
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
                // wave to everyone.
                // let _ = self.outgoing.send(SigningMessage::Waves).await;
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
                // info!("event : {:#?}", event);
                debug!("transactions : {:?}", self.transactions);
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
                            ).await;
                            self.tasks.push(Box::pin(s.run()));
                            self.transactions.insert(transaction_id, tx);
                            let _ = self
                                .outgoing
                                .send(SigningMessage::Start {
                                    transaction_id,
                                    message,
                                })
                                .await;
                        }
                    }
                    SigningMessage::Round1 { transaction_id } => {
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

    pub async fn route(&mut self, transaction_id: i64, event: SigEvents) -> Result<(),AnyError> {
        if let Some(tx) = self.transactions.get(&transaction_id) {
            tx.send(event).await.expect("bad routing");
        }
        Ok(())
    }
    pub async fn run(mut self) -> Result<()> {
        let _ = self.outgoing.send(SigningMessage::Hello).await;
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
