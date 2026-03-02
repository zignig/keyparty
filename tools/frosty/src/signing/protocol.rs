use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
// Actor and support for the signing sequence
// use frost_ed25519 as frost;
use iroh::PublicKey;
use n0_error::Result;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, info, warn};

use crate::config::Config;

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
    config: Config,
    state: QuorumSteps,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<SigningMessage>,
    peers: BTreeSet<PublicKey>,
    online_peers: BTreeSet<PublicKey>,
    transactions: BTreeMap<i64, PublicKey>,
    // Round 1
    // nonce: Option<frost::round1::SigningNonces>,
    // round1_commitments: Option<BTreeMap<PublicKey, frost::round1::SigningCommitments>>,
    // message: Option<Bytes>,
}

impl QuorumWatcher {
    pub fn new(
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
            config,
            state: QuorumSteps::Preparty,
            incoming,
            outgoing,
            peers: peer_set,
            online_peers: Default::default(),
            transactions: Default::default(),
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
                warn!("Quorum Mode");
                info!("event : {:#?}", event);
                info!("transactions : {:?}", self.transactions);
                match event.message {
                    SigningMessage::Start {
                        transaction_id,
                        message,
                    } => {
                        self.transactions.insert(transaction_id, event.id);
                        let _ = self
                            .outgoing
                            .send(SigningMessage::Round1 {
                                transaction_id: transaction_id,
                            })
                            .await;
                    }
                    SigningMessage::Round1 { transaction_id } => {
                        if self.transactions.contains_key(&transaction_id) {
                            warn!("have the transaction , round 1 !!!! ");
                            self.transactions.remove(&transaction_id);
                        }
                    }
                    _ => {}
                }
            }
            QuorumSteps::Consensus => {}
        }
        Ok(())
    }
}

pub async fn run(mut s: QuorumWatcher) -> Result<()> {
    let _ = s.outgoing.send(SigningMessage::Hello).await;
    loop {
        while let Some(item) = s.incoming.recv().await {
            // info!("incoming in signer {:?}", item);
            s.handle_event(item).await?
        }
    }
}
