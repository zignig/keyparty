use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
// Actor and support for the signing sequence
use frost_ed25519 as frost;
use iroh::PublicKey;
use n0_error::Result;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{info, warn};

use super::{SigEvents, SigningMessage};

pub enum Steps {
    preparty,
    init,
    quorum,
    consensus,
}

#[derive(Debug)]
pub struct SigningSequence {
    transact: i64,
    state: SigningMessage,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<SigningMessage>,
    peers: BTreeSet<PublicKey>,
    online_peers: BTreeSet<PublicKey>,
    // Round 1
    nonce: Option<frost::round1::SigningNonces>,
    round1_commitments: Option<BTreeMap<PublicKey, frost::round1::SigningCommitments>>,
    message: Option<Bytes>,
}

impl SigningSequence {
    pub fn new(
        message: Option<Bytes>,
        outgoing: Sender<SigningMessage>,
        incoming: Receiver<SigEvents>,
        peers_vec: Vec<PublicKey>,
    ) -> Self {
        let transact = chrono::Utc::now()
            .timestamp_nanos_opt()
            .expect("time does not exist");
        let mut peer_set: BTreeSet<PublicKey> = Default::default();
        for peer in peers_vec.iter() {
            peer_set.insert(*peer);
        }
        Self {
            transact,
            state: SigningMessage::Init,
            incoming,
            outgoing,
            peers: peer_set,
            online_peers: Default::default(),
            nonce: None,
            round1_commitments: Default::default(),
            message,
        }
    }


    // Need a diagram of the signing flow
    async fn handle_event(&mut self, event: SigEvents) -> Result<()> {
        // NEEDS a global timeout.
        // Match for state machine
        match &self.state {
            SigningMessage::Init => {
                // Collect the IDs,
                self.online_peers.insert(event.id);
                warn!("{:#?}", self.online_peers);
                if self.peers.eq(&self.online_peers) {
                    self.state = SigningMessage::Hello;
                }
            }
            SigningMessage::Hello => {
                info!("MODE HELLO");
                let _ = self.outgoing.send(SigningMessage::Waves).await;
                self.state = SigningMessage::Waves;
            }
            SigningMessage::Waves => {
                info!("MODE WAVES");
            },
            SigningMessage::Start { .. } => {},
            SigningMessage::Round1 => todo!(),
            SigningMessage::Round2 => todo!(),
            SigningMessage::Collect => todo!(),
            SigningMessage::Compare => todo!(),
        }
        Ok(())
    }
}

pub async fn run(mut s: SigningSequence) -> Result<()> {
    loop {
        while let Some(item) = s.incoming.recv().await {
            // info!("incoming in signer {:?}", item);
            s.handle_event(item).await?
        }
    }
}
