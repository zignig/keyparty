// This is the task that performs the actual signature

use bytes::Bytes;
use frost::{
    Identifier, SigningPackage,
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
};
use frost_ed25519 as frost;
use iroh::PublicKey;
use n0_error::{AnyError, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, warn};

// s

use crate::signing::{GossipMessage, SigEvent, TransMessage};

// Simple verstion of the state (actual data is contained in messges)
#[derive(Debug)]
enum SState {
    Start,
    Check,
    Round1,
    Round2,
    Finished,
    Fail,
}

// TODO missing fields

// online nodes
// round1/2 pacakges
// nonces
// just comms for now
pub struct SignerTask {
    my_id: PublicKey,
    transaction_id: i64,
    message: Bytes,
    state: SState,
    incoming: Receiver<(PublicKey, TransMessage)>,
    outgoing: Sender<GossipMessage>,
    nodes: BTreeSet<PublicKey>,
    identifier_map: BTreeMap<PublicKey, Identifier>,

    // Signing Bits
    key_package: Option<KeyPackage>,
    // round 1
    nonce: Option<SigningNonces>,
    commitments: BTreeMap<PublicKey, SigningCommitments>,
    // round 2
    signing_package: BTreeMap<PublicKey, SigningPackage>,
}

impl SignerTask {
    const TIME_OUT: Duration = Duration::from_secs(1);

    // Make a new one
    pub async fn new(
        my_id: PublicKey,
        transaction_id: i64,
        message: Bytes,
        outgoing: Sender<GossipMessage>,
        key_package: Option<KeyPackage>,
        nodes: BTreeSet<PublicKey>,
    ) -> (Sender<(PublicKey, TransMessage)>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel::<(PublicKey, TransMessage)>(5);

        let mut id_map: BTreeMap<PublicKey, Identifier> = Default::default();
        for id in nodes.iter() {
            id_map.insert(
                *id,
                Identifier::derive(id.as_bytes()).expect("bad identifier"),
            );
        }
        debug!("nodes = {:#?}", &nodes);
        debug!("id_map = {:#?}", id_map);

        let sel = Self {
            my_id,
            transaction_id,
            message: message.clone(),
            state: SState::Start,
            incoming: rx,
            outgoing,
            nodes,
            identifier_map: id_map,
            key_package,
            nonce: None,
            commitments: Default::default(),
            signing_package: Default::default(),
        };
        (tx, sel)
    }

    // Send a message out the the gossip network
    async fn send_out(&self, sigevent: SigEvent) -> Result<()> {
        let gmessage = GossipMessage::Event {
            message: TransMessage {
                transaction_id: self.transaction_id,
                event: sigevent,
            },
        };
        self.outgoing.send(gmessage).await.expect("bad out");
        Ok(())
    }

    async fn handle_event(&mut self, event: (PublicKey, TransMessage)) -> Result<(), AnyError> {
        debug!("{:?} ==> {:#?}", &self.state, &event);
        let (id, mess) = event;
        let mut rng = frost_ed25519::rand_core::OsRng;
        // TODO fix this to track both state and message switch.
        // self.send_out(SigEvent::Compare).await?;
        match &mess.event {
            SigEvent::Start { sig_message } => match &self.key_package {
                Some(key_package) => {
                    let (nonce, commitment) =
                        frost::round1::commit(key_package.signing_share(), &mut rng);
                    self.nonce = Some(nonce);
                    self.commitments.insert(self.my_id, commitment);
                    self.send_out(SigEvent::Round1 { commitment }).await?;
                    self.state = SState::Round1;
                }
                None => {
                    self.state = SState::Fail;
                }
            },
            SigEvent::Round1 { commitment } => {
                self.commitments.insert(id, commitment.to_owned());
            }

            SigEvent::Round2 { package } => {
                self.signing_package.insert(id, package.clone());
            }

            SigEvent::Collect => {}
            SigEvent::Compare => {}
        };
        match self.state {
            SState::Start => {
                info!("[signer] Start");
                self.state = SState::Check;
            }
            SState::Check => {
                info!("[signer] Check");
                self.state = SState::Round1;
            }
            SState::Round1 => {
                info!("[signer] Round1");
                let ids: Vec<PublicKey> = self.commitments.keys().map(|id| id.clone()).collect();
                for id in ids.iter() {
                    info!("{:}", id.fmt_short());
                }
                if self
                    .nodes
                    .iter()
                    .all(|key| self.commitments.contains_key(key))
                {
                    warn!("GOT ALL THE COMMITMENTS");
                    // Remap to identifiers and create the signing pacakage
                    let mut id_commitments: BTreeMap<Identifier, SigningCommitments> =
                        Default::default();
                    for (key, com) in self.commitments.iter() {
                        let id = self.identifier_map.get(key).ok_or("bad ident")?;
                        id_commitments.insert(*id, *com);
                    }
                    // Create the signing pacakge
                    let mess_bytes: &[u8] = self.message.as_ref();
                    let signing_package = frost::SigningPackage::new(id_commitments, mess_bytes);
                    self.state = SState::Round2;
                    self.signing_package.insert(self.my_id,signing_package.clone());
                    self.send_out(SigEvent::Round2 {
                        package: signing_package,
                    })
                    .await?;
                }
            }
            SState::Round2 => {
                debug!("round 2 {:?}", self.commitments);
                if self
                    .nodes
                    .iter()
                    .all(|key| self.signing_package.contains_key(key))
                {
                    warn!("GOT ALL THE SIGNING PACKAGES");
                    self.state = SState::Finished;
                }
            }
            SState::Finished => {},
            SState::Fail => {
                error!("FAIL!!! on keypakage")
            }
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<i64, AnyError> {
        warn!(" Starting Signer Task {:#?}", &self.state);
        let timeout = tokio::time::sleep(SignerTask::TIME_OUT);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                Some(event)  = self.incoming.recv() => {
                    // error!("signing interior {:#?}",&event);
                    self.handle_event(event).await?;
                },
                _ = &mut timeout => {
                    warn!("timeout finished");
                    return Ok(self.transaction_id);
                },

            }
        }
    }
}
