// This is the task that performs the actual signature

use bytes::Bytes;
use frost::{
    Identifier, SigningPackage,
    keys::KeyPackage,
    round1::{SigningCommitments, SigningNonces},
};
use frost_ed25519::{self as frost, keys::PublicKeyPackage, round2::SignatureShare};
use iroh::PublicKey;
use n0_error::{AnyError, Result, anyerr};
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
pub struct SignerTask {
    my_id: PublicKey,
    transaction_id: i64,
    message: Bytes,
    state: SState,
    incoming: Receiver<(PublicKey, TransMessage)>,
    outgoing: Sender<GossipMessage>,
    nodes: BTreeSet<PublicKey>,

    id_map: BTreeMap<PublicKey, Identifier>,

    // Signing Bits
    key_package: Option<KeyPackage>,
    public_package: Option<PublicKeyPackage>,
    // round 1
    nonce: Option<SigningNonces>,
    commitments: BTreeMap<PublicKey, SigningCommitments>,
    // round 2
    signing_package: Option<SigningPackage>,
    signing_shares: BTreeMap<PublicKey, SignatureShare>,
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
        public_package: Option<PublicKeyPackage>,
        nodes: BTreeSet<PublicKey>,
    ) -> (Sender<(PublicKey, TransMessage)>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel::<(PublicKey, TransMessage)>(5);

        // error!("nodes = {:#?}", &nodes);

        let mut id_map: BTreeMap<PublicKey, Identifier> = BTreeMap::new();
        for node in nodes.iter() {
            id_map.insert(*node, Identifier::derive(node.as_bytes()).expect("bork"));
        }

        // error!("{:?}", &id_map);

        let sel = Self {
            my_id,
            transaction_id,
            message: message.clone(),
            state: SState::Start,
            incoming: rx,
            outgoing,
            nodes,
            key_package,
            public_package,
            nonce: None,
            commitments: Default::default(),
            signing_package: None,
            signing_shares: Default::default(),
            id_map,
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

    async fn handle_event(&mut self, event: (PublicKey, TransMessage)) -> Result<bool, AnyError> {
        debug!("{:?} ==> {:#?}", &self.state, &event);
        let (id, mess) = event;
        let mut rng = frost_ed25519::rand_core::OsRng;

        // TODO finish the signing sequence
        // match incoming events
        match &mess.event {
            SigEvent::Start { .. } => {
                info!("{} - {:}", self.transaction_id, self.my_id.fmt_short());
                match &self.key_package {
                    Some(key_package) => {
                        let (nonce, commitment) =
                            frost::round1::commit(key_package.signing_share(), &mut rng);
                        self.nonce = Some(nonce);
                        self.commitments.insert(self.my_id, commitment);
                        // error!("signer , {:#?}",&commitment);
                        self.send_out(SigEvent::Round1 { commitment }).await?;
                        self.state = SState::Round1;
                    }
                    None => {
                        self.state = SState::Fail;
                    }
                }
            }
            // TODO limit these to known ids
            SigEvent::Round1 { commitment } => {
                self.commitments.insert(id, commitment.to_owned());
            }

            // TODO limit these to known ids
            SigEvent::Round2 { share } => {
                self.signing_shares.insert(id, share.clone());
            }

            SigEvent::Collect => {}
            SigEvent::Compare => {}
        };

        //
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
                // do I have all the commitments ?
                if self
                    .nodes
                    .iter()
                    .all(|key| self.commitments.contains_key(key))
                {
                    warn!("All commitments");
                    // Remap to identifiers and create the signing pacakage
                    let mut id_commitments: BTreeMap<Identifier, SigningCommitments> =
                        Default::default();
                    // TODO , there are some edge cases on new nodes
                    for (key, com) in self.commitments.iter() {
                        let iden = self.id_map.get(key).ok_or("bad id")?;
                        // error!("map  : {:} --> {:?}", key.fmt_short(), iden);
                        id_commitments.insert(*iden, *com);
                    }

                    // Create the signing package
                    let mess_bytes: &[u8] = self.message.as_ref();
                    let signing_package = frost::SigningPackage::new(id_commitments, mess_bytes);
                    self.signing_package = Some(signing_package.clone());

                    // Make and distrubute shares
                    let nonce = self.nonce.clone().ok_or("missing nonce")?;
                    let key_package = self.key_package.clone().ok_or("missing keypackage")?;
                    
                    let signature_share =
                        frost::round2::sign(&signing_package, &nonce, &key_package);
                    match signature_share {
                        Ok(signature_share) => {
                            self.signing_shares.insert(self.my_id, signature_share);
                            self.send_out(SigEvent::Round2 {
                                share: signature_share,
                            })
                            .await?;
                        }
                        Err(e) => error!("sig share {:#?}", e),
                    }
                    self.state = SState::Round2;
                }
            }

            SState::Round2 => {
                info!("[signer] Round1");
                let ids: Vec<PublicKey> = self.signing_shares.keys().map(|id| id.clone()).collect();
                for id in ids.iter() {
                    info!("{:}", id.fmt_short());
                }
                if self
                    .nodes
                    .iter()
                    .all(|key| self.signing_shares.contains_key(key))
                {
                    warn!("Have all the shares");
                    // get signing package
                    let signing_package =
                        self.signing_package.clone().ok_or("missing sig pacakge")?;

                    // remap the signing shares
                    let mut sig_share: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
                    for (key, value) in self.signing_shares.iter() {
                        let id = self.id_map.get(key).ok_or("bad id")?;
                        sig_share.insert(*id, *value);
                    }

                    // get the public package
                    let public_package = self
                        .public_package
                        .clone()
                        .ok_or("missing public pacakge)")?;
                    let group_signature =
                        frost::aggregate(&signing_package, &sig_share, &public_package)
                            .expect("bad group signature");
                    error!(" WOO HOO !!! ---- {:#?}", group_signature);
                    return Ok(true);
                    // self.state = SState::Finished;
                }
            }
            SState::Finished => {}
            SState::Fail => {
                error!("FAIL!!! on keypakage");
                return Err(anyerr!("package fail"));
            }
        }
        Ok(false)
    }

    // Runner loop for the signer
    pub async fn run(mut self) -> Result<i64, (i64, AnyError)> {
        warn!(" Starting Signer Task {:#?}", &self.state);

        let timeout = tokio::time::sleep(SignerTask::TIME_OUT);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                // Incoming events for the task
                Some(event)  = self.incoming.recv() => {
                    match self.handle_event(event).await {
                        Ok(fin) => if fin { return Ok(self.transaction_id)},
                        Err(e) => error!("transaction error {} : {}",self.transaction_id,e),
                    };
                },
                // Did not complete in time
                _ = &mut timeout => {
                    error!("timeout for {}",self.transaction_id);
                    return Err((self.transaction_id,anyerr!("timeout")));
                },

            }
        }
    }
}
