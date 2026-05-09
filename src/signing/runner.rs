// The main runner for the signing process

use std::collections::BTreeMap;

use bytes::Bytes;
use iroh::{EndpointId, PublicKey, SecretKey};
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use n0_error::Result;
use n0_future::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    service::irpc::{Reply, ServiceMessage, SigStatus},
    signing::{GossipMessage, SigEvent, SigEvents, SignedMessage, TransMessage, now},
};

pub struct MainRunner {
    id: PublicKey,
    peers: Vec<PublicKey>,
    tx: GossipSender,
    rx: GossipReceiver,
    outgoing: Sender<SigEvents>,
    incoming: Receiver<GossipMessage>,
    service_in: Receiver<ServiceMessage>,
    secret: SecretKey,
    cancel_token: CancellationToken,
    transaction_map: BTreeMap<i64, Reply>,
    quorum: bool
}

impl MainRunner {
    pub fn new(
        id: PublicKey,
        peers: Vec<PublicKey>,
        tx: GossipSender,
        rx: GossipReceiver,
        outgoing: Sender<SigEvents>,
        incoming: Receiver<GossipMessage>,
        service_in: Receiver<ServiceMessage>,
        secret: SecretKey,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            id,
            peers,
            tx,
            rx,
            outgoing,
            incoming,
            service_in,
            secret,
            cancel_token,
            transaction_map: BTreeMap::default(),
            quorum: false,
        }
    }

    // Insert a blob to sign onto the network.
    pub async fn insert(&self, message: Bytes) -> Result<i64> {
        warn!("insert message ");
        let transaction_id = now();
        let gm = GossipMessage::Event {
            message: TransMessage {
                transaction_id,
                event: SigEvent::Start {
                    sig_message: message.clone(),
                },
            },
        };
        // Send local
        let sig_m = SigEvents {
            id: self.id,
            message: gm.clone(),
        };
        let _ = self.outgoing.send(sig_m).await;

        // Send to gossip
        let g_mess = SignedMessage::sign_and_encode(&self.secret, &gm)?;
        let _ = self.tx.broadcast(g_mess).await;
        Ok(transaction_id)
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                            // biased;
                            // Events from the gossip network.
                            event = self.rx.try_next() => {
                                let event = event?;
                                if let Some(event) = event {
                                    match event {
                                        Event::NeighborUp(public_key) => {
                                            println!("NeighborUp {:?}", public_key);
                                            let _ = self.outgoing.send(SigEvents { id: public_key, message: GossipMessage::PeerUp}).await;
                                        },
                                        Event::NeighborDown(public_key) => {
                                            println!("NeighborDown {:?}", public_key);
                                            let _ = self.outgoing.send(SigEvents { id: public_key, message: GossipMessage::PeerDown}).await;
                                        },
                                        Event::Received(message) => {
                                            let (public_key,mess_checked) = match SignedMessage::verify_and_decode(&message.content.to_vec()){
                                                Ok((public_key,sig_mess)) => (public_key,sig_mess),
                                                Err(e) => {
                                                    error!("bad key{:?}",e);
                                                    continue;
                                                }
                                            };
                                            if !self.peers.contains(&public_key) {
                                                error!("unkown node id {:?}",public_key);
                                                continue;
                                            }
                                            self.outgoing.send(SigEvents{id : public_key,message : mess_checked.clone()}).await.expect("send to sig failed");
                                            debug!("message {} => {:?}",public_key.fmt_short(),mess_checked);
                                        }
                                        Event::Lagged => println!("Lagged!!"),
                                    }
                                }
                            }

                            // Incoming message from signer.
                            Some(signer) = self.incoming.recv() =>{
                                debug!("SIGNER ==> GOSSIP {:?}",signer);
                                // pull out the processed signatures
                                match signer {
                                    // Find the transaction in the service transactions
                                    GossipMessage::SigStatus{transaction_id,status} => { 
                                        println!("transaction map {:#?}",&self.transaction_map);
                                        println!("transaction id {}",&transaction_id);
                                        println!("status {:#?}",&status);
                                        if let Some(reply) = self.transaction_map.remove(&transaction_id){
                                            reply.send(status).await?;
                                        }
                                    },
                                    GossipMessage::QuorumUp => { 
                                        warn!("quorum in main runner ");
                                        self.quorum = true;
                                    },
                                    GossipMessage::QuorumDown => { 
                                        warn!("quorum lost in main runner ");
                                        self.quorum = false;
                                    }
                                    // Route everthing else onto the gossip network
                                    _ => {
                                            let sig_mess = SignedMessage::sign_and_encode(&self.secret, &signer)?;
                                            let _ = self.tx.broadcast(sig_mess).await;
                                        }
                                }
                            }

                            // Messges from the service
                            Some(service_message) = self.service_in.recv() => {
                                let message = service_message.message();
                                debug!(" in from service => {}",&message);
                                if self.quorum {
                                    let mess = Bytes::from(message.clone());
                                    
                                    // push the message into the signing system
                                    let transaction_id = self.insert(mess).await?;
                                    info!("tr_id {}",transaction_id);
                                    let reply = service_message.reply;
                                    self.transaction_map.insert(transaction_id,reply);
                                } else { 
                                    service_message.send(
                                        SigStatus::SigError{ error : "No  quorum".to_string()}
                                    ).await;
                                }
                                
                                // service_message.reply(message).await;
                            }

                            // Cancel token to  bug out.
                            _ = self.cancel_token.cancelled() =>  {
                                info!("Stop the main runner");
                                return Ok(());
                            }
                        }
        }
    }
}
