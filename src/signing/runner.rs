// The main runner for the signing process

use bytes::Bytes;
use iroh::{PublicKey, SecretKey};
use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use n0_error::{AnyError, Result};
use n0_future::StreamExt;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    service::irpc::ServiceMessage,
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
        }
    }

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
                    let sig_mess = SignedMessage::sign_and_encode(&self.secret, &signer)?;
                    let _ = self.tx.broadcast(sig_mess).await;
                }

                // Messges from the service
                Some(service_message) = self.service_in.recv() => {
                    let message = service_message.message();
                    error!(" in gossip => {}",&message);

                    // let mess = service_message.message();
                    let mess = Bytes::from(message.clone());
                    self.insert(mess).await?;

                    // let r = service_message.reply;
                    // service_transactions.insert(4,r);
                    // println!("{:#?}",service_transactions);
                    service_message.reply(message).await;
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
