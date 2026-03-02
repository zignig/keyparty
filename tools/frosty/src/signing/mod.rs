// Signing can be done with a gossip channel

use bytes::Bytes;
use std::time::Duration;

use tokio::{sync::mpsc::Receiver, sync::mpsc::Sender};

use iroh::{
    Endpoint, PublicKey, RelayMode, SecretKey, Signature, discovery::mdns::MdnsDiscovery,
    protocol::RouterBuilder,
};
use iroh_gossip::{
    ALPN as GOSSIP_APLN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};
use n0_error::{AnyError, Result};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

use crate::{cli::Args, config::Config};

mod auth;
mod protocol;

pub async fn run(config: Config, _args: Args, message: Option<Bytes>) -> Result<()> {
    info!("-- Start the signing party --");

    let endpoint = Endpoint::builder()
        .secret_key(config.secret())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    // temp until the internet is fixed
    let mdns = MdnsDiscovery::builder().build(endpoint.id()).unwrap();
    endpoint.discovery().add(mdns.clone());

    // Build all signing bits
    // Convert to an actor.

    let gossip = Gossip::builder().spawn(endpoint.clone());

    let router = RouterBuilder::new(endpoint.clone())
        .accept(GOSSIP_APLN, gossip.clone())
        .spawn();

    // Gossip bits
    let topic = config.public_key();
    let topic_id = TopicId::from_bytes([5; 32]);

    let peers = config.clone().peers();

    for peer in peers.iter() {
        info!("Waiting for peer : {:?}", peer);
    }
    let goss = gossip.subscribe_and_join(topic_id, peers).await?;
    let secret = config.secret().clone();
    let (tx, rx) = goss.split();

    // Messages between actors
    let (from_gossip, to_signer) = tokio::sync::mpsc::channel::<SigEvents>(10);
    let (from_signer, to_gossip) = tokio::sync::mpsc::channel::<SigningMessage>(10);

    // Create the signer
    let peers = config.clone().peers();
    let signer =
        protocol::QuorumWatcher::new(config.clone(), message, from_signer, to_signer, peers);

    tokio::spawn(protocol::run(signer));

    tokio::spawn(runner(
        tx.clone(),
        rx,
        from_gossip,
        to_gossip,
        secret.clone(),
    ));

    tokio::spawn(booper(tx, secret));

    tokio::signal::ctrl_c().await?;

    let _ = router.shutdown().await;

    Ok(())
}

pub async fn runner(
    tx: GossipSender,
    mut rx: GossipReceiver,
    outgoing: Sender<SigEvents>,
    mut incoming: Receiver<SigningMessage>,
    secret: SecretKey,
) -> Result<(), AnyError> {
    // Select on the events
    // from gossip
    // from local irpc
    // from elsewhere...
    loop {
        tokio::select! {
            biased;
            // Events from the gossip network.
            event = rx.try_next() => {
                let event = event?;
                if let Some(event) = event {
                    match event {
                        Event::NeighborUp(public_key) => {
                            println!("NeighborUp {:?}", public_key);
                            let _ = outgoing.send(SigEvents { id: public_key, message: SigningMessage::PeerUp}).await;
                        },
                        Event::NeighborDown(public_key) => {
                            println!("NeighborDown {:?}", public_key);
                            let _ = outgoing.send(SigEvents { id: public_key, message: SigningMessage::PeerDown}).await;
                        },
                        Event::Received(message) => {
                            let (public_key,mess_checked) = match SignedMessage::verify_and_decode(&message.content.to_vec()){
                                Ok((public_key,sig_mess)) => (public_key,sig_mess),
                                Err(e) => {
                                    error!("bad key{:?}",e);
                                    continue;
                                }
                            };
                            outgoing.send(SigEvents{id : public_key,message : mess_checked.clone()}).await.expect("send to sig failed");
                            debug!("message {} => {:?}",public_key.fmt_short(),mess_checked);
                        }
                        Event::Lagged => println!("Lagged!!"),
                    }
                }
            }
            Some(signer) = incoming.recv() =>{
                // error!("SIGNER ==> GOSSIP {:?}",signer);
                let sig_mess = SignedMessage::sign_and_encode(&secret, &signer)?;
                let _ = tx.broadcast(sig_mess).await;
            }

        }
    }
    Ok(())
}

pub async fn booper(tx: GossipSender, secret_key: SecretKey) -> Result<()> {
    loop {
        let message = SigningMessage::Hello;
        let sig_mess = SignedMessage::sign_and_encode(&secret_key, &message)?;
        let _ = tx.broadcast(sig_mess).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// Transfer messages
#[derive(Clone, Debug)]
pub struct SigEvents {
    id: PublicKey,
    message: SigningMessage,
}

// Stolen from CHAT.
// Message Structs

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SigningMessage {
    Init,
    Hello,
    Waves,
    Start {
        transaction_id: String,
        message: String,
    },
    Round1,
    Round2,
    Collect,
    Compare,
    // peer event
    PeerDown,
    PeerUp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    when: i64,
    signature: Signature,
}

impl SignedMessage {
    pub fn verify_and_decode(bytes: &[u8]) -> Result<(PublicKey, SigningMessage)> {
        let signed_message: Self = postcard::from_bytes(bytes).expect("deser fail");
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)
            .expect("verify fail");
        let message: SigningMessage =
            postcard::from_bytes(&signed_message.data).expect("postcard fail");
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: &SigningMessage) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(&message)
            .expect("postcard encode fail")
            .into();
        let signature = secret_key.sign(&data);
        let from: PublicKey = secret_key.public();
        let signed_message = Self {
            from,
            data,
            when: chrono::Utc::now()
                .timestamp_nanos_opt()
                .expect("time does not exist"),
            signature,
        };
        let encoded = postcard::to_stdvec(&signed_message).expect("postcard decode fail");
        Ok(encoded.into())
    }
}
