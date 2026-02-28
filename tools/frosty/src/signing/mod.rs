// Signing can be done with a gossip channel

use bytes::Bytes;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use iroh::{
    Endpoint, PublicKey, RelayMode, SecretKey, Signature, discovery::mdns::MdnsDiscovery,
    protocol::RouterBuilder,
};
use iroh_gossip::{
    ALPN as GOSSIP_APLN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};
use n0_error::Result;
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{cli::Args, config::Config};

mod auth;
mod protocol;

pub async fn run(config: Config, args: Args, message: &Option<String>) -> Result<()> {
    info!("Start the signing party");

    let endpoint = Endpoint::builder()
        .secret_key(config.secret())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;

    // temp until the internet is fixed
    let mdns = MdnsDiscovery::builder().build(endpoint.id()).unwrap();
    endpoint.discovery().add(mdns.clone());

    let gossip = Gossip::builder().spawn(endpoint.clone());

    let router = RouterBuilder::new(endpoint.clone())
        .accept(GOSSIP_APLN, gossip.clone())
        .spawn();

    // Gossip bits
    let topic_id = TopicId::from_bytes([5; 32]);
    let peers = config.clone().peers();
    let goss = gossip.subscribe_and_join(topic_id, peers).await?;
    let secret = config.secret().clone();
    let (tx, rx) = goss.split();

    // Messages between
    let (outgoing, incoming) = tokio::sync::mpsc::channel(10);

    // Create the signer
    let peers = config.clone().peers();
    let signer = protocol::SigningSequence::new("hello".into(), incoming, peers);

    tokio::spawn(protocol::run(signer));
    // Spawn the main process
    tokio::spawn(runner(rx, outgoing));
    tokio::spawn(booper(tx, secret));

    tokio::signal::ctrl_c().await?;
    let _ = router.shutdown().await;
    Ok(())
}

pub async fn runner(mut rx: GossipReceiver, outgoing: Sender<SigEvents>) -> Result<()> {
    // Select on the events
    // from gossip
    // from local irpc
    // from elsewhere...
    loop {
        tokio::select! {
            biased;
            event = rx.try_next() => {
                let event = event?;
                if let Some(event) = event {
                    match event {
                        Event::NeighborUp(public_key) => println!("NeighborUp {:?}", public_key),
                        Event::NeighborDown(public_key) => println!("NeighborDown {:?}", public_key),
                        Event::Received(message) => {
                            let (public_key,mess_checked) = match SignedMessage::verify_and_decode(&message.content.to_vec()){
                                Ok((public_key,sig_mess)) => (public_key,sig_mess),
                                Err(e) => {
                                    error!("bad key{:?}",e);
                                    continue;
                                }
                            };
                            outgoing.send(SigEvents{id : public_key,message : mess_checked.clone()}).await.expect("send to sig failed");
                            info!("message {} => {:?}",public_key.fmt_short(),mess_checked);
                        }
                        Event::Lagged => println!("Lagged!!"),
                    }

                }
            }
        }
    } 
    Ok(())
}

pub async fn booper(tx: GossipSender, secret_key: SecretKey) -> Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let message = SigningMessage::Hello;
        let sig_mess = SignedMessage::sign_and_encode(&secret_key, &message)?;
        let _ = tx.broadcast(sig_mess).await;
    }
}

// Transfer messages
#[derive(Clone,Debug)]
pub struct SigEvents {
    id: PublicKey,
    message: SigningMessage,
}

// Stolen from CHAT.
// Message Structs

#[derive(Debug, Clone, Serialize, Deserialize)]
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
