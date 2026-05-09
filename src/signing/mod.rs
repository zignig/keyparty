// Signing can be done with a gossip channel

use bytes::Bytes;
use frost_ed25519::{Signature as FrostSig, round1::SigningCommitments, round2::SignatureShare};
use tokio_util::sync::CancellationToken;
use std::{collections::BTreeMap, time::Duration};

use tokio::sync::mpsc::{Receiver, Sender};

use iroh::{Endpoint, PublicKey, SecretKey, Signature, endpoint::presets, protocol::RouterBuilder};
use iroh_gossip::{
    ALPN as GOSSIP_APLN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};

use n0_error::{AnyError, Result};
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::service;
use crate::service::irpc::ServiceMessage;
use crate::{IdentityApi, cli::Args, config::Config, service::irpc::Reply};

mod auth;
mod quorum;
mod signer;
mod validator;

use auth::Authenticator;

pub const BEACON_DURATION: u64 = 5u64;

// Message Structs
// https://frost.zfnd.org/tutorial/signing.html for info.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SigEvent {
    Start { sig_message: Bytes },
    Round1 { commitment: SigningCommitments },
    Round2 { share: SignatureShare },
    Collect { signature: FrostSig },
    Compare,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransMessage {
    transaction_id: i64,
    event: SigEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GossipMessage {
    Init,
    Hello { timestamp: i64 },
    Waves,
    Event { message: TransMessage },
    PeerDown,
    PeerUp,
}

// Init and run the signing party.
pub async fn run(
    config: Config,
    _args: Args,
    message: Option<Bytes>,
    run_service: bool,
) -> Result<()> {
    info!("-- Start the signing party --");

    let secret = config.secret().clone();
    let peers = config.clone().get_peers().clone();

    let auth_hook = Authenticator::new(peers.clone());

    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        .hooks(auth_hook)
        .bind()
        .await?;

    let _ = endpoint.online().await;
    info!("Endpoint Online");

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // Build the identity client
    let id = IdentityApi::new();
    let id_client = id.client();

    // Build the gossip network.
    let gossip = Gossip::builder().spawn(endpoint.clone());

    // ...and the router
    let router = RouterBuilder::new(endpoint.clone())
        .accept(GOSSIP_APLN, gossip.clone())
        .spawn();

    // messages from the service
    let (service_out, service_in) = tokio::sync::mpsc::channel::<ServiceMessage>(10);
    // if the service flag is set , create  the service node
    if run_service {
        warn!("Start  the external service");
        let token = cancel_token.clone();
        tokio::spawn(service::run(
            config.clone(),
            id_client,
            service_out.clone(),
            token,
        ));
    }

    // Gossip bits
    // TODO fix this topic , this should be the public key.
    let topic_id = TopicId::from_bytes([5; 32]);

    for peer in peers.iter() {
        info!("Waiting for peer : {:}", peer.fmt_short());
    }

    //    let goss = gossip.subscribe_and_join(topic_id, peers.clone()).await?;
    let goss = gossip.subscribe(topic_id, peers.clone()).await?;

    let my_id = secret.public();

    let (tx, rx) = goss.split();

    // Messages between actors
    let (from_gossip, to_signer) = tokio::sync::mpsc::channel::<SigEvents>(10);
    let (from_signer, to_gossip) = tokio::sync::mpsc::channel::<GossipMessage>(10);

    // Create the signer
    let signer = quorum::QuorumWatcher::new(
        my_id.clone(),
        config.clone(),
        from_signer,
        to_signer,
        peers,
        cancel_token.clone(),
    );

    // Start the signer.
    tokio::spawn(signer.run());

    // Start the gossip interface.
    tokio::spawn(runner(
        my_id.clone(),
        tx.clone(),
        rx,
        from_gossip.clone(),
        to_gossip,
        service_in,
        secret.clone(),
        cancel_token.clone()
    ));

    // Bounce some messages
    tokio::spawn(beacon(tx.clone(), secret.clone()));

    // If there is signage , inject some messages.
    if let Some(message) = message.clone() {
        tokio::spawn(message_boop(
            my_id.clone(),
            from_gossip,
            tx.clone(),
            secret.clone(),
            message,
        ));
    }

    // Wait for exit.
    tokio::signal::ctrl_c().await?;
    cancel_token.cancel();
    info!("Exiting signer");

    let _ = router.shutdown().await;

    Ok(())
}

// Gossip runner
// This shares messages to all participants.
pub async fn runner(
    _id: PublicKey,
    tx: GossipSender,
    mut rx: GossipReceiver,
    outgoing: Sender<SigEvents>,
    mut incoming: Receiver<GossipMessage>,
    mut service_in: Receiver<ServiceMessage>,
    secret: SecretKey,
    cancel_token: CancellationToken
) -> Result<(), AnyError> {
    let _service_transactions = BTreeMap::<u64, Reply>::new();
    // Select on the events
    loop {
        tokio::select! {
            // biased;
            // Events from the gossip network.
            event = rx.try_next() => {
                let event = event?;
                if let Some(event) = event {
                    match event {
                        Event::NeighborUp(public_key) => {
                            println!("NeighborUp {:?}", public_key);
                            let _ = outgoing.send(SigEvents { id: public_key, message: GossipMessage::PeerUp}).await;
                        },
                        Event::NeighborDown(public_key) => {
                            println!("NeighborDown {:?}", public_key);
                            let _ = outgoing.send(SigEvents { id: public_key, message: GossipMessage::PeerDown}).await;
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

            // Incoming message from signer.
            Some(signer) = incoming.recv() =>{
                debug!("SIGNER ==> GOSSIP {:?}",signer);
                let sig_mess = SignedMessage::sign_and_encode(&secret, &signer)?;
                let _ = tx.broadcast(sig_mess).await;
            }

            // Messges from the service
            Some(service_message) = service_in.recv() => {
                error!(" in gossip => {}",service_message.message());
                // let mess = service_message.message();
                let mess = "woo hoo it seems to work".to_string();
                // let r = service_message.reply;
                // service_transactions.insert(4,r);
                // println!("{:#?}",service_transactions);
                service_message.reply(mess).await;
            }

            // Cancel token to  bug out.
            _ = cancel_token.cancelled() =>  { 
                info!("Stop the main runner");
                return Ok(());
            }
        }
    }
}

// Chuch a hello onto the gossip.
pub async fn beacon(tx: GossipSender, secret_key: SecretKey) -> Result<()> {
    warn!("start beacon");
    loop {
        let message = GossipMessage::Hello {
            timestamp: chrono::Utc::now().timestamp_millis(),
        };
        let sig_mess = SignedMessage::sign_and_encode(&secret_key, &message)?;
        let _ = tx.broadcast(sig_mess).await;
        tokio::time::sleep(Duration::from_secs(BEACON_DURATION)).await;
    }
}

// TESTING , some testing to inject signing messages
pub async fn message_boop(
    id: PublicKey,
    tx: Sender<SigEvents>,
    gtx: GossipSender,
    secret_key: SecretKey,
    message: Bytes,
) -> Result<()> {
    warn!("start message booper");
    loop {
        let gm = GossipMessage::Event {
            message: TransMessage {
                transaction_id: now(),
                event: SigEvent::Start {
                    sig_message: message.clone(),
                },
            },
        };
        // Send local
        let sig_m = SigEvents {
            id,
            message: gm.clone(),
        };
        let _ = tx.send(sig_m).await;

        // Send to gossip
        let g_mess = SignedMessage::sign_and_encode(&secret_key, &gm)?;
        let _ = gtx.broadcast(g_mess).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

// Interprocess messages ,
#[derive(Clone, Debug)]
pub struct SigEvents {
    id: PublicKey,
    message: GossipMessage,
}

// Stolen from CHAT.
//

// Messages signed with endpoing secrect...
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    when: i64,
    signature: Signature,
}

impl SignedMessage {
    pub fn verify_and_decode(bytes: &[u8]) -> Result<(PublicKey, GossipMessage)> {
        let signed_message: Self = postcard::from_bytes(bytes).expect("deser fail");
        let key: PublicKey = signed_message.from;
        key.verify(&signed_message.data, &signed_message.signature)
            .expect("verify fail");
        let message: GossipMessage =
            postcard::from_bytes(&signed_message.data).expect("postcard fail");
        Ok((signed_message.from, message))
    }

    pub fn sign_and_encode(secret_key: &SecretKey, message: &GossipMessage) -> Result<Bytes> {
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
