// Signing can be done with a gossip channel

use bytes::Bytes;
use frost_ed25519::{round1::SigningCommitments, round2::SignatureShare};
use std::time::Duration;

use iroh::{Endpoint, PublicKey, SecretKey, Signature, endpoint::presets, protocol::RouterBuilder};
use iroh_gossip::{ALPN as GOSSIP_APLN, Gossip, TopicId, api::GossipSender};

use n0_error::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::service::irpc::ServiceMessage;
use crate::{IdentityApi, cli::Args, config::Config};
use crate::{
    service::{self, irpc::SigStatus},
    signing::runner::MainRunner,
};

mod auth;
mod quorum;
mod runner;
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
    // Collect { signature: FrostSig },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TransMessage {
    transaction_id: i64,
    event: SigEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GossipMessage {
    Init,
    Hello {
        timestamp: i64,
    },
    Waves,
    Event {
        message: TransMessage,
    },
    PeerDown,
    PeerUp,
    // These stops at the signer exit point, and
    // don't go into the actual gossip network
    SigStatus {
        transaction_id: i64,
        status: SigStatus,
    },
    QuorumUp,
    QuorumDown,
}

// Init and run the signing party.
pub async fn run(config: Config, _args: Args, run_service: bool) -> Result<()> {
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
    let (service_out, service_in) = tokio::sync::mpsc::channel::<ServiceMessage>(50);
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
    let topic: [u8; 32] = match config.public_key() {
        Some(topic) => topic.serialize().unwrap().try_into().expect("bad decode"),
        None => [5; 32],
    };

    let topic_id = TopicId::from_bytes(topic);

    for peer in peers.iter() {
        info!("Waiting for peer : {:}", peer.fmt_short());
    }

    //    let goss = gossip.subscribe_and_join(topic_id, peers.clone()).await?;
    let goss = gossip.subscribe(topic_id, peers.clone()).await?;

    let my_id = secret.public();

    let (tx, rx) = goss.split();

    // Messages between actors
    let (from_gossip, to_signer) = tokio::sync::mpsc::channel::<SigEvents>(50);
    let (from_signer, to_gossip) = tokio::sync::mpsc::channel::<GossipMessage>(50);

    // Create the signer
    let signer = quorum::QuorumWatcher::new(
        my_id.clone(),
        config.clone(),
        from_signer,
        to_signer,
        peers.clone(),
        cancel_token.clone(),
    );

    // Start the signer.
    tokio::spawn(signer.run());

    // Start the gossip interface.
    let main_runner = MainRunner::new(
        my_id.clone(),
        peers,
        tx.clone(),
        rx,
        from_gossip.clone(),
        to_gossip,
        service_in,
        secret.clone(),
        cancel_token.clone(),
    );

    // Spawn the main runner for the signer.
    tokio::spawn(main_runner.run());

    // Bounce some messages
    tokio::spawn(beacon(tx.clone(), secret.clone()));

    // Wait for exit.
    tokio::signal::ctrl_c().await?;
    cancel_token.cancel();
    info!("Exiting signer");

    let _ = router.shutdown().await;

    Ok(())
}

// Chuck a hello onto the gossip.
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
