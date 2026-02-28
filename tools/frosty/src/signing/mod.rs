// Signing can be done with a gossip channel

use std::time::Duration;

use iroh::{
    Endpoint, PublicKey, RelayMode, SecretKey, discovery::mdns::MdnsDiscovery,
    protocol::RouterBuilder,
};
use iroh_gossip::{
    ALPN as GOSSIP_APLN, Gossip, TopicId,
    api::{Event, GossipReceiver, GossipSender},
};
use n0_error::Result;
use n0_future::StreamExt;
use tracing::info;

use crate::{cli::Args, config::Config};

pub async fn run(config: Config, args: Args, file: &Option<String>) -> Result<()> {
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

    let topic_id = TopicId::from_bytes([5; 32]);
    let peers = config.clone().peers();
    let goss = gossip.subscribe_and_join(topic_id, peers).await?;
    let secret = config.secret().clone();
    let (tx, rx) = goss.split();

    // Spawn the main process
    tokio::spawn(runner(rx, secret));
    tokio::spawn(booper(tx));

    tokio::signal::ctrl_c().await?;
    let _ = router.shutdown().await;
    Ok(())
}

pub async fn runner(mut rx: GossipReceiver, secret: SecretKey) -> Result<()> {
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
                            let content = message.content;
                            println!(
                            "message -> {:?} from {}",
                            content,
                            message.delivered_from.fmt_short()
                        );
                        }
                        Event::Lagged => println!("Lagged!!"),
                    }
                }
            }
        }
    }
    // while let Some(event) = rx.try_next().await? {
    //     // println!("gossip event--> {:#?}", event);
    //     match event {
    //         Event::NeighborUp(public_key) => println!("NeighborUp {:?}", public_key),
    //         Event::NeighborDown(public_key) => println!("NeighborDown {:?}", public_key),
    //         Event::Received(message) => {
    //             let content = message.content;
    //             println!(
    //                 "message -> {:?} from {}",
    //                 content,
    //                 message.delivered_from.fmt_short()
    //             );
    //         }
    //         Event::Lagged => println!("Lagged!!"),
    //     }
    // }
    Ok(())
}

pub async fn booper(tx: GossipSender) -> Result<()> {
    let now = std::time::SystemTime::now();
    let mut counter = 1;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let delta = now.elapsed().expect("time fail").as_nanos();
        let _ = tx
            .broadcast(format!("boop {} {}", delta, counter).into())
            .await;
        counter += 1;
    }
}
