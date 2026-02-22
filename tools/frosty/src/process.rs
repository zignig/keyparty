// this is the signing state machine
// goes through the process of building the keys

// refer to https://frost.zfnd.org/tutorial/dkg.html
// for the process

use iroh::{Endpoint, PublicKey};
use n0_error::Result;
use std::{collections::BTreeMap, time::Duration};
use tracing::{error, info, warn};

use crate::{
    frostyrpc::{FrostyClient, ProcessSteps},
    ticket::FrostyTicket,
};

// Key gen imports
use frost_ed25519::keys::dkg::round1::Package as r1package;
use frost_ed25519::{self as frost, Identifier};

pub struct DistributedKeyGeneration {
    endpoint: Endpoint,
    local_rpc: FrostyClient,
    process_client: FrostyClient,
    clients: BTreeMap<PublicKey, FrostyClient>,
    ticket: FrostyTicket,
    state: ProcessSteps,
    my_id: PublicKey,
    // round info
    round1: BTreeMap<PublicKey, BTreeMap<PublicKey, r1package>>,
    round1_secret: Option<frost_ed25519::keys::dkg::round1::SecretPackage>,
    round1_count: BTreeMap<PublicKey, usize>,
}

impl DistributedKeyGeneration {
    pub fn new(
        endpoint: Endpoint,
        // Local connection to the Frosty Server
        local_rpc: FrostyClient,
        // as Server this is local , as Client is remote
        client: FrostyClient,
        ticket: FrostyTicket,
    ) -> Self {
        let my_id = endpoint.id();
        Self {
            endpoint: endpoint,
            local_rpc: local_rpc,
            process_client: client,
            clients: Default::default(),
            ticket: ticket,
            state: ProcessSteps::Init,
            my_id: my_id,
            round1: Default::default(),
            round1_secret: None,
            round1_count: Default::default(),
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting the key generation for {:?}", self.my_id);
        let mut rng = frost_ed25519::rand_core::OsRng;
        loop {
            match self.state {
                // Wait for the correct number of clients
                ProcessSteps::Init => {
                    let mut client_counter = 1;
                    info!("Start the local client");
                    info!("Need {:?} clients", self.ticket.max_shares);
                    // need to make sure that this connection is robust ( try  more than once )
                    let mut count = 0;
                    const MAX_FAIL: i32 = 5;
                    let mut exit = false;
                    while !exit {
                        match self.process_client.auth(self.ticket.token.as_str()).await {
                            Ok(_) => exit = true,
                            Err(e) => {
                                error!("CONNECT fail {:?} of {:?} with {:?} ", count, MAX_FAIL, e);
                                count += 1;
                                if count == MAX_FAIL {
                                    return Err(e.into());
                                }
                            }
                        }
                    }
                    loop {
                        let count = self.process_client.count().await?;
                        if count != client_counter {
                            info!(" new peer {:?}/{:?}", count, self.ticket.max_shares);
                            if count == self.ticket.max_shares as usize {
                                break;
                            }
                            client_counter = count;
                        }
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    info!("start the process");
                    self.state = ProcessSteps::CreateMesh;
                    continue;
                }
                // Connect all the clients  together
                ProcessSteps::CreateMesh => {
                    info!("Create the mesh");
                    let mut peers = self.process_client.peers().await?;
                    // Add this node
                    self.clients.insert(self.my_id, self.local_rpc.clone());
                    while let Some(peer) = peers.recv().await? {
                        info!("peers {:?}", peer);
                        if peer != self.my_id {
                            self.clients
                                .insert(peer, FrostyClient::connect(self.endpoint.clone(), peer));
                        };
                    }
                    // Need more robust check that we have all the nodes.
                    // connect is lazy and will only connect on action
                    self.auth_all().await?;

                    // self.show_peers();
                    self.booper().await?;

                    self.state = ProcessSteps::Part1Send;
                    continue;
                }
                // Create the public pack and send to all the nodes including this one
                ProcessSteps::Part1Send => {
                    info!("Part1 send");
                    let participant =
                        Identifier::derive(self.my_id.as_bytes()).expect("bad identifier");
                    let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
                        participant,
                        self.ticket.max_shares,
                        self.ticket.min_shares,
                        &mut rng,
                    )
                    .expect("part1 package fail");
                    self.round1_secret = Some(round1_secret_package);

                    // The round 1 package gets sent to everyone
                    // TODO , can this loop across all client be put into a function ?
                    for (peer, client) in self.clients.iter() {
                        let _ = client.round1(round1_package.clone()).await?;
                        warn!("send round1 package to {:?}", peer);
                    }
                    self.state = ProcessSteps::Part1Fetch;
                    continue;
                }
                // Fetch each of the packages from each of the nodes
                ProcessSteps::Part1Fetch => {
                    info!("Check that each client has enough packs");
                    let mut exit = false;
                    while !exit {
                        for (peer, client) in self.clients.iter() {
                            let count = client.round1_count().await?;
                            println!("{:?} -- {:?}", peer, count);
                            self.round1_count.insert(peer.clone(), count);
                        }
                        let max = self.ticket.max_shares as usize;
                        // if they are all there bail out
                        exit = self.round1_count.values().all(|x| *x == max);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    info!("Part1 Fetch");
                    for (peer, client) in self.clients.iter() {
                        let mut packages = client.round1_fetch().await?;
                        let mut peer_pack: BTreeMap<PublicKey, r1package> = Default::default();
                        while let Some((p, i)) = packages.recv().await? {
                            peer_pack.insert(p, i);
                        }
                        self.round1.insert(peer.clone(), peer_pack);
                    }
                    self.state = ProcessSteps::Part1Check;
                    continue;
                }
                // Check that all the pacakages are the same from each node
                ProcessSteps::Part1Check => {
                    info!("Part 1 Check");

                    self.check_round1()?;

                    return Ok(());
                }
            }
        }
    }

    fn check_round1(&self) -> Result<()> {
        info!("check that all the round 1 packages are good");
        // println!("{:#?}", self.round1);
        for (peer, peer_map) in self.round1.iter() {
            println!("map check {:?} -- {:?}", peer, peer_map.len());
        }
        Ok(())
    }

    // #[allow(dead_code)]

    async fn booper(&self) -> Result<()> {
        let mut counter = 0;
        const MAX: i32 = 5;
        loop {
            for (peer, client) in self.clients.iter() {
                match client.boop().await {
                    Ok(n) => println!("booper {:?} -- {:?}", peer, n),
                    Err(e) => error!("{:?} for {:?}", e, peer),
                }
            }
            counter += 1;
            if counter > MAX {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[allow(dead_code)]
    fn show_peers(&self) {
        println!("Self {:?}", self.my_id);
        println!("______________________________");
        for (peer, client) in self.clients.iter() {
            println!("{:?} -- {:?}", peer, client.local());
        }
        println!("______________________________");
    }

    // async fn run_each(&mut self) -> Result<()> {
    //     let r: Vec<&mut FrostyClient> = self.clients
    //         .iter_mut()
    //         .map(|(_, client)| client).collect();
    //     r.iter().for_each(FrostyClient::count);
    //     Ok(())
    // }

    async fn auth_all(&mut self) -> Result<()> {
        for (peer, client) in self.clients.iter() {
            // let a = client.auth(self.ticket.token.as_str()).await?;
            // warn!("{:?} -- {:?}", peer, a);
            let mut count = 0;
            const MAX_FAIL: i32 = 5;
            let mut exit = false;
            while !exit {
                match client.auth(self.ticket.token.as_str()).await {
                    Ok(_) => exit = true,
                    Err(e) => {
                        error!(
                            "CONNECT fail {:?} of {:?} to {:?} with {:?} ",
                            count, MAX_FAIL, peer, e
                        );
                        count += 1;
                        if count == MAX_FAIL {
                            return Err(e.into());
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
