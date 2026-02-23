// this is the signing state machine
// goes through the process of building the keys

// refer to https://frost.zfnd.org/tutorial/dkg.html
// for the process

use iroh::{Endpoint, PublicKey};
use n0_error::Result;
use std::{collections::BTreeMap, time::Duration};
use tracing::{debug, error, info};

use crate::{
    config::Config,
    frostyrpc::{FrostyClient, ProcessSteps},
    ticket::FrostyTicket,
};

// Key gen imports
use anyhow::anyhow;
use frost_ed25519::keys::dkg::round1::Package as r1package;
use frost_ed25519::{self as frost, Identifier};

pub struct DistributedKeyGeneration {
    config: Config,
    endpoint: Endpoint,
    local_rpc: FrostyClient,
    process_client: FrostyClient,
    clients: BTreeMap<PublicKey, FrostyClient>,
    ticket: FrostyTicket,
    state: ProcessSteps,
    my_id: PublicKey,
    // round 1 info
    round1: BTreeMap<PublicKey, BTreeMap<PublicKey, r1package>>,
    round1_secret: Option<frost_ed25519::keys::dkg::round1::SecretPackage>,
    round1_count: BTreeMap<PublicKey, usize>,
    // map built for ident
    part1_map: BTreeMap<Identifier, r1package>,
    // round 2 info
    round2_secret: Option<frost_ed25519::keys::dkg::round2::SecretPackage>,
    round2_map_out: BTreeMap<PublicKey, frost_ed25519::keys::dkg::round2::Package>,
    // round 2 mapping
    round2_map_in: BTreeMap<Identifier, frost_ed25519::keys::dkg::round2::Package>,
}

impl DistributedKeyGeneration {
    pub fn new(
        endpoint: Endpoint,
        // Local connection to the Frosty Server
        local_rpc: FrostyClient,
        // as Server this is local , as Client is remote
        client: FrostyClient,
        ticket: FrostyTicket,
        config: Config,
    ) -> Self {
        let my_id = endpoint.id();
        Self {
            config: config,
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
            part1_map: Default::default(),
            round2_secret: None,
            round2_map_out: Default::default(),
            round2_map_in: Default::default(),
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
                            info!("New client {:?}/{:?}", count, self.ticket.max_shares);
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
                        debug!("peers {:?}", peer);
                        if peer != self.my_id {
                            self.clients
                                .insert(peer, FrostyClient::connect(self.endpoint.clone(), peer));
                        };
                    }
                    // Need more robust check that we have all the nodes.
                    // connect is lazy and will only connect on action
                    let peers = self.auth_all().await?;
                    self.config.set_peers(peers);
                    // some requests to be sure
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
                        debug!("send round1 package to {:?}", peer);
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
                            debug!("{:?} -- {:?}", peer, count);
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
                    info!("Check OK");
                    self.state = ProcessSteps::Part2Build;
                    continue;
                }
                ProcessSteps::Part2Build => {
                    info!("Part 2 build");
                    // Build the correct map type
                    let mut part1_map: BTreeMap<Identifier, r1package> = Default::default();
                    // Map identfiers to ID (conversion is painful , just save and remap)
                    let mut id_key_map: BTreeMap<Identifier, PublicKey> = Default::default();

                    // convert the map , use this local id's map
                    // should not matter as they have been checked
                    if let Some(map) = self.round1.get(&self.my_id) {
                        for (id, pack) in map.iter() {
                            let ident = Identifier::derive(id.as_bytes()).expect("bad identifier");
                            // not well documented but don't include the round 1 package for _this_ client
                            if *id != self.my_id {
                                id_key_map.insert(ident.clone(), id.clone());
                                part1_map.insert(ident, pack.clone());
                            };
                        }
                        // Save this for part 3
                        self.part1_map = part1_map.clone();
                    }
                    // create the second round of stuff
                    // println!("{:#?}", &part1_map);
                    let secret_package = self
                        .round1_secret
                        .clone()
                        .ok_or(anyhow!("missing secret package"))?;

                    let (round2_secret, round2_map) =
                        frost::keys::dkg::part2(secret_package, &part1_map)
                            .expect("part2 build failed");

                    // Save the secret for round 2
                    self.round2_secret = Some(round2_secret);
                    // Rebuild the round2 map for public keys
                    for (ident, pack) in round2_map.iter() {
                        let pk = id_key_map
                            .get(ident)
                            .ok_or(anyhow!("missing ident key"))?
                            .clone();
                        self.round2_map_out.insert(pk, pack.clone());
                    }
                    self.state = ProcessSteps::Part2Send;
                    continue;
                }
                ProcessSteps::Part2Send => {
                    info!("Part 2 Send");
                    for (id, pack) in self.round2_map_out.iter() {
                        debug!("part2 send {:?}", &id);
                        let client = self
                            .clients
                            .get(id)
                            .ok_or(anyhow!("missing client for pack2"))?;
                        client.round2(pack.clone()).await?;
                    }
                    // Does this need a counter check , probably yes
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    self.state = ProcessSteps::Part2Fetch;
                    continue;
                }
                ProcessSteps::Part2Fetch => {
                    info!("Part 2 Fetch");
                    // This is fetching from local as it has the section given to me
                    // this should be more protected.
                    // self.show_peers();
                    let mut packs = self.local_rpc.round2_fetch().await?;
                    while let Some((id, pack2)) = packs.recv().await?.transpose()? {
                        let ident = Identifier::derive(id.as_bytes()).expect("bad identifier");
                        self.round2_map_in.insert(ident, pack2);
                    }
                    self.state = ProcessSteps::Part3Build;
                    continue;
                }
                ProcessSteps::Part3Build => {
                    info!("Part 3 build");
                    let secret_package = self
                        .round2_secret
                        .clone()
                        .ok_or(anyhow!("round 2 secret package broken"))?;
                    let (key_share, public_share) = frost_ed25519::keys::dkg::part3(
                        &secret_package,
                        &self.part1_map,
                        &self.round2_map_in,
                    )
                    .expect("part 3 build error");

                    // Prepare for saving
                    let key_share_vec = key_share.serialize().expect("bad keyshare serialization");
                    let public_share_vec =
                        public_share.serialize().expect("bad public serialization");
                    let verifying_vec = public_share
                        .verifying_key()
                        .serialize()
                        .expect("bad verifying key");

                    let mut ks_hex = data_encoding::BASE32_NOPAD.encode(&key_share_vec);
                    let mut ps_hex = data_encoding::BASE32_NOPAD.encode(&public_share_vec);
                    let mut vk_hex = data_encoding::BASE32_NOPAD.encode(&verifying_vec);

                    ks_hex.make_ascii_lowercase();
                    ps_hex.make_ascii_lowercase();
                    vk_hex.make_ascii_lowercase();

                    self.config.set_packages(ks_hex, ps_hex, vk_hex);
                    info!("See file {:?}", Config::FILE_NAME);
                    return Ok(());
                }
            }
        }
    }

    fn check_round1(&self) -> Result<()> {
        info!("check that all the round 1 packages are equivilent");
        let mut clumped: BTreeMap<PublicKey, Vec<r1package>> = Default::default();
        for (peer, peer_map) in self.round1.iter() {
            debug!("map check {:?} -- {:?}", peer, peer_map.len());
            for (key, pack) in peer_map.iter() {
                clumped.entry(key.clone()).or_default().push(pack.clone())
            }
        }
        for (_, v) in clumped.iter() {
            // Check consecutive pairs against each other
            // if false just bug out
            if !v.windows(2).all(|w| w[0] == w[1]) {
                error!("Round one packages bad ABORT!!!");
                return Err(anyhow!("round 1 packages broken").into());
            }
        }
        Ok(())
    }

    // #[allow(dead_code)]

    async fn booper(&self) -> Result<()> {
        let mut counter = 0;
        const MAX: i32 = 4;
        loop {
            for (peer, client) in self.clients.iter() {
                match client.boop().await {
                    Ok(n) => {
                        debug!("booper {:?} -- {:?}", peer, n);
                        continue;
                    }
                    Err(e) => error!("{:?} for {:?}", e, peer),
                }
            }
            counter += 1;
            if counter > MAX {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
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

    async fn auth_all(&mut self) -> Result<Vec<PublicKey>> {
        let mut peer_list: Vec<PublicKey> = Vec::new();
        for (peer, client) in self.clients.iter() {
            debug!("{:?} -- {:?}", peer, client);
            let mut count = 0;
            const MAX_FAIL: i32 = 5;
            let mut exit = false;
            while !exit {
                match client.auth(self.ticket.token.as_str()).await {
                    Ok(_) => {
                        peer_list.push(peer.clone());
                        exit = true;
                    }
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
        Ok(peer_list)
    }
}
