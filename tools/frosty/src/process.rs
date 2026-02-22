// this is the signing state machine
// goes through the process of building the keys

// refer to https://frost.zfnd.org/tutorial/dkg.html
// for the process

use iroh::{Endpoint, PublicKey};
use n0_error::Result;
use rand::rng;
use std::{collections::BTreeMap, time::Duration};
use tracing::{error, info, warn};

use crate::{
    frostyrpc::{FrostyClient, ProcessSteps},
    ticket::FrostyTicket,
};

// Key gen imports
use frost_ed25519::{self as frost, Identifier};

pub struct DistributedKeyGeneration {
    endpoint: Endpoint,
    local_rpc: FrostyClient,
    process_client: FrostyClient,
    clients: BTreeMap<PublicKey, FrostyClient>,
    ticket: FrostyTicket,
    state: ProcessSteps,
    my_id: PublicKey,
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
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting the key generation for {:?}", self.my_id);
        let mut rng = frost_ed25519::rand_core::OsRng; 
        loop {
            match self.state {
                // Wait for the correct number of clients
                ProcessSteps::Init => {
                    let mut client_counter= 1;
                    info!("Start the local client");
                    info!("Need {:?} clients", self.ticket.max_shares);
                    let res = self.process_client.auth(self.ticket.token.as_str()).await;
                    println!("RESULT: {:?}", res);
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
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    info!("start the process");
                    self.state = ProcessSteps::CreateMesh;
                    continue;
                }
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

                    self.show_peers();

                    self.auth_all().await?;

                    self.booper().await?;

                    self.state = ProcessSteps::Part1Send;
                    continue;
                }
                ProcessSteps::Part1Send => {
                    info!("Part1 send");
                    let participant =
                        Identifier::derive(self.my_id.as_bytes()).expect("bad identifier");
                    let (round1_secret_package, round1_package) = frost::keys::dkg::part1(
                        participant,
                        self.ticket.max_shares,
                        self.ticket.min_shares,
                        &mut rng,
                    ).expect("part1 package fail");
                    error!("{:#?}",round1_secret_package);
                    error!("{:#?}",round1_package);
                    self.local_rpc.round1(round1_package).await?;
                    
                    return Ok(());
                }
            }
        }
    }

    // #[allow(dead_code)]

    async fn booper(&self) -> Result<()> {
        let mut counter = 0;
        const MAX: i32 = 40;
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
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

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
            let a = client.auth(self.ticket.token.as_str()).await?;
            warn!("{:?} -- {:?}", peer, a);
        }
        Ok(())
    }
}
