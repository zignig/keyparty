// this is the signing state machine
// goes through the process of building the keys

// refer to https://frost.zfnd.org/tutorial/dkg.html
// for the process

use iroh::{Endpoint, PublicKey};
use n0_error::Result;
use std::{collections::BTreeMap, time::Duration};
use tracing::{info, warn};

use crate::{
    frostyrpc::{FrostyClient, ProcessSteps},
    ticket::FrostyTicket,
};

pub struct DistributedKeyGeneration {
    endpoint: Endpoint,
    local_client: FrostyClient,
    clients: BTreeMap<PublicKey, FrostyClient>,
    ticket: FrostyTicket,
    state: ProcessSteps,
    my_id: PublicKey,
}

impl DistributedKeyGeneration {
    pub fn new(
        endpoint: Endpoint,
        client: FrostyClient,
        ticket: FrostyTicket,
        id: PublicKey,
    ) -> Self {
        Self {
            endpoint: endpoint,
            local_client: client,
            clients: Default::default(),
            ticket: ticket,
            state: ProcessSteps::Init,
            my_id: id,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Starting the key generation for {:?}", self.my_id);
        loop {
            match self.state {
                // Wait for the correct number of clients
                ProcessSteps::Init => {
                    let mut client_counter = 1;
                    info!("Start the local client");
                    info!("Need {:?} clients", self.ticket.max_shares);
                    let _ = self.local_client.auth(self.ticket.token.as_str()).await?;
                    loop {
                        let count = self.local_client.count().await?;
                        if count != client_counter {
                            info!(" new peer {:?}/{:?}", count + 1, self.ticket.max_shares);
                            if count == self.ticket.max_shares - 1 {
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
                ProcessSteps::CreateMesh => {
                    info!("Create the mesh");
                    // set out selves
                    let mut peers = self.local_client.peers().await?;
                    // Add this node
                    self.clients.insert(self.my_id, self.local_client.clone());
                    println!("?? should be here");
                    self.show_peers();

                    while let Some(peer) = peers.recv().await? {
                        info!("local peer item {:?}", peer);
                        if peer != self.my_id {
                            self.clients
                                .insert(peer, FrostyClient::connect(self.endpoint.clone(), peer));
                        };
                    }

                    self.show_peers();

                    self.each().await?;
                    return Ok(());
                }
            }
        }
    }

    fn show_peers(&self) {
        println!("______________________________");
        for (peer, client) in self.clients.iter() {
            println!("{:?} -- {:?}", peer, client.local());
        }
        println!("______________________________");
    }

    async fn each(&mut self) -> Result<()> {
        for (peer, client) in self.clients.iter() {
            let a = client.auth(self.ticket.token.as_str()).await?;
            warn!("{:?} -- {:?}", peer, a);
        }
        Ok(())
    }
}
