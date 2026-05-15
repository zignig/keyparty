// A cache of the rcan authenticated endpoints.

use std::{collections::BTreeMap, time::SystemTime};

use iroh::EndpointId;
use irpc::{Client, WithChannels, channel::oneshot, rpc_requests};
use rcan::Rcan;
use rcan::Capability;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::Sender;
use tracing::{debug, info, warn};

use crate::service::caps::Caps;

// Stored endpoint data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Status {
    Seen,
    Known,
    Apparent,
    Fren,
    Enemy,
    DestroyOnSight,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fren {
    id: EndpointId,
    status: Status,
    created: i64,
    rcan: Option<Rcan<Caps>>,
}

impl Fren {
    fn new(id: EndpointId) -> Self {
        Self {
            id: id,
            status: Status::Seen,
            created: chrono::Utc::now()
                .timestamp_nanos_opt()
                .expect("time does not exist"),
            rcan: None,
        }
    }

    // TDO add the rest of the permits
    pub fn can_sign(&self) -> bool { 
        if let Some(rcan) = self.rcan.clone() { 
            let base_cap = Caps::sign();
            let cap = rcan.capability();
            return cap.permits(&base_cap);
        }
        false
    }
}

// Irpc constructs

#[derive(Debug, Serialize, Deserialize)]
struct Get {
    key: EndpointId,
}

#[derive(Debug, Serialize, Deserialize)]
struct Remove {
    key: EndpointId,
}

#[derive(Debug, Serialize, Deserialize)]
struct Set {
    key: EndpointId,
    value: Fren,
}

#[derive(Debug, Serialize, Deserialize)]
struct Check {
    key: EndpointId,
}

#[derive(Debug, Serialize, Deserialize)]
struct List;

impl From<(EndpointId, Fren)> for Set {
    fn from((key, value): (EndpointId, Fren)) -> Self {
        Self { key, value }
    }
}

#[rpc_requests(message = IdentityMessage, no_rpc, no_spans)]
#[derive(Serialize, Deserialize, Debug)]
enum StorageProtocol {
    #[rpc(tx=oneshot::Sender<Option<Fren>>)]
    Get(Get),
    #[rpc(tx=oneshot::Sender<()>)]
    Remove(Remove),
    #[rpc(tx=oneshot::Sender<()>)]
    Set(Set),
    #[rpc(tx=oneshot::Sender<bool>)]
    Check(Check),
    #[rpc(tx=oneshot::Sender<Vec<Fren>>)]
    List(List),
}

struct Actor {
    recv: tokio::sync::mpsc::Receiver<IdentityMessage>,
    store: BTreeMap<EndpointId, Fren>,
}

impl Actor {
    async fn run(mut self) {
        while let Some(msg) = self.recv.recv().await {
            self.handle(msg).await;
        }
    }

    async fn handle(&mut self, msg: IdentityMessage) {
        match msg {
            IdentityMessage::Get(get) => {
                let WithChannels { tx, inner, .. } = get;
                let value = match self.store.get(&inner.key) {
                    Some(value) => Some(value.clone()),
                    None => None,
                };
                tx.send(value).await.ok();
            }

            IdentityMessage::Set(set) => {
                let WithChannels { tx, inner, .. } = set;
                self.store.insert(inner.key, inner.value);
                tx.send(()).await.ok();
            }

            IdentityMessage::Remove(remove) => {
                let WithChannels { tx, inner, .. } = remove;
                self.store.remove(&inner.key);
                tx.send(()).await.ok();
            }

            IdentityMessage::Check(check) => {
                let WithChannels { tx,inner , .. } = check;
                let is_good = match self.store.get(&inner.key) { 
                    Some(fren) => {
                        // Check to see if the rbac is still valid
                        let mut status = false;
                        if let Some(rcan) = fren.rcan.clone() { 
                            let time = SystemTime::now();
                            if rcan.expires().is_valid_at(time) {
                                status = true;
                            } else { 
                                status = false;
                            }
                        }
                        status
                    }
                    None => false
                };
                tx.send(is_good).await.ok();
            }

            IdentityMessage::List(list) => {
                let WithChannels { tx, .. } = list;
                let mut res: Vec<Fren> = Vec::new();
                for item in self.store.iter() {
                    let (_, item) = item;
                    res.push(item.clone());
                }
                tx.send(res).await.ok();
            }
        }
    }
}

pub struct IdentityApi {
    tx: Sender<IdentityMessage>,
}

impl IdentityApi {
    pub fn new() -> IdentityApi {
        let (tx, rx) = tokio::sync::mpsc::channel(5);
        let store = BTreeMap::default();
        let actor = Actor {
            recv: rx,
            store: store,
        };
        n0_future::task::spawn(actor.run());
        IdentityApi { tx: tx.clone() }
    }

    pub fn client(&self) -> IdClient {
        let tx = self.tx.clone();
        IdClient {
            inner: Client::local(tx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IdClient {
    inner: Client<StorageProtocol>,
}

impl IdClient {
    pub async fn get(&self, key: EndpointId) -> irpc::Result<Option<Fren>> {
        debug!("get id {} ", key);
        self.inner.rpc(Get { key }).await
    }

    pub async fn new_fren(&self, key: EndpointId, rcan: Rcan<Caps>) {
        match self.inner.rpc(Get { key }).await.unwrap() {
            Some(fren) => {
                debug!("existing fren => {:#?}", fren);
                return;
            }
            None => {
                let mut value = Fren::new(key);
                value.rcan = Some(rcan);
                self.inner.rpc(Set { key, value }).await.unwrap();
            }
        }
    }

    pub async fn check(&self,key: EndpointId) -> irpc::Result<bool> { 
        self.inner.rpc(Check { key }).await
    }
    
    pub async fn set(&self, key: EndpointId, value: Fren) -> irpc::Result<()> {
        self.inner.rpc(Set { key, value }).await
    }

    pub async fn remove(&self, key: EndpointId) -> irpc::Result<()> {
        self.inner.rpc(Remove { key }).await
    }

    pub async fn list(&self) -> irpc::Result<Vec<Fren>> {
        self.inner.rpc(List {}).await
    }
}
