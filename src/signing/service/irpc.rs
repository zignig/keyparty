// IRPC interface

use iroh::protocol::{AcceptError, ProtocolHandler};
use serde::{Deserialize, Serialize};


use irpc::{
    Client, WithChannels,
    channel::{mpsc, oneshot},
    rpc_requests,
};

// Irpc structs
#[derive(Debug, Serialize, Deserialize)]
struct ToSign {
    token: String,
}

#[rpc_requests(message = FrostyMessage)]
#[derive(Serialize, Deserialize, Debug)]
enum RemoteSigner {
    #[rpc(tx=oneshot::Sender<Result<(), String>>)]
    ToSign(ToSign),
}

#[derive(Debug)]
pub struct ServiceActor {
    name: String,
}

impl ProtocolHandler for ServiceActor {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        todo!()
    }
}