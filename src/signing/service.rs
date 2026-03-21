// Second endpoint for a signing service
// should have auth ( base on rcan )
// and a signing irpc interface

// has
// Sign( BLOB )
// Signature ( Signature )
// Status
// Errors from the signing machine

use serde::{Deserialize, Serialize};
use tracing::info;

use irpc::{
    Client, WithChannels,
    channel::{mpsc, oneshot},
    rpc_requests,
};
use irpc_iroh::{IrohLazyRemoteConnection, read_request};

pub async fn run() {
    info!("run the external service");
}

// IRPC interface

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



