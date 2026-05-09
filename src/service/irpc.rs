// IRPC interface

pub const ALPN: &[u8] = b"keyparty/service/0";

use iroh::{
    Endpoint,
    protocol::{AcceptError, ProtocolHandler},
};
use irpc_iroh::{IrohLazyRemoteConnection, read_request};
use serde::{Deserialize, Serialize};

use irpc::{
    Client, WithChannels,
    channel::{mpsc, oneshot},
    rpc_requests,
};
use tracing::info;

// Irpc structs
#[derive(Debug, Serialize, Deserialize)]
struct ToSign {
    data: String,
}

#[rpc_requests(message = SigningMessage)]
#[derive(Serialize, Deserialize, Debug)]
enum SignerProtocol {
    #[rpc(tx=oneshot::Sender<Result<(), String>>)]
    ToSign(ToSign),
}

#[derive(Debug)]
pub struct ServiceActor {
    active: bool,
}

impl ServiceActor {
    pub fn new() -> Self {
        Self { active: true }
    }
}

impl ProtocolHandler for ServiceActor {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        while let Some(msg) = read_request::<SignerProtocol>(&conn).await? {
            match msg {
                SigningMessage::ToSign(msg) => {
                    let WithChannels { inner, tx, .. } = msg;
                    info!("To Sign {:#?}", inner);
                    tx.send(Ok(())).await.ok();
                }
            }
        }
        Ok(())
    }
}

pub struct ServiceClient {
    inner: Client<SignerProtocol>,
}

impl ServiceClient {
    pub fn connect(endpoint: Endpoint, addr: impl Into<iroh::EndpointAddr>) -> ServiceClient {
        let conn = IrohLazyRemoteConnection::new(endpoint, addr.into(), ALPN.to_vec());
        ServiceClient {
            inner: Client::boxed(conn),
        }
    }

    pub async fn sign(&self, data: &str) -> Result<(), anyhow::Error> {
        self.inner
            .rpc(ToSign {
                data: data.to_string(),
            })
            .await?
            .map_err(|err| anyhow::anyhow!(err))
    }
}
