// IRPC interface

pub const ALPN: &[u8] = b"keyparty/service/0";

use iroh::{
    Endpoint,
    protocol::{AcceptError, ProtocolHandler},
};
use irpc_iroh::{IrohLazyRemoteConnection, read_request};
use serde::{Deserialize, Serialize};

use irpc::{Client, WithChannels, channel::oneshot, rpc_requests};

use tokio::sync::mpsc::Sender;
use tracing::{error, info};

use crate::IdClient;

// Service mesasges

pub type Reply = oneshot::Sender<String>;

#[derive(Debug)]
pub struct ServiceMessage {
    message: String,
    reply: Reply,
}

impl ServiceMessage {
    pub fn new(message: String, reply: Reply) -> Self {
        Self { message, reply }
    }

    pub fn message(&self) -> String { 
        self.message.clone()
    }

    pub async fn reply(self, data: String) {
        let _ = self.reply.send(data).await;
    }
}

// Irpc structs
#[derive(Debug, Serialize, Deserialize)]
struct ToSign {
    data: String,
}

#[rpc_requests(message = SigningMessage)]
#[derive(Serialize, Deserialize, Debug)]
enum SignerProtocol {
    #[rpc(tx=oneshot::Sender<Result<String,String>>)]
    ToSign(ToSign),
}

#[derive(Debug)]
pub struct ServiceActor {
    id_client: IdClient,
    service_out: Sender<ServiceMessage>,
}

impl ServiceActor {
    pub fn new(id_client: IdClient, service_out: Sender<ServiceMessage>) -> Self {
        Self {
            id_client,
            service_out,
        }
    }
}

impl ProtocolHandler for ServiceActor {
    async fn accept(&self, conn: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        if let Some(fren) = self.id_client.get(conn.remote_id()).await.unwrap() {
            info!("{:?}", fren);
        }
        while let Some(msg) = read_request::<SignerProtocol>(&conn).await? {
            match msg {
                SigningMessage::ToSign(msg) => {
                    let WithChannels { inner, tx, .. } = msg;
                    // Send to the signer
                    let (smtx, smrx) = oneshot::channel();
                    let out_mess = ServiceMessage::new(inner.data.clone(), smtx);
                    let _ = self.service_out.send(out_mess).await;
                    let reply_string = smrx.await.unwrap();
                    error!("back from the signer {:#?}",reply_string);
                    tx.send(Ok(reply_string)).await.ok();
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

    pub async fn sign(&self, data: &str) -> Result<String, anyhow::Error> {
        self.inner
            .rpc(ToSign {
                data: data.to_string(),
            })
            .await?
            .map_err(|err| anyhow::anyhow!(err))
    }

}
