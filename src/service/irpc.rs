// IRPC interface

pub const ALPN: &[u8] = b"keyparty/service/0";

use frost_ed25519::Signature;
use iroh::{
    Endpoint,
    protocol::{AcceptError, ProtocolHandler},
};
use irpc_iroh::{IrohLazyRemoteConnection, read_request};
use serde::{Deserialize, Serialize};

use irpc::{Client, WithChannels, channel::oneshot, rpc_requests};

use tokio::sync::mpsc::Sender;
use tracing::{debug, info};

use crate::IdClient;

// Service mesasges
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SigStatus {
    Sig { sig: Signature },
    SigError { error: String },
}

pub type Reply = oneshot::Sender<SigStatus>;

#[derive(Debug)]
pub struct ServiceMessage {
    message: String,
    pub reply: Reply,
}

impl ServiceMessage {
    pub fn new(message: String, reply: Reply) -> Self {
        Self { message, reply }
    }

    pub fn message(&self) -> String {
        self.message.clone()
    }

    pub async fn send(self, sig: SigStatus) {
        let _ = self.reply.send(sig).await;
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
    #[rpc(tx=oneshot::Sender<Result<SigStatus,String>>)]
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
        // if let Some(fren) = self.id_client.get(conn.remote_id()).await.unwrap() {
        // info!("{:?}", fren);
        // }
        let id = conn.remote_id();
        if self.id_client.check(id).await.expect("rcan expired") {
            info!("rcan good for {}",id.fmt_short());
        }else { 
            conn.close(1u32.into(), b"invalid message");
            return Ok(());
        };

        while let Some(msg) = read_request::<SignerProtocol>(&conn).await? {
            match msg {
                SigningMessage::ToSign(msg) => {
                    let WithChannels { inner, tx, .. } = msg;
                    // Send to the signer
                    let (smtx, smrx) = oneshot::channel();
                    let out_mess = ServiceMessage::new(inner.data.clone(), smtx);
                    let _ = self.service_out.send(out_mess).await;
                    let reply_string = smrx.await.unwrap();
                    debug!("back from the signer {:#?}", reply_string);
                    tx.send(Ok(reply_string)).await.ok();
                }
            }
        }
        info!("Client {} disconnectd", conn.remote_id().fmt_short());
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

    pub async fn sign(&self, data: &str) -> Result<SigStatus, anyhow::Error> {
        self.inner
            .rpc(ToSign {
                data: data.to_string(),
            })
            .await?
            .map_err(|err| anyhow::anyhow!(err))
    }
}
