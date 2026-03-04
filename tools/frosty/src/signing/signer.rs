// This is the task that performs the actual signature

use bytes::Bytes;
use n0_error::{AnyError, Result};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, warn};

use crate::signing::{SigEvents, SigningMessage};

#[derive(Debug)]
pub struct SignerTask {
    //signer bits
    transaction_id: i64,
    message: Bytes,
    state: SigningMessage,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<SigningMessage>,
}

impl SignerTask {
    const TIME_OUT: Duration = Duration::from_secs(2);
    pub fn new(transaction_id: i64, message: Bytes, outgoing: Sender<SigningMessage>) -> Self {
        let (tx,rx) = tokio::sync::mpsc::channel::<SigEvents>(5);
        Self {
            transaction_id,
            message: message.clone(),
            state: SigningMessage::Start {
                transaction_id,
                message,
            },
            incoming: rx,
            outgoing,
        };
        ertaertaert
        // TODO fix this up .
    }

    pub async fn run(mut self) -> Result<i64, AnyError> {
        warn!(" Starting Signer Task {:#?}", &self.state);
        let timeout = Box::pin(tokio::time::sleep(SignerTask::TIME_OUT));
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                message  = self.incoming.recv() => { 
                    error!("signing interior {:#?}",message);
                }
                _ = timeout => {
                    warn!("timeout finished");
                    return Ok(self.transaction_id);
                }
            }
        }
    }
}
