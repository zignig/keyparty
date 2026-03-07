// This is the task that performs the actual signature

use bytes::Bytes;
use frost_ed25519::keys::KeyPackage;
use iroh::PublicKey;
use n0_error::{AnyError, Result};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{error, info, warn};

// s

use crate::signing::{SigEvents, SigningMessage};

// Simple verstion of the state (actual data is contained in messges)
#[derive(Debug)]
enum SState {
    Start,
    Check,
}

#[derive(Debug)]
pub struct SignerTask {
    my_id: PublicKey,
    transaction_id: i64,
    message: Bytes,
    state: SState,
    incoming: Receiver<SigEvents>,
    outgoing: Sender<SigningMessage>,
    key_pacakge: Option<KeyPackage>,
}

impl SignerTask {
    const TIME_OUT: Duration = Duration::from_secs(20);
    pub async fn new(
        my_id: PublicKey,
        transaction_id: i64,
        message: Bytes,
        outgoing: Sender<SigningMessage>,
        key_pacakge: Option<KeyPackage>,
    ) -> (Sender<SigEvents>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel::<SigEvents>(5);
        let sel = Self {
            my_id,
            transaction_id,
            message: message.clone(),
            state: SState::Start,
            incoming: rx,
            outgoing,
            key_pacakge,
        };
        // Send the inital event for local (gossip does not send to local)
        // tx.send(SigEvents {
        //     id: my_id,
        //     message: SigningMessage::Start {
        //         transaction_id,
        //         message,
        //     },
        // })
        // .await
        // .expect("start event fail");
        (tx, sel)
    }

    async fn send_out(&self, mess: SigningMessage) -> Result<()> {
        info!("out message");
        self.outgoing.send(mess).await.expect("bad out");
        info!("out complete");
        Ok(())
    }

    async fn handle_event(&mut self, event: SigEvents) -> Result<(), AnyError> {
        info!("{:?} ==> {:#?}", &self.state, &event);
        match self.state {
            SState::Start => {
                error!("start transaction {:?}", &self.transaction_id);
                match &event.message {
                    SigningMessage::Init => todo!(),
                    SigningMessage::Hello { timestamp } => todo!(),
                    SigningMessage::Waves => todo!(),
                    SigningMessage::Start { .. } => {
                        info!("pass transaction on");
                        self.send_out(event.message.clone()).await?;
                        self.state = SState::Check;
                    }
                    SigningMessage::Round1 { transaction_id } => todo!(),
                    SigningMessage::Round2 { transaction_id } => todo!(),
                    SigningMessage::Collect { transaction_id } => todo!(),
                    SigningMessage::Compare { transaction_id } => todo!(),
                    SigningMessage::PeerDown => todo!(),
                    SigningMessage::PeerUp => todo!(),
                }
            }
            SState::Check => {
                error!("Check mode for {:?}", &self.transaction_id);
                self.send_out(SigningMessage::Round1 {
                    transaction_id: self.transaction_id,
                })
                .await?;
            }
        }
        Ok(())
    }

    pub async fn run(mut self) -> Result<i64, AnyError> {
        warn!(" Starting Signer Task {:#?}", &self.state);
        let timeout = tokio::time::sleep(SignerTask::TIME_OUT);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                Some(event)  = self.incoming.recv() => {
                    // error!("signing interior {:#?}",&event);
                    self.handle_event(event).await?;
                },
                _ = &mut timeout => {
                    warn!("timeout finished");
                    return Ok(self.transaction_id);
                },

            }
        }
    }
}
