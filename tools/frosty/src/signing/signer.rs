// This is the task that performs the actual signature

use bytes::Bytes;
use frost_ed25519::keys::KeyPackage;
use iroh::PublicKey;
use n0_error::{AnyError, Result};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, error, info, warn};

// s

use crate::signing::{GossipMessage, SigEvent, TransMessage};

// Simple verstion of the state (actual data is contained in messges)
#[derive(Debug)]
enum SState {
    Start,
    Check,
    Round1,
    Round1Gather,
    Round2,
    Round2Gather,
    Finished,
}


// TODO missing fields

// online nodes 
// round1/2 pacakges
// nonces
// just comms for now
#[derive(Debug)]
pub struct SignerTask {
    my_id: PublicKey,
    transaction_id: i64,
    message: Bytes,
    state: SState,
    incoming: Receiver<(PublicKey, TransMessage)>,
    outgoing: Sender<GossipMessage>,
    key_pacakge: Option<KeyPackage>,
}

impl SignerTask {
    const TIME_OUT: Duration = Duration::from_secs(2);
    pub async fn new(
        my_id: PublicKey,
        transaction_id: i64,
        message: Bytes,
        outgoing: Sender<GossipMessage>,
        key_pacakge: Option<KeyPackage>,
    ) -> (Sender<(PublicKey, TransMessage)>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel::<(PublicKey, TransMessage)>(5);
        let sel = Self {
            my_id,
            transaction_id,
            message: message.clone(),
            state: SState::Start,
            incoming: rx,
            outgoing,
            key_pacakge,
        };
        (tx, sel)
    }

    async fn send_out(&self, sigevent: SigEvent) -> Result<()> {
        let gmessage = GossipMessage::Event {
            message: TransMessage {
                transaction_id: self.transaction_id,
                event: sigevent,
            },
        };
        self.outgoing.send(gmessage).await.expect("bad out");
        Ok(())
    }

    async fn handle_event(&mut self, event: (PublicKey, TransMessage)) -> Result<(), AnyError> {
        debug!("{:?} ==> {:#?}", &self.state, &event);
        let ( id , mess ) = event;
        // TODO fix this to track both state and message switch.
        self.send_out(SigEvent::Compare).await?;
        match self.state {
            SState::Start => {
                info!("[signer] Start");
                self.state = SState::Check;
            }
            SState::Check => {
                info!("[signer] Check");
                self.state = SState::Round1;
            }
            SState::Round1 => {
                info!("[signer] Round1");
                self.state = SState::Round1Gather
            },
            SState::Round1Gather => {
                info!("[signer] Round1 Gather");
                info!("{:} {:?}",id.fmt_short(),mess);
                self.state = SState::Round2;
            },
            SState::Round2 => {},
            SState::Round2Gather => todo!(),
            SState::Finished => todo!(),
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
