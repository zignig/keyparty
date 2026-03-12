// Second endpoint for a signing service 
// should have auth ( base on rcan )
// and a signing irpc interface 

// has 
// Sign( BLOB )
// Signature ( Signature )
// Status 
// Errors from the signing machine

use tracing::info;

pub async fn run() { 
    info!("run the external service");
}

// IRPC interface
