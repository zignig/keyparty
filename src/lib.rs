// Expose the keyparty sections as a lib.
// Integrate a client for remote signing against a keyparty cluter. 

// This is to expose the client interface to a program
// this makes keyparty a binary and a lib for clients

pub mod client;
pub mod keygen;
pub mod service;
pub mod ticket;
pub mod signing;

mod config;
mod cli;
mod id_store;

pub use cli::{Args,Command};
pub use config::Config;

pub use service::irpc::ServiceClient;

pub use client::KeyClient;
pub use service::ticket::ServiceTicket;
pub use service::caps::Caps;
pub use id_store::{IdentityApi,IdClient};