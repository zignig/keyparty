// Expose the keyparty sections as a lib.
// Integrate a client for remote signing against a keyparty cluter.

// This is to expose the client interface to a program
// this makes keyparty a binary and a lib for clients


//make clippy be annoying
// #![warn(missing_docs)]



pub mod client;
pub mod keygen;
pub mod service;
pub mod signing;
pub mod ticket;

mod cli;
mod config;
mod id_store;

pub use cli::{Args, Command};
pub use client::KeyClient;
pub use config::Config;
pub use id_store::{IdClient, IdentityApi};
pub use service::caps::Caps;
pub use service::irpc::ServiceClient;
pub use service::ticket::ServiceTicket;
