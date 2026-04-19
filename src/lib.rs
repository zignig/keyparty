// Expose the keyparty sections as a lib.
// Integrate a client for remote signing against a keyparty cluter. 

// This is to expose the client interface to a program
// this makes keyparty a binary and a lib for clients

pub mod client;

mod service;
mod signing;
mod config;
mod cli;

pub use client::KeyClient;
pub use service::ticket::ServiceTicket;
pub use service::caps::Caps;
