// Expose the keyparty sections as a lib.
// Integrate a client for remote signing against a keyparty cluter. 


pub mod client;
mod service;
mod signing;
mod config;
mod cli;

pub use client::KeyClient;
