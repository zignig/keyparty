// Cli entries

use bytes::Bytes;
use clap_derive::Parser;

#[derive(Parser, Clone, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
    #[arg(short, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Parser, Clone, Debug)]
pub enum Command {
    Generate {
        token: String,
        #[arg(long, default_value_t = 3)]
        max: u16,
        #[arg(long, default_value_t = 2)]
        min: u16,
    },
    Join {
        ticket: String,
    },
    Sign {
        message: Option<Bytes>,
    },
}
