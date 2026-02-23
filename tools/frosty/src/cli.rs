use clap_derive::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
    #[arg(short, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,
}

#[derive(Parser, Debug)]
pub enum Command {
    Server {
        token: String,
        #[arg(long, default_value_t = 3)]
        max: u16,
        #[arg(long, default_value_t = 2)]
        min: u16,
    },
    Client {
        ticket: String,
    },
}
