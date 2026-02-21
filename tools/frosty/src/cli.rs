// use clap::Parser;
use clap_derive::Parser;
// use iroh::EndpointId; 


#[derive(Parser,Debug)]
pub struct Args { 
    #[clap(subcommand)]
    pub command: Command 
}

#[derive(Parser,Debug)]
pub enum Command { 
    Server,
    Client
}

