use clap_derive::Parser;


#[derive(Parser,Debug)]
pub struct Args { 
    #[clap(subcommand)]
    pub command: Command 
}

#[derive(Parser,Debug)]
pub enum Command { 
    Server,
    Client { ticket : String }
}

