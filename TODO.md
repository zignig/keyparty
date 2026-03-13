# Next stuff

1. hook up the validator
1. add external irpc client for signing
1. send complete transaction back to the gossip with enum of state

# Outstanding stuff 

## Some todo stuff 

1. harden endpoints and process to make it hard to cheat.
1. add finished event to drop the key gen structs.
1. make the config file based on token name.
1. integrate rcan construction
    1. use as a rcan anchor , and sign subkeys
    1. distribute rcan chains

## Signing

- itegrate chat ? 
- show/process message and ask Y/N from the endpoint before signing
- deal with large messages (4Kb on gossip messages) , ?integrate blob distribution.
- check that there is quorum (min shares) before proceeding
    - this needs to be be a better system , separate timed task.

## quorum 

Maintaining quorm is harder than it looks.

1. send quorum and lost_quorum to the gossip channel.
1. need to use hello messages to watch for node changes.
1. add quorum messages , gained / lost through the gossip channel.

### Layout

[https://frost.zfnd.org/tutorial/signing.html](https://frost.zfnd.org/tutorial/signing.html) 

- local irpc client for signing works
- gossip channel to communnicate
- messages
    - hello
    - start signing , with UUID transaction id
    - round1 , make claim
    - round2 , collect
    - collect and sign
    - compare sigs and save

# Done

1. new config file just creates the secret key
1. Split into keyparty and signer.
1. change the wait times to minimise the sequence time.
1. check and save max and min shares
1. change name to keyparty.
1. break into another repo ( git filter-repo --path=tools/frosty/ )
1. move the key generation data into it's own struct.
1. have auth hooks that only allow participants
1. each node is a coordinator
1. new endpoint


## Done move secondary keys into the keygen, 

1. remove saving the primary key from the config
1. change the secondary key on the irpc to just set and get rather than a vec
1. at the start of the process, get the secondary public keys
1. map the identifiers on the _secondary_ keys to the primary keys.
1. use this map for the key generation.
1. then the signing gossip can just use the secondary keys straight up
