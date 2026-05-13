# Outstanding stuff 

1. u64 as time stamp seems to collide, perhaps UUID after all. - random i64 works fine.
1. check TODOs
1. clean up logging -- nearly.
1. fix id_client and rcan setup.

# Service

1. turn auth into a local rpc
    1. need to validate the rcan from the id_service
    1. check rcan capabilities from the id_service

# Next stuff

1. hook up the validator
1. send complete transaction back to the gossip with enum of state


## Some todo stuff 

1. harden endpoints and process to make it hard to cheat.
1. add finished event to drop the key gen structs.
1. make the config file based on token name.
1. integrate rcan construction
    1. use as a rcan anchor , and sign subkeys # partial
    1. distribute rcan chains

## Signing

- show/process message and ask Y/N from the endpoint before signing
    - itegrate into validator
- check that there is quorum (min shares) before proceeding
    - this needs to be be a better system , separate timed task.

### Layout

[https://frost.zfnd.org/tutorial/signing.html](https://frost.zfnd.org/tutorial/signing.html) 

- local irpc client for signing works
    - ongoing
- gossip channel to communnicate
    - working
- messages
    - hello
    - start signing , with UUID transaction id
        - using 64 bit time stamp , perhaps the has of it.
    - round1 , make claim
    - round2 , collect
    - collect and sign
    - compare sigs and save
        - this needs more thought

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
1. rcan auth is working, it's only one layer deep , but seems to be working
1. **add** defence againt the dark arts.
1. add external irpc client for signing
1. send quorum and lost_quorum to the gossip channel.
    1. extract the gossip into it's own module and add state
1. add quorum messages , gained / lost through the gossip channel.


## Done move secondary keys into the keygen, 

1. remove saving the primary key from the config
1. change the secondary key on the irpc to just set and get rather than a vec
1. at the start of the process, get the secondary public keys
1. map the identifiers on the _secondary_ keys to the primary keys.
1. use this map for the key generation.
1. then the signing gossip can just use the secondary keys straight up

## quorum 

Maintaining quorm is harder than it looks.
1. need to use hello messages to watch for node changes.
    1. gossip does this for us
