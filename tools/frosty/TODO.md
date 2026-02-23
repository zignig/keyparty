# Some todo stuff 

1. new config file just creates the secret key
1. make the config file based on token name.
1. Split into keyparty and signer.
1. integrate rcan construction
    1. use as a rcan anchor , and sign subkeys
    2. distribute rcan chains
1. check and save max and min shares
1. change the wait times to minimise the sequence time.

## Signing

- new endpoint
- have auth hooks that only allow participants
- itegrate chat ? 
- show/process message and ask Y/N from the endpoint before signing
- each node is a coordinator
- deal with large messages (4Kb on gossip messages) , ?integrate blob distribution.
- check that there is quorum (min shares) before proceeding

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


