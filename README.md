# Automatic frost distributed key signer

Following 
[https://frost.zfnd.org/tutorial/dkg.html](https://frost.zfnd.org/tutorial/dkg.html)

Using iroh , irpc it will create a set of key segments and endpoints and do all the hard stuff for you 

# Usage

## Generate a new key set

In the frost folder...
```
> cargo run generate "token"
```

where "token" is an auth string, this will give you a frost token 

```
frostysorelsfb2zbrj6dz7pvxqwnhsuhujiouvtdbbwhqw5b7hmeamtxaiytpojvqgaq
```

then from another machine or folder with the frosty binary

```
./keyparty join frostysorelsfb2zbrj6dz7pvxqwnhsuhujiouvtdbbwhqw5b7hmeamtxaiytpojvqgaq
```

The program will connect , and wait until there are enough friends and then run through the
distributed key generation sequence.

It will then create keys endpoint keys , with keymatter into frosty.toml.

## Running the signing party

On each of the Endpoints run 

```
keyparty sign
```

This should connect all the endpoints together, create a quorum and be able to sign incoming requests.


## Issue a service key

Keyparty provides a second endpoint to be able to remotely sign data. To do this a [rcan](https://github.com/n0-computer/rcan) needs to be issued to the client 

Run the client and then save the Endpoint ID , then issue a access ticket

```
keyparty issue <EndpointID>
```

This will return a ticket with a target and a RCAN blob 

```
keypartyhubltrt4kyzpyl5yetnmfdhqpsicvqhtfxho5vzvmz3odzbu5e3sakgmvqvn35za6vv4qenln5fmf
qkewa6us7y4j6vmv7trlhyrbl6z4qawczlrmqzgc5t2pf5dmztnnv4dizrwgrrwu53xmnzhi6lipjswe23zmr
5hgm3upbxtenbso5wtk6dcgryte33tnz5gc3buoftdgmtxgvrw2zddomzwin3fnjqxi5lhmvqwo6dwojvhmnd
opbuxa33omjxwm2jxmjvxez32oz3wk2dbmfqwcy3bmvrgczdhmzzxs3djofwwkylqgvyti2jvnbtwqzlfgn3w
22ljnyzge6ttgrztiytdg5shs2lymztxsnjxo5uwen3yn52wi4teor4hkztmnfywc5tspe2wk33wofyhkzbwm
z4gc3tlg5twe2thgvwgyzztgn2wu33yoz3xu3bvmrqxk6lgpbzgkzlb

```
This keyparty instance needs to offer the service. 

```
keyparty sign --service 
```
This flag is sticky, so this Endpoint will now run the service whenever it is run

## Attach the client 

Bind the ticket to the client.

```

client --ticket=<TICKET>

```
Now the client will connect and autenticate to the the Endpoint where the ticket was issued and sign 
data send to it.

## Ongoing works
 
Key party is functioning. however it still need more cleanup and work, 

Comments, Issues and Pull requests welcome.







