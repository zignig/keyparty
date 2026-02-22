# Automatic frost distributed key signer

Following 
[https://frost.zfnd.org/tutorial/dkg.html](https://frost.zfnd.org/tutorial/dkg.html)

Using iroh , irpc it will create a set of key segments and endpoints and do all the hard stuff for you 

## Usage

In the frost folder...
```
> cargo run server token 
```

where "token" is an auth string, this will give you a frost token 

```
frostysorelsfb2zbrj6dz7pvxqwnhsuhujiouvtdbbwhqw5b7hmeamtxaiytpojvqgaq
```

then from another machine or folder with the frosty binary

```
./frosty client frostysorelsfb2zbrj6dz7pvxqwnhsuhujiouvtdbbwhqw5b7hmeamtxaiytpojvqgaq
```

The program will connect , and wait until there are enough friends and then run through the
distributed key generation sequence.

## TODO 

Automated signing on [https://frost.zfnd.org/tutorial/signing.html](https://frost.zfnd.org/tutorial/signing.html) with a gossip channel is next.

Key share generation works for now.

This may be split into it's own repo.



