# Minicash - a cryptocurrency without blockchain

### The big picture
[Here](https://saav29.blogspot.gr/) you can have a big picture of the idea

    Bob (as every other peer) has a ledger with the balances of all the peers in the network.
    *What to do*:
    Bob wants to send 5 coins to Alice
    *How to do*:
    1. Bob takes a copy of the ledger.
    2. Makes the appropriate balance change.
    3. Signs it with his private key and sends it to all the peers.
    4. Each peer checks for the validity of the transcaction and if he finds it valid signs the 
    whole thing with his private key and sends it back to Bob.
    5. Bob collects all the data from the peers and puts them together in some kind of “block”.
    6. Sends this block back to all the peers.
    7. Each peer checks if the block received contains signatures from more than 50% of the total 
    peers and if yes then the transaction is valid so the peer renews his ledger according to the transcation.

### How a coin is born
    There is no mining. Each coin is mined every time a new GPG key fingerprint is introduced in the legder together with a proof of work. The proof of work 
    is an integer that when sticked at the end of the fingerprint with a “:” between them creates a string that its sha256 hash starts with 
    a specified number of zeros. For example: “<fingerprint>:<proof of work>”.
    So each time a new key fingerprint, accompanied with proof of work, enters the ledger a fresh coin is added on its balance. This way it’s easy for a 
    company to receive pre-generated 
    pubilc keys and create proof of work for them for some price.
    
### Components
- minicashd.py - The actual node that supports the network and the consesus
- minicash.py - The command line client that communicates with the server
- minicashPS.py - The peer server that is responsible for peer discovery

