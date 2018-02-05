# Minicash
##### *A cryptocurrency without blockchain*
--------------------------------------------
&nbsp;
### What is Minicash?
As the title says Minicash is a cryptocurrency that doesn't use blockchain but instead uses a ledger of addresses and balances. It uses GPG asymmetric cryptography for secure communication and "voting". Voting occurs on two cases, first when a new key requests to be introduced to the ledger and second when a transaction is requested. For a key to be valid to enter the ledger a proof of work must be provided. This needs many sha256 calculations and regulates the difficulty of key creation. When a key enters the ledger, 10 new coins are created and assigned to this key.

### Why to choose Minicash?
Most of the current cryptocurrencies use the blockchain which requires huge free space to dedicate in your hard disk. Running a full node is important and one way road for the security. Minicash doesn't have this problem as the ledger and GPG key's size is not big enough to be noticed. Also Minicash concentrates on simplicity. Without a blockchain no resource hungry calculations need to be done.

### The big picture
Bob (as every other peer) has a ledger with the balances of all the peers in the network.
How does he send 5 coins to Alice?
1. Bob takes a copy of the ledger.
2. Makes the appropriate balance change.
3. Signs it with his private key and sends it to all the peers.
4. Each peer checks for the validity of the transcaction and if he finds it valid signs the whole message with his private key and sends it back to Bob.
5. Bob collects all the data from the peers and puts them together in  a new message.
6. Sends this message back to all the peers.
7. Each peer checks if the block received contains signatures from more than 66% of the total peers and if yes then the transaction is valid so the peer renews his ledger according to the transcation.
&nbsp;

### How are coins created?
There is no mining. Coins are born every time a new GPG key fingerprint is introduced in the legder together with a proof of work. The proof of work is an integer that when sticked to the end of the fingerprint with a “_” between them creates a string that its sha256 hash starts with a specified number of zeros. For example: “fingerprint"_"proof of work”.
So each time a new key fingerprint, accompanied with proof of work, enters the ledger 10 fresh coins are added on its balance.

### How to install?
Minicash has been tested working on Linux with Python 3.5 and Python 3.6
1. You can download it from [Pypi](https://pypi.org/search/?q=Minicash). Decompress the file in a folder and run `python setup.py install` from that folder.
2. Alternatively you can download it straight from pip running `pip3 install Minicash`
3. There are alse portable executable files to use [here](https://github.com/saavedra29/Minicash/releases). Download the portable zip archive and extract the binary files inside it to the `/usr/local/bin` folder.

*Important notes*:
- Using a virtualenv is strongly adviced. 
- Requires **dirmngr** to be installed from your Linux distribution's repositories for Minicash to be able to sign using the local gpg keyring.
- Minicash uses the specific [MinicashPeerServer]( https://github.com/saavedra29/MinicashPeerServer) software for network peer discovery. You will need it if you intend to use Minicash on local networks.

### Components
============= 

#### minicashd (The node's server - daemon)
    (minicashPy3-5Env) aris@adesk MinicashWorld-> minicashd -h
    usage: minicashd [-h] [--loglevel LOGLEVEL] [--peerserver PEERSERVER]
                     [--homedir HOMEDIR] [--nopid]
                     password
    
    positional arguments:
      password              Common password for all the GNUPG keys
    
    optional arguments:
      -h, --help            show this help message and exit
      --loglevel LOGLEVEL   Level of logging in file minicash.log
      --peerserver PEERSERVER
                            IP of the peer discovery server
      --homedir HOMEDIR     Directory inside which .minicash should be located
  
#### minicash (The node's command line client)
    (minicashPy3-5Env) aris@adesk MinicashWorld-> minicash -h
    usage: minicash [-h]
                    {listpeers,getledger,introducekeytoledger,listlocalkeys,gen-pow,add-key,getbalances,getallbalances,stop,send}
                    ...
    
    positional arguments:
      {listpeers,getledger,introducekeytoledger,listlocalkeys,gen-pow,add-key,getbalances,getallbalances,stop,send}
        listpeers           List all online nodes in the network
        getledger           Print the current ledger
        introducekeytoledger
                            Introduce the key to the ledger
        listlocalkeys       List all local keys fingerprints
        gen-pow             Create proof of work
        add-key             Add existing key in the node
        getbalances         Get the balances
        getallbalances      Get the balances of all the nodes
        stop                Stop the server
        send                Pay to other key
    
    optional arguments:
      -h, --help            show this help message and exit
  
#### quickDataGen (A script for easy and fast keys and configuration generation)

    (minicashPy3-5Env) aris@adesk MinicashWorld-> quickDataGen -h
    usage: quickDataGen [-h] keysnum difficulty password homedir [homedir ...]
    
    positional arguments:
      keysnum     Number of keys to create
      difficulty  Number of zeros hash start
      password    The gpg private key password
      homedir     Directory inside which .minicash folder should be created
    
    optional arguments:
      -h, --help  show this help message and exit
&nbsp;

### How to use?
*Prerequisites*:
- Decide a **common** password that you'll be always using for **every** new gpg key you will create. Let's call it "mypassword"
- Decide **inside which** folder you want the ".minicash" configuration folder to be placed. Let's name it "myinstallationfolderpath" (default is the linux user home folder).
- You need to do port forwarding at your router so that it sends all port 2222 incoming data to your node.
- If you run a peer discovery server on the same computer you run a server node make sure to pass the --peerserver argument with the IP and not just "localhost".
- **Attention**: Every path you pass to the command line must be the **full** path. 
&nbsp;

##### *The hard way*:
1. Make sure you are connected to the Internet.
2. Run `minicashd --homedir <myinstallationfolderpath> <mypassword>` to boot the daemon.
3. Create a GPG key pair: `gpg --homedir <myinstallationfolderpath>/.minicash/.gnupg --gen-key` using "mypassword" when asked for password.
4. Run `gpg --homedir <myinstallationfolderpath>/.minicash/.gnupg --list-keys --keyid-format long | grep -Po 'pub   rsa2048/\K[A-Z0-9]*'` and note down the 16 character public key fingerprint of the output. Let's call it "myfingerprint".
5. Create proof of work running `minicash gen-pow 7 <myfingerprint>`. Wait for a while and let's name the output "proof".
6. Add the key with the proof to minicash running `minicash add-key <myfingerprint> <proof>`.
7. Introduce the key to the global ledger running `minicash introducekeytoledger <myfingerprint>`.
8. Now you are ready to do your first transaction. You have 10 coins since your key was introduced to the ledger. Say you want to send 1.504 coins to the fingerpint 1559CBEBCB7E72B6. Run `minicash send <myfingerprint> 1559CBEBCB7E72B6 1.504`.
9. Congratulations! You've done your first transaction!

##### *The lazy way*:
1. Run `quickDataGen 1 7 <mypassword> <myinstallationfolderpath>`
2. Run `minicashd --homedir <myinstallationfolderpath> <mypassword>` to boot the daemon.
3. Run `minicash listlocalkeys` and note down your 16 character fingerprint. Let's call it "myfingerprint"
4. Follow the "The hard way" above from step 7 until the end.
&nbsp;

### Help
On every case you can run `minicash -h` to list the available options.
Don't hesitate to email me on arisgold29@gmail.com with "minicash" as title in case you have any questions.
