import signal
import logging
import threading
import socketserver
import socket
import os
import re
import argparse
import json
import gnupg
import asyncio
import random
import time
from utils.protocols import sendToMany
from utils.protocols import sendReceiveToMany
from jsonrpc import JSONRPCResponseManager, dispatcher
from daemon import DaemonContext
from daemon.daemon import DaemonOSEnvironmentError
from utils.client import simpleSend
from utils.checksum import isValidProof
from utils.checksum import getmd5 
from utils.parsers import isValidLedgerResponseFormat
from utils.parsers import PacketParser

# Global variables
noPid = False
PIDPATH = "/tmp/minicashd.pid"
G_privateKeys = {}
G_configuration = {}
G_peers = {}
G_ledger = {}
G_remoteIps = set()
HOMEDIR = ''
MINICASHDIR = ''
GPGDIR = ''


def getRemoteIps():
    remoteips = []
    for proofIp in G_peers.values():
        remoteips.append(proofIp['Ip'])
    return set(remoteips)
    

# take nonce and ledger and return dictionary with local keys as keys and the signatures of the
# ledger's md5 as values
def signLedgerLocalKeys(ledger):
    dumpedLedger = json.dumps(ledger, sort_keys=True)
    dataToSign = getmd5(dumpedLedger)
    # Sign the checksum with all the local keys
    signaturesDict = {}
    gpg = gnupg.GPG(gnupghome=GPGDIR)
    for searchingKey in G_privateKeys.keys():
        for listedKey in gpg.list_keys(True):
            listedKey = listedKey['keyid']
            if listedKey == searchingKey:
                signedData = gpg.sign(dataToSign, keyid=searchingKey,
                    passphrase='mylongminicashsillypassphrase')
                signaturesDict[searchingKey] = str(signedData)
    return signaturesDict
    

def getConsesusValidLedger(ledgerResponces):
    # Filter out the wrongly formatted responses
    filteredResponses = []
    # Dictionary with dumped ledgers for the keys and lists of really signed keys as the values
    # Example: {'{'aris':23, 'Nick':40}': ['3EE3FD7A50CBD975', '8D972AA78B46CBF7'],..}
    ledgersWithSignedKeys = {}
    for response in ledgerResponces:
        # Check for the response format
        parser = PacketParser(response)
        if not parser.isPacketValid():
            logging.warning('Invalid packet => {}'.format(parser.errorMessage))
            continue
        if not parser.type == 'RESP_LEDGER':
            logging.warning('Invalid packet, RESP_LEDGER expected')
            continue
        filteredResponses.append(response)
    for response in filteredResponses:
        ledger = json.dumps(response['Data']['Ledger'], sort_keys=True)
        signedKeys = getKeysThatSignedLedger(response)
        logging.info('-------- Filtered ledger and keys that signed it -------')
        logging.info('Ledger: {}'.format(ledger))
        logging.info('Keys: {}'.format(signedKeys))
        if ledger not in ledgersWithSignedKeys:
            ledgersWithSignedKeys[ledger] = signedKeys
        else:
            ledgersWithSignedKeys[ledger].extend(signedKeys)
        setKeys = set(ledgersWithSignedKeys[ledger])
        ledgersWithSignedKeys[ledger] = list(setKeys)
    numberOfKeysThatVote = len(G_peers) 
    logging.info('-------- VOTING TABLE ---------')
    logging.info('{} keys voting!'.format(numberOfKeysThatVote))
    for ledger in ledgersWithSignedKeys:
        logging.warning('LEDGER: {}\n\t\t\tVOTERS: {}'.format(ledger, len(ledgersWithSignedKeys[ledger])))
    for ledger in ledgersWithSignedKeys:
        positiveVotes = len(ledgersWithSignedKeys[ledger])
        if positiveVotes > 67/100 * numberOfKeysThatVote:
            logging.info('-------- NEW VOTED LEDGER ----------')
            logging.info('Ledger: {}'.format(ledger))
            logging.info('{} keys signed for the ledger out of {} keys that voted'.format(
                            positiveVotes, numberOfKeysThatVote))
            logging.info('Success percentage: {}%'.format(str(positiveVotes / numberOfKeysThatVote * 100)))
            return json.loads(ledger)
    logging.warning('-------- NO CONSESUS FOR A LEDGER -------')
    return None

# Takes the response and nonce and return a list with the keys that really signed the ledger
def getKeysThatSignedLedger(response):
    gpg = gnupg.GPG(gnupghome=GPGDIR)
    ledger = response['Data']['Ledger']
    ledger = json.dumps(ledger, sort_keys=True)
    dataToCheck= getmd5(ledger)
    
    validKeys = []
    keysSignaturesDict = response['Data']['Signatures']
    # Loop in signatures
    for fprint in keysSignaturesDict:
        for key in gpg.list_keys():
            if key['keyid'] == fprint:
                logging.info('Checking key {}..'.format(fprint))
                foundKey = True
                break
        if not 'foundKey' in locals():
            continue
        signature = keysSignaturesDict[fprint]
        verification = gpg.verify(signature)
        if verification.key_id != fprint:
            logging.info('Wrong verification keyid')
            continue
        if verification.status != 'signature valid':
            logging.info('Not valid signature')
            continue
        messagePattern = re.compile('(?<=\n\n)\w+')
        extractFromSignature = messagePattern.search(signature)
        if extractFromSignature is None:
            logging.info('Wrong signature format')
            continue
        result =  extractFromSignature.group(0)
        if result != dataToCheck:
            logging.info('Signed data is not the expected')
            logging.info('Result: {}'.format(result))
            logging.info('dataToCheck: {}'.format(dataToCheck))
            continue
        validKeys.append(fprint)
    return validKeys


def sendHello(fprint=None, proof=None):
    # Send hello to the other peers
    hello = {'Type': 'HELLO', 'Data': []}
    if fprint == None:
        for key in G_privateKeys.keys():
            hello['Data'].append({'Fingerprint': key, 'ProofOfWork': G_privateKeys[key]})
    else:
        hello['Data'].append({'Fingerprint': fprint, 'ProofOfWork': proof})
    hello = json.dumps(hello)
    simpleSend(hello, getRemoteIps(), 2222, timeout=1)
    for ip in getRemoteIps():
        logging.info('Hello sent to {}'.format(ip))



# COMMAND LINE FUNCTIONS
def init(kwargs):
    # Create .minicash folder if not existing and enter it
    try:
        os.chdir(kwargs['Homedir'])
        if not os.path.isdir('.minicash'):
            os.mkdir('.minicash')
        os.chdir(kwargs['Homedir'] + '/.minicash')
    except OSError as e:
        return {'Fail': {'Reason': 'IOError accessing data folder', 'Message': str(e)}}

    # Create configuration file
    if not os.path.isfile('config.json'):
        config = {
            'PEER_SERVER': {'Ip': '192.168.0.20', 'Port': '9999'},
            'KEY_SERVERS': {'adresses': [
                'pgp.mit.edu',
                'sks-keyservers.net',
                'pool.sks-keyservers.net',
                'eu.pool.sks-keyservers.net'
            ]}
        }
        jsonedConfig = json.dumps(config, indent=4)
        try:
            with open('config.json', 'w') as conffile:
                conffile.write(jsonedConfig)
        except OSError as e:
            return {'Fail': {'Reason': 'Error writting initial configuration', 'Message': str(e)}}

    # Take care of key files and .gnupg folder
    try:
        if not os.path.isfile('private_keys.json'):
            with open('private_keys.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isfile('peers.json'):
            with open('peers.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isfile('ledger.json'):
            with open('ledger.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isfile('minicash.log'):
            with open('minicash.log', 'w') as infile:
                infile.write('')
        if not os.path.isdir('.gnupg'):
            os.mkdir('.gnupg')
            os.chmod('.gnupg', 0o700)
    except OSError as e:
        return {'Fail': {'Reason': 'OSError', 'Message': str(e)}}

    return {'Success': {}}


def addToKeyring(fingerprint):
    gpg = gnupg.GPG(gnupghome=GPGDIR)
    for key in gpg.list_keys():
        if key['keyid'] == fingerprint:
            return True
    # Receive key from key server
    servers = G_configuration['KEY_SERVERS']['adresses']
    for keyserver in servers:
        response = gpg.recv_keys(keyserver, '0x' + fingerprint).stderr
        logging.info('Sent {} to {} keyserver and got response: {}'.format(fingerprint, keyserver, response))
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            return True
    return False
    

def addKey(kwargs):
    fingerprint = kwargs['key']
    proof = kwargs['pow']
    if 'gpgdir' in kwargs:
        gpg = gnupg.GPG(gnupghome=kwargs['gpgdir'])
    else:
        gpg = gnupg.GPG(gnupghome=GPGDIR)

    foundkey = None
    for key in gpg.list_keys(True):
        if key['keyid'] == fingerprint:
            foundkey = key
    if foundkey == None:
        return {'Fail': {'Reason': 'Key not found in gpg database'}}

    # Check if pow is invalid for the key
    if not isValidProof(fingerprint, proof):
        return {'Fail': {'Reason': 'Wrong proof of work'}}

    # Add the key to the privateKeys
    global G_privateKeys
    G_privateKeys[fingerprint] = proof

    # Return if uploading to server is not requested
    # if 'noupload' in kwargs:
    if kwargs['noupload'] == True:
        logging.warning('Adding key {} without uploading to key server'.format(fingerprint))
        return {'Success': {}}

    # Upload key to the key server
    servers = G_configuration['KEY_SERVERS']['adresses']

    for keyserver in servers:
        response = gpg.send_keys(keyserver, '0x' + fingerprint).stderr
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            sendHello(fingerprint, proof)

            # UPDATE ALSO THE PEER SERVER
            peersRequest = {'Type': 'REGUP', 'Keys': []}
            for key in G_privateKeys.keys():
                peersRequest['Keys'].append({'Fingerprint': key, 'ProofOfWork': G_privateKeys[key]})
            peersRequest = json.dumps(peersRequest).encode('utf-8')

            peersRequestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIp = G_configuration['PEER_SERVER']['Ip']
            serverPort = G_configuration['PEER_SERVER']['Port']
            logging.info('connecting to server {}:{}'.format(serverIp, serverPort))
            try:
                peersRequestSock.connect((serverIp, int(serverPort)))
                peersRequestSock.sendall(peersRequest)
                peersRequestSock.shutdown(socket.SHUT_WR)
                peersResponse = str(peersRequestSock.recv(65535), 'utf-8')
            except OSError as e:
                logging.info('Problem connecting to the peer server: {}\nExiting..'.format(e))
                stop()
            finally:
                peersRequestSock.close()

            try:
                peersResponse = json.loads(peersResponse)
            except json.JSONDecodeError as e:
                logging.error('Json error on peers server response: {}\nExiting..'.format(e))
                stop()

            if peersResponse['Response'] == 'Fail':
                logging.error('Could not receive valid data from the peer server\n'
                      '{}\nExiting..'.format(peersResponse['Reason']))
                stop()
            
            return {'Success': {}}
    
    del(G_privateKeys[fingerprint])
    return {'Fail': {'Reason': 'Problem uploading key to server'}}
    

def listPeers(kwargs):
    return {'Success': G_peers}


def listLocalKeys(kwargs):
    return {'Success': G_privateKeys}


def getBalances(kwargs):
    return kwargs


def getLedger(kwargs):
    return {'Success': G_ledger}


def pay(kwargs):
    return kwargs


def interruptHandler(signum, frame):
    stop()


def introduceKeyToLedger(kwargs):
    return kwargs
    """
    key = kwargs['keytoadd']
    if key not in G_privateKeys:
        return {'Fail': {'Reason': 'Invalid key'}}
    keyproof = key + _ + str(G_privateKeys[key]) 
    newLedger = G_ledger.copy()
    newLedger[keyproof] = 100000000
    chksum = getmd5(json.dumps(newLedger, sort_keys=True))

    """


def stop():
    # Save memory data to filesystem
    try:
        with open(os.path.join(MINICASHDIR, 'peers.json'), 'w') as peersOutFile:
            peersOutFile.write(json.dumps(G_peers, indent=4))
        with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'w') as privateKeysOutFile:
            privateKeysOutFile.write(json.dumps(G_privateKeys, indent=4))
        with open(os.path.join(MINICASHDIR, 'ledger.json'), 'w') as ledgerFile:
            ledgerFile.write(json.dumps(G_ledger, indent=4))
    except OSError as e:
        logging.error('While exiting program could not write memory data to disk: {}'.format(e))
    finally:
        if not noPid:
            os.unlink(PIDPATH)
        os._exit(0)

# COMMAND LINE INTERFACE AND SERVER CLASSES

# Server handler
class SynchronizerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        logging.info('Connection received from {}'.format(self.peername))
        self.transport = transport

    def data_received(self, data):
        try:
            message = json.loads(data)
        except json.JSONDecodeError as e:
            self.transport.close()
            return
        
        parser = PacketParser(message)
        if not parser.isPacketValid():
            logging.warning('Invalid incoming data => {}'.format(parser.errorMessage))
            return
        ptype = parser.getType()
        pdata = parser.getData()
        if ptype == 'HELLO':
            for entry in pdata:
                fprint = entry['Fingerprint']
                proof = entry['ProofOfWork']
                if fprint in G_peers:
                    continue
                # Check for valid proof of work
                if not addToKeyring(fprint):
                    logging.info('The key {} is rejected because can not' 
                                 'be found on key server'.format(fprint))
                    continue
                G_peers[fprint] = {'Proof':proof, 'Ip':self.peername[0]}
                logging.info('{} key with {} proof received from {}'.format(
                    fprint, proof, self.peername[0]))
        elif ptype == 'REQ_LEDGER':
            # Get dumped ledger's md5
            signaturesDict = signLedgerLocalKeys(G_ledger)
            ledgerResponse = {'Type': 'RESP_LEDGER', 'Data':{'Ledger': G_ledger,
                              'Signatures': signaturesDict}}
            ledgerResponse = json.dumps(ledgerResponse, sort_keys=True)
            self.transport.write(ledgerResponse.encode('utf-8'))

    def connection_lost(self, exc):
        self.transport.close()


# Command line interface handler
class MyCliHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(64000)

        dispatcher.add_method(init)
        dispatcher.add_method(getLedger)
        dispatcher.add_method(listLocalKeys)
        dispatcher.add_method(listPeers)
        dispatcher.add_method(getBalances)
        dispatcher.add_method(pay)
        dispatcher.add_method(addKey)
        dispatcher.add_method(stop)
        dispatcher.add_method(introduceKeyToLedger)

        response = JSONRPCResponseManager.handle(
            str(data, 'utf-8'), dispatcher)
        self.request.sendall(response.json.encode('utf-8'))

def cliServer():
    HOST, PORT = "localhost", 2223
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), MyCliHandler) as server:
        server.serve_forever()

def nodeServer():
    loop = asyncio.new_event_loop()
    try:
        server = loop.run_until_complete(loop.create_server(SynchronizerProtocol,'',2222))
    except OSError as e:
        logging.error('Error running the node server: {}. Exiting..'.format(e))
        stop()
    loop.run_forever()
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    

def main():
    signal.signal(signal.SIGINT, interruptHandler)
    signal.signal(signal.SIGTERM, interruptHandler)

    # Command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--loglevel', help='Level of logging in file minicash.log')
    parser.add_argument('--peerserver', help='IP of the peer discovery server')
    parser.add_argument('--homedir', help='Directory inside which .minicash should \
                                                     be located')
    parser.add_argument('--nopid', action='store_true', help='Run without pid file')

    subparsers = parser.add_subparsers(dest='command')

    # Read the arguments of the command line
    args = parser.parse_args()

    if args.nopid:
        global noPid
        noPid = True
    
    # Checking for already running instance
    if not noPid:
        pid = str(os.getpid())
        if os.path.isfile(PIDPATH):
            print('{} already exists, exiting..'.format(PIDPATH))
            exit()
        try:
            with open(PIDPATH, 'w') as pidfile:
                pidfile.write(pid)
        except OSError as e:
            print('Error writting pid file: {}'.format(e))
            exit()


    # Initialize data folder
    global HOMEDIR
    global MINICASHDIR
    global GPGDIR
    global G_privateKeys
    global G_configuration
    global G_peers
    global G_ledger

    if args.homedir:
        HOMEDIR = args.homedir
    else:
        HOMEDIR = os.getenv('HOME')
    MINICASHDIR = os.path.join(HOMEDIR, '.minicash')

    GPGDIR = os.path.join(MINICASHDIR, '.gnupg')
    dataCreation = init({'Homedir': HOMEDIR})
    if 'Fail' in dataCreation:
        print(dataCreation['Fail']['Reason'] + '\nExiting..')
        stop()

    # Set logger level
    if args.loglevel:
        level = args.loglevel
        logLevel = getattr(logging, level.upper(), None)
        if not isinstance(logLevel, int):
            print('Wrong logging level')
            stop()
    else:
        logLevel = 'WARNING'
    logging.basicConfig(format='%(asctime)s => (%(levelname)-8s) %(message)s', level=logLevel,
                        filename=os.path.join(MINICASHDIR, 'minicash.log'),
                        filemode='w')
    logging.info('The program started')
    print('Program started')

    ## Load the configuration
    try:
        with open(os.path.join(MINICASHDIR, 'config.json'), 'r') as configfile:
            G_configuration = json.load(configfile)
            if args.peerserver:
                G_configuration['PEER_SERVER']['Ip'] = args.peerserver
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading config.json file to memory: {}\nExiting..'.format(e))
        stop()

    ## Load the peers
    try:
        with open(os.path.join(MINICASHDIR, 'peers.json'), 'r') as peersFile:
            G_peers = json.load(peersFile)
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading peers.json file to memory: {}\nExiting..'.format(e))
        stop()

    ## Load the private keys
    try:
        with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'r') as privateKeysFile:
            G_privateKeys = json.load(privateKeysFile)
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading private_keys.json file to memory: {}\nExiting..'.format(e))
        stop()

    ## Load the ledger
    try:
        with open(os.path.join(MINICASHDIR, 'ledger.json'), 'r') as ledgerFile:
            G_ledger = json.load(ledgerFile)
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading ledger.json file to memory: {}\nExiting..'.format(e))
        stop()

    try:
        dcontext = DaemonContext(
            working_directory=MINICASHDIR,
            files_preserve=[logging.root.handlers[0].stream.fileno()],
            umask=0o022)
        dcontext.stderr = open(os.path.join(MINICASHDIR, 'minicash.err'), 'w+')
        print('Staring the daemon..')
        with dcontext:
            signal.signal(signal.SIGINT, interruptHandler)
            signal.signal(signal.SIGTERM, interruptHandler)
            nodeThread = threading.Thread(target=nodeServer)
            nodeThread.start()

            # ---------  INITIAL CONNECTIONS ----------------

            # Introduce our keys to the peer server and get other peers ips
            peersRequest = {'Type': 'REGUP', 'Keys': []}
            for key in G_privateKeys.keys():
                peersRequest['Keys'].append({'Fingerprint': key, 'ProofOfWork': G_privateKeys[key]})
            peersRequest = json.dumps(peersRequest).encode('utf-8')

            peersRequestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serverIp = G_configuration['PEER_SERVER']['Ip']
            serverPort = G_configuration['PEER_SERVER']['Port']
            # Wait for a random amount of time for solving synchronization problems
            time.sleep(random.uniform(0.0, 2.0))
            logging.info('connecting to server {}:{}'.format(serverIp, serverPort))
            try:
                peersRequestSock.connect((serverIp, int(serverPort)))
                peersRequestSock.sendall(peersRequest)
                peersRequestSock.shutdown(socket.SHUT_WR)
                peersResponse = str(peersRequestSock.recv(65535), 'utf-8')
            except OSError as e:
                logging.info('Problem connecting to the peer server: {}\nExiting..'.format(e))
                stop()
            finally:
                peersRequestSock.close()

            try:
                peersResponse = json.loads(peersResponse)
            except json.JSONDecodeError as e:
                logging.error('Json error on peers server response: {}\nExiting..'.format(e))
                stop()

            if peersResponse['Response'] == 'Fail':
                logging.error('Could not receive valid data from the peer server\n'
                      '{}\nExiting..'.format(peersResponse['Reason']))
                stop()
            
            maps = peersResponse['Maps']
            for key, val in maps.items():
                # Check if we already have the key in our file
                if key in G_peers:
                    continue
                # Check the proof of work of the key.
                if not isValidProof(key, val['Proof']):
                    logging.info('The key {} is rejected because of invalid proof of work'.format(key))
                    continue
                # Try to download the key from the key server. If it's impossible continue
                if not addToKeyring(key):
                    logging.info('The key {} is rejected because can not be found on key server'.format(
                                    key))
                    continue
                # Add the key to the keyring
                G_peers[key] = val   
                logging.info('Peers Memory: Peer {} added from {} with proof of work {}'.format(
                    G_peers[key], val['Ip'], val['Proof']
                            ))

            # Send hello to all nodes with peer list
            sendHello()
            
            # Ask for ledger from the other nodes 
            results = sendReceiveToMany({'Type':'REQ_LEDGER', 'Data': {}}, getRemoteIps())
            logging.info('--------- LEDGER RESPONSES ---------')
            for response in results:
                logging.info('Ledger uninspected reponse received from keys {}'.format(
                                response['Data']['Signatures'].keys()))
            consesusLedger = getConsesusValidLedger(results)
            if consesusLedger != None:
                G_ledger = consesusLedger



            logging.info('---MEMORY DATA----')
            logging.info('HOMEDIR: {}'.format(HOMEDIR))
            logging.info('MINICASHDIR: {}'.format(MINICASHDIR))
            logging.info('GPGDIR: {}'.format(GPGDIR))
            logging.info('G_privateKeys: {}'.format(G_privateKeys))
            logging.info('G_configuration: {}'.format(G_configuration))
            logging.info('G_peers: {}'.format(G_peers))
            logging.info('G_ledger: {}'.format(G_ledger))
            logging.info('---END OF MEMORY DATA---')


            cliThread = threading.Thread(target=cliServer)
            cliThread.start()

    except DaemonOSEnvironmentError as e:
        print('ERROR: {}'.format(e))
        stop()
    
if __name__ == '__main__':
    main()
