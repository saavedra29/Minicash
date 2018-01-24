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
from utils.gpg import signWithKeys
from utils.gpg import getKeysThatSignedData

# Global variables
noPid = False
PIDPATH = "/tmp/minicashd.pid"
G_privateKeys = {}
G_configuration = {}
G_peers = {}
G_ledger = {}
G_keyIntro = {'Key': None, 'LedgerHash': None, 'MessageHash': None}
HOMEDIR = ''
MINICASHDIR = ''
GPGDIR = ''


# COMMAND LINE INTERFACE AND SERVER CLASSES

# Command line interface handler
class MyCliHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(64000)

        dispatcher.add_method(init)
        dispatcher.add_method(getLedger)
        dispatcher.add_method(listLocalKeys)
        dispatcher.add_method(listPeers)
        dispatcher.add_method(getBalances)
        dispatcher.add_method(send)
        dispatcher.add_method(addKey)
        dispatcher.add_method(stop)
        dispatcher.add_method(introduceKeyToLedger)

        response = JSONRPCResponseManager.handle(
            str(data, 'utf-8'), dispatcher)
        self.request.sendall(response.json.encode('utf-8'))


# Server handler
class MainServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        self.peername = transport.get_extra_info('peername')
        logging.info('Connection received from {}'.format(self.peername))
        self.transport = transport

    def data_received(self, data):
        global G_ledger
        try:
            message = json.loads(data)
        except json.JSONDecodeError as e:
            self.transport.close()
            return

        parser = PacketParser(message)
        if not parser.isPacketValid():
            logging.warning('Invalid packet => {}'.format(parser.errorMessage))
            self.transport.close()
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
                    logging.warning('The key {} is rejected because can not'
                                 'be found on key server'.format(fprint))
                    continue
                G_peers[fprint] = {'Proof': proof, 'Ip': self.peername[0]}
                logging.info('{} key with {} proof received from {}'.format(
                    fprint, proof, self.peername[0]))
        elif ptype == 'REQ_LEDGER':
            # Get dumped ledger's md5
            dumpedLedger = json.dumps(G_ledger, sort_keys=True)
            signaturesDict = signWithKeys(GPGDIR, G_privateKeys.keys(), G_privateKeys.keys(),
                                          getmd5(dumpedLedger), 'mylongminicashsillypassphrase')
            ledgerResponse = {'Type': 'RESP_LEDGER', 'Data': {'Ledger': G_ledger,
                                                              'Signatures': signaturesDict}}
            ledgerResponse = json.dumps(ledgerResponse, sort_keys=True)
            self.transport.write(ledgerResponse.encode('utf-8'))

        elif ptype == 'REQ_INTRO_KEY':
            hashedReceivedMessage = getmd5(data.decode('utf-8'))
            reqIntroKeyResponse = {'Type': 'RESP_INTRO_KEY', 'Data': {
                'Checksum': hashedReceivedMessage, 'Signatures': {}}}
            fprint = pdata['Key'][:16]
            # TODO maybe not logical
            if fprint not in G_peers:
                logging.warning('The key {} can\'t be added to the ledger because is not in the'
                                ' G_peers'.format(fprint))
                self.transport.write(json.dumps(reqIntroKeyResponse).encode('utf-8'))
                return
            newLedger = G_ledger.copy()
            newLedger[pdata['Key']] = 100000000
            hashedNewLedger = getmd5(json.dumps(newLedger, sort_keys=True))
            if not hashedNewLedger == pdata['Checksum']:
                logging.warning('The checksums doesn\'t fit')
                self.transport.write(json.dumps(reqIntroKeyResponse).encode('utf-8'))
                return
            validKeys, _ = getKeysThatSignedData(
                logging, GPGDIR, {fprint: pdata['Sig']}, pdata['Checksum'])
            if fprint not in validKeys:
                logging.warning('Wrong signature')
                self.transport.write(json.dumps(reqIntroKeyResponse).encode('utf-8'))
                return
            signaturesDict = signWithKeys(GPGDIR, G_privateKeys.keys(), G_privateKeys.keys(),
                                          hashedReceivedMessage, 'mylongminicashsillypassphrase')
            reqIntroKeyResponse['Data']['Signatures'] = signaturesDict
            G_keyIntro['Key'] = pdata['Key']
            G_keyIntro['LedgerHash'] = pdata['Checksum']
            G_keyIntro['MessageHash'] = hashedReceivedMessage
            self.transport.write(json.dumps(reqIntroKeyResponse).encode('utf-8'))

        elif ptype == 'REQ_INTRO_KEY_END':
            if pdata['Checksum'] != G_keyIntro['MessageHash']:
                logging.warning(ptype + ': Invalid checksum or key')
                return
            tmpLedger = G_ledger.copy()
            tmpLedger[G_keyIntro['Key']] = 100000000
            hashedLedger = getmd5(json.dumps(tmpLedger, sort_keys=True))
            if hashedLedger != G_keyIntro['LedgerHash']:
                logging.warning(
                    ptype + ': G_ledger checksum won\'t agree with stored G_keyIntro checksum')
                self.transport.close()
                return
            validKeys, _ = getKeysThatSignedData(
                logging, GPGDIR, pdata['Signatures'], pdata['Checksum'])
            numberOfKeysThatVote = len(G_peers)
            positiveVotes = len(validKeys)
            if not positiveVotes > 67 / 100 * numberOfKeysThatVote:
                logging.warning(ptype + ': Not enough signatures of key intro voting')
                self.transport.close()
                return
            logging.info('-------- NEW KEY INTRODUCED TO THE LEDGER ----------')
            logging.info('Key: {}'.format(G_keyIntro['Key']))
            logging.info(
                '{} keys signed for the key introduction out of {} keys that voted'.format(
                    positiveVotes, numberOfKeysThatVote))
            logging.info('Success percentage: {}%'.format(
                str(positiveVotes / numberOfKeysThatVote * 100)))
            G_ledger = tmpLedger

        self.transport.close()

    def connection_lost(self, exc):
        self.transport.close()


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
    if foundkey is None:
        return {'Fail': {'Reason': 'Key not found in gpg database'}}

    # Check if pow is invalid for the key
    if not isValidProof(fingerprint, proof):
        return {'Fail': {'Reason': 'Wrong proof of work'}}

    # Add the key to the privateKeys
    global G_privateKeys
    G_privateKeys[fingerprint] = proof

    # Return if uploading to server is not requested
    # if 'noupload' in kwargs:
    if kwargs['noupload']:
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
            updatePeerServer()
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


def send(kwargs):
    return kwargs


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


def cliServer():
    HOST, PORT = "localhost", 2223
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), MyCliHandler) as server:
        server.serve_forever()


def nodeServer():
    loop = asyncio.new_event_loop()
    try:
        server = loop.run_until_complete(loop.create_server(MainServerProtocol, '', 2222))
    except OSError as e:
        logging.error('Error running the node server: {}. Exiting..'.format(e))
        stop()
    loop.run_forever()
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


def getRemoteIps():
    remoteips = []
    for proofIp in G_peers.values():
        remoteips.append(proofIp['Ip'])
    return set(remoteips)


def getConsesusValidLedger(ledgerResponces):
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
        signedKeys, _ = getKeysThatSignedLedger(response)
        logging.info('-------- Ledger and keys that signed it -------')
        logging.info('Ledger: {}'.format(ledger))
        logging.info('Keys: {}'.format(signedKeys))
        if ledger not in ledgersWithSignedKeys:
            ledgersWithSignedKeys[ledger] = signedKeys
        else:
            ledgersWithSignedKeys[ledger].extend(signedKeys)
        # Avoid duplications
        setKeys = set(ledgersWithSignedKeys[ledger])
        ledgersWithSignedKeys[ledger] = list(setKeys)
    numberOfKeysThatVote = len(G_peers)
    logging.info('-------- VOTING TABLE ---------')
    logging.info('{} keys voting!'.format(numberOfKeysThatVote))
    for ledger in ledgersWithSignedKeys:
        logging.warning(
            'LEDGER: {}\n\t\t\tVOTERS: {}'.format(
                ledger, len(
                    ledgersWithSignedKeys[ledger])))
    for ledger in ledgersWithSignedKeys:
        positiveVotes = len(ledgersWithSignedKeys[ledger])
        if positiveVotes > 67 / 100 * numberOfKeysThatVote:
            logging.info('-------- NEW VOTED LEDGER ----------')
            logging.info('Ledger: {}'.format(ledger))
            logging.info('{} keys signed for the ledger out of {} keys that voted'.format(
                positiveVotes, numberOfKeysThatVote))
            logging.info('Success percentage: {}%'.format(
                str(positiveVotes / numberOfKeysThatVote * 100)))
            return json.loads(ledger)
    logging.warning('-------- NO CONSESUS FOR A LEDGER -------')
    return None


# Takes the response and nonce and return a list with the keys that really signed the ledger
def getKeysThatSignedLedger(response):
    ledger = response['Data']['Ledger']
    ledger = json.dumps(ledger, sort_keys=True)
    dataToCheck = getmd5(ledger)
    keysSignaturesDict = response['Data']['Signatures']
    # Loop in signatures
    return getKeysThatSignedData(logging, GPGDIR, keysSignaturesDict, dataToCheck)


def sendHello(fprint=None, proof=None):
    # Send hello to the other peers
    hello = {'Type': 'HELLO', 'Data': []}
    if fprint is None:
        for key in G_privateKeys.keys():
            hello['Data'].append({'Fingerprint': key, 'ProofOfWork': G_privateKeys[key]})
    else:
        hello['Data'].append({'Fingerprint': fprint, 'ProofOfWork': proof})
    hello = json.dumps(hello)
    simpleSend(hello, getRemoteIps(), 2222, timeout=1)
    for ip in getRemoteIps():
        logging.info('Hello sent to {}'.format(ip))


def addToKeyring(fingerprint):
    gpg = gnupg.GPG(gnupghome=GPGDIR)
    for key in gpg.list_keys():
        if key['keyid'] == fingerprint:
            return True
    # Receive key from key server
    servers = G_configuration['KEY_SERVERS']['adresses']
    for keyserver in servers:
        response = gpg.recv_keys(keyserver, '0x' + fingerprint).stderr
        logging.info(
            'Sent {} to {} keyserver and got response: {}'.format(
                fingerprint, keyserver, response))
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            return True
    return False


def interruptHandler(signum, frame):
    stop()


def updatePeerServer(initial=False):
    peersRequest = {'Type': 'REGUP', 'Keys': []}
    for key in G_privateKeys.keys():
        peersRequest['Keys'].append({'Fingerprint': key, 'ProofOfWork': G_privateKeys[key]})
    peersRequest = json.dumps(peersRequest).encode('utf-8')

    peersRequestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverIp = G_configuration['PEER_SERVER']['Ip']
    serverPort = G_configuration['PEER_SERVER']['Port']
    if initial:
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
    return peersResponse


def introduceKeyToLedger(kwargs):
    key = kwargs['keytoadd']
    if key not in G_privateKeys:
        return {'Fail': {'Reason': 'Invalid key'}}
    keyproof = key + '_' + str(G_privateKeys[key])
    logging.info('====> keyproof: {}'.format(keyproof))
    if keyproof in G_ledger:
        return {'Fail': {'Reason': 'Key already in ledger'}}
    newLedger = G_ledger.copy()
    newLedger[keyproof] = 100000000
    chksum = getmd5(json.dumps(newLedger, sort_keys=True))
    signatures = signWithKeys(
        GPGDIR,
        G_privateKeys.keys(),
        [key],
        chksum,
        'mylongminicashsillypassphrase')
    message = {
        'Type': 'REQ_INTRO_KEY',
        'Data': {
            'Key': keyproof,
            'Checksum': chksum,
            'Sig': signatures[key]}}

    results = sendReceiveToMany(message, getRemoteIps())
    # collect all the valid data
    logging.info('Checking incoming RESP_INTRO_KEY data..')
    messageHash = getmd5(json.dumps(message))
    totalKeysSigs = {}
    for response in results:
        parser = PacketParser(response)
        if not parser.isPacketValid():
            logging.warning('Invalid incoming data: {}'.format(parser.errorMessage))
            continue
        if not parser.type == 'RESP_INTRO_KEY':
            logging.warning('Invalid incoming data type')
            continue
        data = parser.data
        if messageHash != data['Checksum']:
            logging.warning('Invalid checksum in data')
            continue
        _, keysSigsToCollect = getKeysThatSignedData(
            logging, GPGDIR, data['Signatures'], messageHash)
        totalKeysSigs.update(keysSigsToCollect)
    # check for the consesus
    numberOfKeysThatVote = len(G_peers)
    positiveVotes = len(totalKeysSigs)
    if not positiveVotes > 67 / 100 * numberOfKeysThatVote:
        logging.info('-------- KEY INTRO REQUESTER: NEW KEY FAILED TO ENTER THE LEDGER ----------')
        logging.info('Key: {}'.format(key))
        logging.info('{} keys signed for the key introduction out of {} keys that voted'.format(
            positiveVotes, numberOfKeysThatVote))
        return {'Fail': {'Reason': 'Not enough votes'}}

    logging.info('-------- KEY INTRO REQUESTER: NEW KEY INTRODUCED TO THE LEDGER ----------')
    logging.info('Key: {}'.format(key))
    logging.info('{} keys signed for the key introduction out of {} keys that voted'.format(
        positiveVotes, numberOfKeysThatVote))
    logging.info('Success percentage: {}%'.format(str(positiveVotes / numberOfKeysThatVote * 100)))
    # Send the 'REQ_INTRO_KEY_END' to all the nodes
    endMessage = {'Type': 'REQ_INTRO_KEY_END', 'Data': {'Checksum': messageHash,
                                                        'Signatures': totalKeysSigs}}
    sendToMany(endMessage, getRemoteIps())
    return {'Success': {}}


def main():
    signal.signal(signal.SIGINT, interruptHandler)
    signal.signal(signal.SIGTERM, interruptHandler)

    # Command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--loglevel', help='Level of logging in file minicash.log')
    parser.add_argument('--peerserver', help='IP of the peer discovery server')
    parser.add_argument('--homedir', help='Directory inside which .minicash should be located')
    parser.add_argument('--nopid', action='store_true', help='Run without pid file')

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

    # Load the configuration
    try:
        with open(os.path.join(MINICASHDIR, 'config.json'), 'r') as configfile:
            G_configuration = json.load(configfile)
            if args.peerserver:
                G_configuration['PEER_SERVER']['Ip'] = args.peerserver
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading config.json file to memory: {}\nExiting..'.format(e))
        stop()

    # Load the peers
    try:
        with open(os.path.join(MINICASHDIR, 'peers.json'), 'r') as peersFile:
            G_peers = json.load(peersFile)
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading peers.json file to memory: {}\nExiting..'.format(e))
        stop()

    # Load the private keys
    try:
        with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'r') as privateKeysFile:
            G_privateKeys = json.load(privateKeysFile)
    except (OSError, json.JSONDecodeError) as e:
        print('Error while loading private_keys.json file to memory: {}\nExiting..'.format(e))
        stop()

    # Load the ledger
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
            peersResponse = updatePeerServer(initial=True)
            maps = peersResponse['Maps']
            for key, val in maps.items():
                # Check if we already have the key in our file
                if key in G_peers:
                    continue
                # Check the proof of work of the key.
                if not isValidProof(key, val['Proof']):
                    logging.info(
                        '#peersResponse: The key {} is rejected because of invalid proof of work'.format(key))
                    continue
                # Try to download the key from the key server. If it's impossible continue
                if not addToKeyring(key):
                    logging.info(
                        '#peersResponse: The key {} is rejected because can not be found on key server'.format(key))
                    continue
                # Add the key to the keyring
                G_peers[key] = val
                logging.info(
                    '#peersResponse: Peers Memory: Peer {} added from {} with proof of work {}'.format(
                        G_peers[key], val['Ip'], val['Proof']))

            # Send hello to all nodes with peer list
            sendHello()

            # Ask for ledger from the other nodes
            results = sendReceiveToMany({'Type': 'REQ_LEDGER', 'Data': {}}, getRemoteIps())
            logging.info('--------- LEDGER RESPONSES ---------')
            for response in results:
                logging.info('Ledger uninspected reponse received from keys {}'.format(
                    response['Data']['Signatures'].keys()))
            consesusLedger = getConsesusValidLedger(results)
            if consesusLedger is not None:
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
