import signal
import threading
import socketserver
import socket
import os
import argparse
import json
import gnupg
import hashlib
from jsonrpc import JSONRPCResponseManager, dispatcher
from daemon import DaemonContext
from daemon.daemon import DaemonOSEnvironmentError

# Global variables
PIDPATH = "/tmp/minicashd.pid"
G_privateKeys = {}
G_configuration = {}
G_peers = {}
HOMEDIR = ''
MINICASHDIR = ''
GPGDIR = ''

# COMMAND LINE FUNCTIONS
def init(kwargs):
    # Create .minicash folder if not existing and enter it
    try:
        os.chdir(kwargs['Homedir'])
        if not os.path.isdir('.minicash'):
            os.mkdir('.minicash')
        os.chdir(kwargs['Homedir']+ '/.minicash')
    except OSError as e:
        return {'Fail': {'Reason':'IOError accessing data folder', 'Message':str(e)}}

    # Create configuration file
    if not os.path.isfile('config.json'):
        config = {
        'PEER_SERVER': {'Ip': '127.0.0.1', 'Port': '9999'},
        'KEY_SERVERS': { 'adresses': [
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
            return {'Fail': {'Reason':'Error writting initial configuration', 'Message': str(e)}}

    # Take care of key files and .gnupg folder
    try:
        if not os.path.isfile('private_keys.json'):
            with open('private_keys.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isfile('peers.json'):
            with open('peers.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isdir('.gnupg'):
            os.mkdir('.gnupg')
            os.chmod('.gnupg', 0o700)
    except OSError as e:
        return {'Fail': {'Reason': 'OSError', 'Message':str(e)}}

    return {'Success': {}}


def addKey(kwargs):
    fingerprint = kwargs['key']
    proof = kwargs['pow']
    gpgdir = kwargs['gpgdir']

    # Check if secret key doesn't exist in keyring
    gpg = gnupg.GPG(gnupghome=gpgdir)
    foundkey = None
    for key in gpg.list_keys(True):
        if key['keyid'] == fingerprint:
            foundkey = key
    if foundkey == None:
        return {'Fail': {'Reason': 'Key not found in gpg database'}}

    # Check if pow is invalid for the key
    keyhash = hashlib.sha256()
    fingerproof = fingerprint + ':' + proof
    ufingerproof = fingerproof.encode('utf-8')
    keyhash.update(ufingerproof)
    result = keyhash.hexdigest()
    if not result.startswith('00000'):
        return {'Fail':{'Reason':'Wrong proof of work'}}

    # Add the key to the privateKeys
    privateKeys = kwargs['toStore']
    privateKeys[fingerprint] = proof

    # Return if uploading to server is not requested
    if not kwargs['upload']:
        return {'Success':{}}
    
    # Upload key to the key server
    servers = G_configuration['KEY_SERVERS']['adresses']

    for keyserver in servers:
        response = gpg.send_keys(keyserver, fingerprint)
        response = response.stderr
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            return {'Success': {}}
    return {'Partial-Fail': {'Reason':'Problem uploading key to server '
            'but key added to private_keys.json'}}

def listNodes(kwargs):
    return {'Success': G_peers}

def listLocalKeys(kwargs):
    return {'Success': G_privateKeys}

def getBalances(kwargs):
    return kwargs

def pay(kwargs):
    return kwargs

def reloadConf(kwargs):
    return kwargs

def interruptHandler(signum, frame):
    stop()

def stop():
    # Save memory data to filesystem
    try:
        with open(os.path.join(MINICASHDIR, 'peers.json') , 'w') as peersOutFile:
            peersOutFile.write(json.dumps(G_peers))
        with open(os.path.join(MINICASHDIR, 'private_keys.json') , 'w') as privateKeysOutFile:
            privateKeysOutFile.write(json.dumps(G_privateKeys))
    except OSError as e:
        print('While exiting program could not write memory data to peers.json or \
private_keys.json file: {}'.format(e))
    finally:
        os.unlink(PIDPATH)
        os._exit(0)


# Command line interface handler
class MyCliHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(64000)
    
        dispatcher.add_method(init)
        dispatcher.add_method(listLocalKeys)
        dispatcher.add_method(listNodes)
        dispatcher.add_method(getBalances)
        dispatcher.add_method(pay)
        dispatcher.add_method(addKey)
        dispatcher.add_method(reloadConf)
        dispatcher.add_method(stop)

        response = JSONRPCResponseManager.handle(
            str(data, 'utf-8'), dispatcher)
        self.request.sendall(response.json.encode('utf-8'))



def cliServer():
    HOST, PORT = "localhost", 2223
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), MyCliHandler) as server:
        server.serve_forever()

def main():
    signal.signal(signal.SIGINT, interruptHandler)
    signal.signal(signal.SIGTERM, interruptHandler)
    # Command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--peerserver', type=str, help='IP of the peer discovery server')
    parser.add_argument('--homedir', type=str, help='Directory inside which .minicash should \
                                                     be located')
    subparsers = parser.add_subparsers(dest='command')
    initialkey_cmd = subparsers.add_parser('initialkey', help='Creation of the first (oblicgatory \
                                            key')
    # Initial key adding for the node to run
    initialkey_cmd.add_argument('key', help='The key\'s fingerprint')
    initialkey_cmd.add_argument('pow', help='The key\'s proof of work')

    # Read the arguments of the command line
    args = parser.parse_args()

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

    if args.homedir:
        HOMEDIR = args.homedir
    else:
        HOMEDIR = os.getenv('HOME')
    MINICASHDIR = os.path.join(HOMEDIR, '.minicash')
    GPGDIR = os.path.join(MINICASHDIR, '.gnupg')
    dataCreation = init({'Homedir':HOMEDIR})
    if 'Fail' in dataCreation:
        print(dataCreation['Fail']['Reason'] + '\nExiting..')
        stop()

    ## Load the configuration
    try:
        with open(os.path.join(MINICASHDIR, 'config.json') , 'r') as configfile:
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

    # Add initial key and proof of work if found
    if args.command == 'initialkey':
        if len(G_privateKeys) != 0:
            print('There is already a private key. No need to run this command.')
            stop()
        result = addKey({'key': args.key, 'pow': args.pow, 'upload': True, \
                         'toStore':G_privateKeys, 'gpgdir':GPGDIR})
        if 'Fail' in result.keys():
            print(result['Fail']['Reason'] + '\nExiting..')
            stop()
        elif 'Partial-Fail' in result.keys():
            print(result['Partial-Fail']['Reason'] + '\nContinuing..')

    # Check first if we have at least one secret key
    # print('G_privateKeys: {}'.format(G_privateKeys))
    if len(G_privateKeys) == 0:
        print("You first have to enter a key before running the server."
              "\nUse the --initialkey argument to start the server. Exiting..")
        stop()

    # Introduce our keys to the peer server and get other peers ips
    request = {'Type':'REGUP', 'Keys':[]}
    for key in G_privateKeys.keys():
        request['Keys'].append(key)
    request = json.dumps(request).encode('utf-8')

    peersRequestSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # peersRequestSock.settimeout(5)
    serverIp = G_configuration['PEER_SERVER']['Ip']
    serverPort = G_configuration['PEER_SERVER']['Port']
    print('connecting to server {}:{}'.format(serverIp, serverPort))
    try:
        peersRequestSock.connect((serverIp, int(serverPort)))
        peersRequestSock.sendall(request)
        peersRequestSock.shutdown(socket.SHUT_WR)
        response = str(peersRequestSock.recv(1024), 'utf-8')
    except OSError as e:
        print('Problem connecting to the peer server: {}\nExiting..'.format(e))
        stop()
    finally:
        peersRequestSock.close()

    try:
        response = json.loads(response)
    except json.JSONDecodeError as e:
        print('Json error on peers server response: {}\nExiting..'.format(e))
        stop()

    if response['RESPONSE'] == 'Fail':
        print('Could not receive valid data from the peer server\n'
              '{}\nExiting..'.format(response['Reason']))
        stop()

    G_peers = response['Maps']

    # Send hello to the other peers
    try:
        dcontext = DaemonContext(
            working_directory=MINICASHDIR,
            umask=0o022)
        dcontext.stderr = open(os.path.join(MINICASHDIR, 'minicash.err'), 'w+')
        dcontext.stdout = open(os.path.join(MINICASHDIR, 'minicash.log'), 'w+')
        print('Staring the daemon..')
        with dcontext:
            signal.signal(signal.SIGINT, interruptHandler)
            signal.signal(signal.SIGTERM, interruptHandler)
            cliThread = threading.Thread(target=cliServer)
            cliThread.start()
    except DaemonOSEnvironmentError as e:
        print('ERROR: {}'.format(e))
        stop()
    

if __name__ == '__main__':
    main()
