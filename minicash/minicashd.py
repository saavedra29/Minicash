import threading
import socketserver
import os
import argparse
import json
import gnupg
import hashlib
from jsonrpc import JSONRPCResponseManager, dispatcher
from daemon import DaemonContext
from daemon.daemon import DaemonOSEnvironmentError
from daemon.pidfile import PIDLockFile

# Working paths
HOMEDIR = os.getenv('HOME')
MINICASHDIR = os.path.join(HOMEDIR, '.minicash')
GPGDIR = os.path.join(MINICASHDIR, '.gnupg')

# COMMAND LINE FUNCTIONS
def init(kwargs):
    # Create .minicash folder if not existing and enter it
    try:
        os.chdir(HOMEDIR)
        if not os.path.isdir('.minicash'):
            os.mkdir('.minicash')
        os.chdir(HOMEDIR + '/.minicash')
    except OSError as e:
        return {'Fail': {'Reason':'IOError accessing data folder', 'Message':str(e)}}


    if not os.path.isfile('config.json'):
        config = {
        'PEER_SERVER': {'Ip': '192.168.1.50', 'Port': '9999'},
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
    # Check if secret key doesn't exist in keyring
    gpg = gnupg.GPG(gnupghome=GPGDIR)
    foundkey = None
    for key in gpg.list_keys(True):
        if key['keyid'] == fingerprint:
            foundkey = key
    if foundkey == None:
        return {'Fail': {'Reason': 'Key not found in database'}}
    # Check if pow is invalid for the key
    keyhash = hashlib.sha256()
    fingerproof = fingerprint + ':' + proof
    ufingerproof = fingerproof.encode('utf-8')
    keyhash.update(ufingerproof)
    result = keyhash.hexdigest()
    if not result.startswith('00000'):
        return {'Fail':{'Reason':'Wrong proof of work'}}

    # Add the key to the private_keys.json
    privateKeys = ''
    try:
        with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'r+') as privPeersFile:
            privateKeys = privPeersFile.read()
            try:
                privateKeys = json.loads(privateKeys)
                privateKeys[fingerprint] = proof
                privateKeys = json.dumps(privateKeys ,indent=4)
            except json.JSONDecodeError as e:
                return {'Fail':{'Reason':'JSONDecodeError (private_keys.json wrong format)', 'Message': str(e)}}
            privPeersFile.seek(0,0)
            privPeersFile.write(privateKeys)
    except OSError as e:
        return {'Fail':{'Reason':'OSError', 'Message':str(e)}}

    if not kwargs['upload']:
        return {'Success':{}}
    
    # Upload key to the key server
    try:
        with open('config.json', 'r') as configfile:
            jsonconfig = json.load(configfile)
    except (OSError, json.JSONDecodeError) as e:
        return {'Partial-Fail': {'Reason':'Problem reading configuration file', 'Message':str(e)}}

    servers = jsonconfig['KEY_SERVERS']['adresses']

    for keyserver in servers:
        response = gpg.send_keys(keyserver, fingerprint)
        response = response.stderr
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            return {'Success': {}}
    return {'Partial-Fail': {'Reason':'Problem uploading key to server '
            'but key added to private_keys.json'}}

def listNodes(kwargs):
    return kwargs

def listLocalKeys(kwargs):
    try:
        with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'r+') as privPeersFile:
            privateKeys = privPeersFile.read()
            try:
                privateKeys = json.loads(privateKeys)
            except json.JSONDecodeError as e:
                return {'Fail':{'Reason':'JSONDecodeError (private_keys.json wrong format)', 'Message': str(e)}}
    except OSError as e:
        return {'Fail':{'Reason':'OSError', 'Message':str(e)}}
    return {'Success': privateKeys}

def getBalances(kwargs):
    return kwargs

def pay(kwargs):
    return kwargs

def reloadConf(kwargs):
    return kwargs

def stop():
    # exit()
    os._exit(0)


class MyCliHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request.recv(64000)
        # Dispatchers
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

# MAIN
def main():
    cliThread = threading.Thread(target=cliServer)
    cliThread.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--daemon', action='store_true', help='Run the program as daemon')
    args = parser.parse_args()
    print(init({}))
    # Check first if we have at least one secret key


    # Connect to peer server, introduce our keys, get other peers ips and send hello to all of them


    if not args.daemon:
        main()
    else:
        try:
            dcontext = DaemonContext(
                working_directory=MINICASHDIR,
                pidfile=PIDLockFile('/tmp/minicash.pid'),
                umask=0o022)
            dcontext.stderr = open(os.path.join(MINICASHDIR, 'minicash.err'), 'w+')
            dcontext.stdout = open(os.path.join(MINICASHDIR, 'minicash.log'), 'w+')
            with dcontext:
                main()
        except DaemonOSEnvironmentError as e:
            print('ERROR: {}'.format(e))
            exit()
