import asyncio
import threading
import socketserver
import os
import argparse
import configparser
import json
import gnupg
import hashlib
from jsonrpc import JSONRPCResponseManager, dispatcher
from daemon import DaemonContext
from daemon.daemon import DaemonOSEnvironmentError
from daemon.pidfile import PIDLockFile

# Working paths
HOMEDIR = os.getenv('HOME')
OPENCASHDIR = os.path.join(HOMEDIR, '.opencash')
GPGDIR = os.path.join(OPENCASHDIR, '.gnupg')

# COMMAND LINE FUNCTIONS
def init(kwargs):
    # Create .opencash folder if not existing and enter it
    try:
        os.chdir(HOMEDIR)
        if not os.path.isdir('.opencash'):
            os.mkdir('.opencash')
        os.chdir(HOMEDIR + '/.opencash')
    except OSError as e:
        return {'Fail': {'Reason':'OSError', 'Message':str(e)}}

    # Check for opencash.ini file for the initial configuration
    if not os.path.isfile('opencash.ini'):
        try:
            config = configparser.ConfigParser()
            config['PEER_SERVER'] = {
                'Ip': '192.168.1.50',
                'Port': '50001'
            }
            config['KEY_SERVER'] = {
                'Ip': 'pgp.mit.edu'
            }
        except configparser.Error as e:
            return {'Fail': {'Reason':'Configparser error', 'Message':str(e)}}
        try:
            with open('opencash.ini', 'w') as infile:
                config.write(infile)
        except (OSError, configparser.Error) as e:
            return {'Fail': {'Reason': 'Error accessing opencash.ini', 'Message':str(e)}}

    # Take care of key files and .gnupg folder
    try:
        if not os.path.isfile('private_peers.json'):
            with open('private_peers.json', 'w') as infile:
                infile.write('{}')
        if not os.path.isfile('public_peers.json'):
            with open('public_peers.json', 'w') as infile:
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

    # Add the key to the private_peers.json
    privatePeers = ''
    try:
        with open(os.path.join(OPENCASHDIR, 'private_peers.json'), 'r+') as privPeersFile:
            privatePeers = privPeersFile.read()
            try:
                privatePeers = json.loads(privatePeers)
                privatePeers[fingerprint] = proof
                privatePeers = json.dumps(privatePeers ,indent=4)
            except json.JSONDecodeError as e:
                return {'Fail':{'Reason':'JSONDecodeError (private_peers.json wrong format)', 'Message': str(e)}}
            privPeersFile.seek(0,0)
            privPeersFile.write(privatePeers)
    except OSError as e:
        return {'Fail':{'Reason':'OSError', 'Message':str(e)}}

    if not kwargs['upload']:
        return {'Success':{}}
    # Upload key to the key server
    config = configparser.ConfigParser()
    try:
        config.read(os.path.join(OPENCASHDIR, 'opencash.ini'))
    except (OSError, configparser.Error) as e:
        return {'Partial-Fail': {'Reason':'Problem uploading key to server '
                'but key added to private_peers.json', 'Message':str(e)}}
    try:
        keyserver = config['KEY_SERVER']['Ip']
    except configparser.Error as e:
        return {'Partial-Fail': {'Reason':'Problem uploading key to server '
                'but key added to private_peers.json', 'Message':str(e)}}
    response = gpg.send_keys(keyserver, fingerprint)
    response = response.stderr
    failureWords = ['ERROR', 'FAILURE']
    uploadfail = False
    if any(x in response for x in failureWords):
        return {'Partial-Fail': {'Reason':'Problem uploading key to server '
                'but key added to private_peers.json'}}
    else:
        return {'Success': {}}

def listonline(kwargs):
    return kwargs

def register(kwargs):
    return kwargs

def reloadConf(kwargs):
    return kwargs

def stop():
    exit()

# COMMAND LINE INTERFACE AND SERVER CLASSES
class SynchronizerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        """
        Called when a connection is made.
        The argument is the transport representing the pipe connection.
        To receive data, wait for data_received() calls.
        When the connection is closed, connection_lost() is called.
        """
        self.peername = transport.get_extra_info('peername')
        if self.peername[0] in ['localhost', '127.0.0.1', '::1']:
            # Dispatchers
            dispatcher.add_method(init)
            dispatcher.add_method(addKey)
            dispatcher.add_method(listonline)
            dispatcher.add_method(register)
            dispatcher.add_method(reloadConf)
            dispatcher.add_method(stop)
            self.cli = True
        else:
            self.cli = False
        print('Connection from {}'.format(self.peername))
        self.transport = transport

    def data_received(self, data):
        if self.cli:
        # CONNECTION COMES FROM THE OPENCASH COMMAND LINE CLIENT
            response = JSONRPCResponseManager.handle(
                str(data, 'utf-8'), dispatcher)
            self.transport.write(response.json.encode('utf-8'))
            # self.transport.close()
        else:
        # CONNECTION COMES FROM OPENCASH REMOTE PEER
            print('Non localhost data: ')
            print(data.decode('utf-8'))
            self.transport.write(data)
                

    def connection_lost(self, exc):
        """
        Called when the connection is lost or closed.
        The argument is an exception object or None (the latter
        meaning a regular EOF is received or the connection was
        aborted or closed).
        """
        print('Connection closed..')


# MAIN
def main():
    loop = asyncio.new_event_loop()
    server = loop.run_until_complete(loop.create_server(SynchronizerProtocol,'',2222))
    loop.run_forever()
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--daemon', action='store_true', help='Run the program as daemon')
    args = parser.parse_args()
    init({})
    if not args.daemon:
        main()
    else:
        try:
            dcontext = DaemonContext(
                working_directory=OPENCASHDIR,
                pidfile=PIDLockFile('/tmp/opencash.pid'),
                umask=0o022)
            dcontext.stderr = open(os.path.join(OPENCASHDIR, 'opencash.err'), 'w+')
            dcontext.stdout = open(os.path.join(OPENCASHDIR, 'opencash.log'), 'w+')
            with dcontext:
                main()
        except DaemonOSEnvironmentError as e:
            print('ERROR: {}'.format(e))
            exit()
