import sys
import os
import json
import argparse
import gnupg
import shutil
from pathlib import Path
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from minicashd import init
from utils.pow import POWGenerator

def addKey(kwargs):
    fingerprint = kwargs['key']
    proof = kwargs['pow']
    if 'gpgdir' in kwargs:
        gpg = gnupg.GPG(gnupghome=kwargs['gpgdir'], use_agent=False)
    else:
        gpg = gnupg.GPG(gnupghome=GPGDIR, use_agent=False)

    foundkey = None
    for key in gpg.list_keys(True):
        if key['keyid'] == fingerprint:
            foundkey = key
    if foundkey == None:
        return {'Fail': {'Reason': 'Key not found in gpg database'}}

    # Check if pow is invalid for the key
    keyhash = hashlib.sha256()
    fingerproof = fingerprint + '_' + str(proof)
    keyhash.update(fingerproof.encode('utf-8'))
    hashResult = keyhash.hexdigest()
    if not hashResult.startswith('00000'):
        return {'Fail': {'Reason': 'Wrong proof of work'}}

    # Add the key to the privateKeys
    privateKeys = kwargs['toStore']
    privateKeys[fingerprint] = proof

    # Return if uploading to server is not requested
    if 'noupload' in kwargs:
        return {'Success': {}}

    # Upload key to the key server
    servers = [
            "pgp.mit.edu",
            "sks-keyservers.net",
            "pool.sks-keyservers.net",
            "eu.pool.sks-keyservers.net"
        ]

    for keyserver in servers:
        response = gpg.send_keys(keyserver, fingerprint).stderr
        failureWords = ['ERROR', 'FAILURE']
        if not any(x in response for x in failureWords):
            return {'Success': {}}
    
    del(privateKeys[fingerprint])
    return {'Fail': {'Reason': 'Problem uploading key to server'}}
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('homedir', type=str, nargs='+',
                        help='Directory inside which .minicash folder should be created')
    parser.add_argument('keysnum', type=int, help='Number of keys to create')
    args = parser.parse_args()

    for path in args.homedir:
        HOMEDIR = path
        MINICASHDIR = os.path.join(HOMEDIR, '.minicash')
        GPGDIR = os.path.join(MINICASHDIR, '.gnupg')
        privateKeys = {}

        print('---------------------------')
        print('CREATING {}'.format(MINICASHDIR))
        print('---------------------------')
        if os.path.isdir(MINICASHDIR):
            shutil.rmtree(MINICASHDIR)
            print('Old folder {} deleted'.format(MINICASHDIR))
        Path(HOMEDIR).mkdir(parents=True, exist_ok=True)
        print('{} created'.format(HOMEDIR))

        # Create homedir
        res = init({'Homedir': HOMEDIR})
        if 'Fail' in res:
            print(res)
            return

        # Create and add the keys 
        keysnum = args.keysnum
        try:
            gpg = gnupg.GPG(gnupghome=GPGDIR, use_agent=False)
        except Exception as e:
            print('Error creating quickstart keys: {}'.format(e))
            return
        if keysnum < 1 or keysnum > 1000:
            print('Provide a number of random keys between 1 and 1000')
            return
        for num in range(keysnum):
            # Create key
            key = gpg.gen_key(gpg.gen_key_input(key_type='RSA',
                                                key_length=1024,
                                                passphrase='mylongminicashsillypassphrase'))
            fingerprint = key.fingerprint[24:]
            print('key {} created'.format(num))
            # Create proof of work for the key (difficulty: 5, cores: maximum 8)
            powGenerator = POWGenerator(fingerprint, 5, 8)
            result = powGenerator.getSolution()
            if result == None:
                print('Proof of work interrupted and exiting')
                return
            print('proof of work created')
            # Add the key
            addKeyRes = addKey({'key': fingerprint, 'pow': result, 'upload': True,
                                'toStore': privateKeys, 'gpgdir': GPGDIR})
            if not 'Success' in addKeyRes:
                print('Problem adding the keys: {}'.format(addKeyRes['Fail']['Reason']))
                return
            print('key {} added'.format(num))

        try:
            with open(os.path.join(MINICASHDIR, 'private_keys.json'), 'w') as privateKeysOutFile:
                privateKeysOutFile.write(json.dumps(privateKeys))
        except OSError as e:
            print('While exiting program could not write memory data to peers.json or \
                  private_keys.json file: {}'.format(e))
            return
        print('-----------------------')
    print('\n\nQuickstart ending with success!')
    return


main()
