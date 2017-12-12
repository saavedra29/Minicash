import sys
import os
import json
import argparse
import gnupg
import shutil
from pathlib import Path

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from minicashd import addKey, init
from utils.pow import POWGenerator


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('homedir', type=str, nargs='+',
                        help='Directory inside which .minicash folder should be created')
    parser.add_argument('keysnum', type=str, help='Number of keys to create')
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
        keysnum = int(args.keysnum)
        try:
            gpg = gnupg.GPG(gnupghome=GPGDIR)
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
            addKeyRes = addKey({'key': fingerprint, 'pow': result, 'upload': False,
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
