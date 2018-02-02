import os
import json


def init(kwargs):
    # Create .minicash folder if not existing and enter it
    try:
        os.chdir(kwargs['Homedir'])
        if not os.path.isdir('.minicash'):
            os.mkdir('.minicash')
        os.chdir(kwargs['Homedir'] + '/.minicash')
    except (OSError, PermissionError)as e:
        return {'Fail':{'Reason': str(e)}}

    # Create configuration file
    if not os.path.isfile('config.json'):
        config = {
            'PEER_SERVER': {'Ip': 'saav29.ddns.net', 'Port': '9999'},
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
        except (OSError, PermissionError)as e:
            return {'Fail':{'Reason': str(e)}}

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
    except (OSError, PermissionError)as e:
        return {'Fail':{'Reason': str(e)}}

    return {'Success': {}}

