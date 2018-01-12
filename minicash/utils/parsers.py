import re
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils.checksum import isValidProof

# Checks for the ledger's format since it's of dict type
def isValidLedger(ledger):
    if type(ledger) is not dict:
        return False
    # check if keys are strings and values are integers
    for key in ledger.keys():
        if type(key) is not str:
            return False
    for balance in ledger.values():
        if type(balance) is not int:
            return False
    for key, value in ledger.items():
        # Check if key first 16 characters are valid fingerprint
        fprint = key[:16]
        res = re.match('^[a-fA-F0-9]{16}$', fprint)
        if res == None:
            return False
        # Check if 17th character is _
        if key[16] != '_':
            return False
        # Check if [17:] is representing integer
        proof = key[17:]
        try:
            proofint = int(proof)
        except ValueError:
            return False
        # Check proof with proof of work checker for the key validity
        if not isValidProof(fprint, proof):
            return False
        # Check if balance is 0 or above
        if value < 0:
            return False
    return True


# Checks if he ledger response is formated correctly. This is a dict
def isValidLedgerResponseFormat(res):
    if type(res) is not dict:
        return False 
    if not ('Ledger' in res and 'Signatures' in res and 'Type' in res):
        return False 
    if res['Type'] != 'RESP_LEDGER':
        return False
    if not isValidLedger(json.loads(res['Ledger'])):
        return False
    if len(res) != 3:
        return False
    # Check if signatures value is dictionary
    signatures = res['Signatures']
    if type(signatures) is not dict:
        return False
    for fprint, sig in signatures.items():
        if type(fprint) is not str or type(sig) is not str:
            return False
        res = re.match('^[a-fA-F0-9]{16}$', fprint)
        if res == None:
            return False
        if type(sig) is not str:
            return False
    return True

