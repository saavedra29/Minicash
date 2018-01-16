import re
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils.checksum import isValidProof

# Checks for the ledger's format since it's of dict type
def isValidLedger(ledger):
    if type(ledger) is not dict:
        return '@Ledger not valid: It is not dict'
    # check if keys are strings and values are integers
    for key in ledger.keys():
        if type(key) is not str:
            return '@Ledger not valid: key is not string'
    for balance in ledger.values():
        if type(balance) is not int:
            return '@Ledger not valid: balance is not integer'
    for key, value in ledger.items():
        # Check if key first 16 characters are valid fingerprint
        fprint = key[:16]
        res = re.match('^[a-fA-F0-9]{16}$', fprint)
        if res == None:
            return '@Ledger not valid: invalid key fingerprint {}'.format(fprint)
        # Check if 17th character is _
        if key[16] != '_':
            return '@Ledger not valid: wrong separating character'
        # Check if [17:] is representing integer
        proof = key[17:]
        try:
            proofint = int(proof)
        except ValueError:
            return '@Ledger not valid: proof is not an integer'
        # Check proof with proof of work checker for the key validity
        if not isValidProof(fprint, proof):
            return '@Ledger not valid: wrong proof of work'
        # Check if balance is 0 or above
        if value < 0:
            return '@Ledger not valid: balance below 0'
    return False


# Checks if the ledger response is formated correctly. This is a dict
def isValidLedgerResponseFormat(res):
    if type(res) is not dict:
        return '@Ledger response wrong format: It is not dict'
    if not ('Ledger' in res and 'Signatures' in res and 'Type' in res):
        return '@Ledger response wrong format: Wrong key'
    if res['Type'] != 'RESP_LEDGER':
        return '@Ledger response wrong format: Type is not RESP_LEDGER'
    fromLedger = isValidLedger(res['Ledger'])
    if fromLedger:
        return '@Ledger response wrong format: The ledger value is not valid' + '==>' + fromLedger
    if len(res) != 3:
        return '@Ledger response wrong format: Not exactly 3 elements'
    # Check if signatures value is dictionary
    signatures = res['Signatures']
    if type(signatures) is not dict:
        return '@Ledger response wrong format: Signatures value is not dict'
    for fprint, sig in signatures.items():
        if type(fprint) is not str or type(sig) is not str:
            return '@Ledger response wrong format: In Signatures fingerprint or signature is not string'
        res = re.match('^[a-fA-F0-9]{16}$', fprint)
        if res == None:
            return '@Ledger response wrong format: Wrong fingerprint format'
    return False

