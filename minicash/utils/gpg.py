import gnupg
import json
import hashlib
import re

def getmd5(data):
    datahash = hashlib.md5()
    datahash.update(data.encode('utf-8'))
    return datahash.hexdigest()

# Arguments
# 1: Path of GPG folder to use
# 2: The keys stored in the private_keys.json file
# 3: The keys we want to sign with
# 4: The data to sign
# 5: The password
def signWithKeys(logging, gpgdir, privateKeys, keysToUse, data, password):
    if type(data) is dict:
        data = json.dumps(data, sort_keys=True)
    gpg = gnupg.GPG(gnupghome=gpgdir, use_agent=False)
    signaturesDict = {}
    existingKeys = []
    # Check for existing keys
    for searchingKey in keysToUse:
        if searchingKey in privateKeys:
            for listedKey in gpg.list_keys(True):
                if searchingKey == listedKey['keyid']:
                    existingKeys.append(searchingKey)
    
    for key in existingKeys:
        signedData = gpg.sign(data, keyid=key,
                    passphrase=password)
        signaturesDict[key] = str(signedData)
    return signaturesDict
    

# Returns tuple
# First element is a list with the valid keys
# Second element is a dict with valid keys:signatures
# Arguments:
# keySigs: a dictionary with keys as keys and signatures as values
def getKeysThatSignedData(logging, gpgdir, keySigs, data):
    logHeader = '@getKeysThatSignedData: '
    validKeys = []
    validKeysSigs = {}
    gpg = gnupg.GPG(gnupghome=gpgdir, use_agent=False)
    for fprint in keySigs:
        for key in gpg.list_keys():
            if key['keyid'] == fprint:
                foundKey = True
                break
        if not 'foundKey' in locals():
            continue
        signature = keySigs[fprint]
        verification = gpg.verify(signature)
        if verification.key_id != fprint:
            logging.info(logHeader + 'Wrong verification keyid')
            continue
        if verification.status != 'signature valid':
            logging.info(logHeader + 'Not valid signature')
            continue
        messagePattern = re.compile('(?<=\n\n)\w+')
        extractFromSignature = messagePattern.search(signature)
        if extractFromSignature is None:
            logging.info(logHeader + 'Wrong signature format')
            continue
        result =  extractFromSignature.group(0)
        if result != data:
            logging.info(logHeader + 'Signed data is not the expected')
            logging.info(logHeader + 'Whole signature: {}'.format(signature))
            logging.info(logHeader + 'Result: {}'.format(result))
            logging.info(logHeader + 'dataToCheck: {}'.format(data))
            continue
        validKeys.append(fprint)
        validKeysSigs[fprint] = signature
    return validKeys, validKeysSigs



