import gnupg
import json
import hashlib
import re

def getmd5(data):
    datahash = hashlib.md5()
    datahash.update(data.encode('utf-8'))
    return datahash.hexdigest()


def signWithKeys(gpgdir, privateKeys, keysToUse, data, password):
    if type(data) is dict:
        hashedData = getmd5(json.dumps(data, sort_keys=True))
    else:
        hashedData = getmd5(data)
    gpg = gnupg.GPG(gnupghome=gpgdir)
    signaturesDict = {}
    existingKeys = []
    # Check for existing keys
    for searchingKey in keysToUse:
        for listedKey in gpg.list_keys(True):
            if searchingKey == listedKey['keyid']:
                existingKeys.append(searchingKey)

    for key in existingKeys:
        signedData = gpg.sign(hashedData, keyid=key,
                    passphrase=password)
        signaturesDict[key] = str(signedData)
    return signaturesDict
    

def getKeysThatSignedData(logging, gpgdir, keySigs, data):
    validKeys = []
    gpg = gnupg.GPG(gnupghome=gpgdir)
    for fprint in keySigs:
        for key in gpg.list_keys():
            if key['keyid'] == fprint:
                logging.info('Checking key {}..'.format(fprint))
                foundKey = True
                break
        if not 'foundKey' in locals():
            continue
        signature = keySigs[fprint]
        verification = gpg.verify(signature)
        if verification.key_id != fprint:
            logging.info('Wrong verification keyid')
            continue
        if verification.status != 'signature valid':
            logging.info('Not valid signature')
            continue
        messagePattern = re.compile('(?<=\n\n)\w+')
        extractFromSignature = messagePattern.search(signature)
        if extractFromSignature is None:
            logging.info('Wrong signature format')
            continue
        result =  extractFromSignature.group(0)
        if result != data:
            logging.info('Signed data is not the expected')
            logging.info('Whole signature: {}'.format(signature))
            logging.info('Result: {}'.format(result))
            logging.info('dataToCheck: {}'.format(data))
            continue
        validKeys.append(fprint)
    return validKeys



