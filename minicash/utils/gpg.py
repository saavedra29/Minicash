import gnupg
import json
import hashlib

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
    


