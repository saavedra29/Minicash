import hashlib

def isValidProof(fprint, proof):
    keyhash = hashlib.sha256()
    fingerproof = fprint + '_' + str(proof)
    keyhash.update(fingerproof.encode('utf-8'))
    hashResult = keyhash.hexdigest()
    if not hashResult.startswith('00000'):
        return False
    return True


def getmd5(data):
    datahash = hashlib.md5()
    datahash.update(data.encode('utf-8'))
    return datahash.hexdigest()
