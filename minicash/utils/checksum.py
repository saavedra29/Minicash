import hashlib

def getmd5(data):
    datahash = hashlib.md5()
    datahash.update(data.encode('utf-8'))
    return datahash.hexdigest()

def getsha256(data):
    datahash = hashlib.sha256()
    datahash.update(data.encode('utf-8'))
    return datahash.hexdigest()

def isValidProof(fprint, proof, difficulty):
    hashResult = getsha256(fprint + '_' + str(proof))
    if not hashResult.startswith(difficulty * '0'):
        return False
    return True

