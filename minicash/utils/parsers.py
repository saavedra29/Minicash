import re
import sys
import os
import hashlib

def isValidProof(fprint, proof, difficulty):
    keyhash = hashlib.sha256()
    fingerproof = fprint + '_' + str(proof)
    keyhash.update(fingerproof.encode('utf-8'))
    hashResult = keyhash.hexdigest()
    if not hashResult.startswith(difficulty * '0'):
        return False
    return True

def isValidSignaturesDict(d):
    for key, sig in d.items():
        if type(key) is not str or type(sig) is not str:
            return False
        if not isValidFingerprint(key):
            return False
    return True
    
def isValidFingerprint(s):
    res = re.match('^[a-fA-F0-9]{16}$', s)
    if res == None:
        return False
    return True

def isValidMD5Sum(s):
    res = re.match('^[a-f0-9]{32}$', s)
    if res == None:
        return False
    return True

def isValidLedgerKey(s):
    fprint = s[:16]
    if not isValidFingerprint(fprint):
        return False
    try:
        if s[16] != '_':
            return False
    except IndexError:
        return False
    proof = s[17:]
    try:
        proofint = int(proof)
    except ValueError:
        return False
    if not isValidProof(fprint, proofint, 6):
        return False
    return True

# Checks for the ledger's format since it's of dict type
def isValidLedger(ledger):
    if type(ledger) is not dict:
        return False
    for key, value in ledger.items():
        if type(key) is not str:
            return False
        if type(value) is not int:
            return False
        if not isValidLedgerKey(key):
            return False
        # Check if balance is 0 or above
        if value < 0:
            return False
        # Check if the sum of all balances is 100000000 times the number of keys
        if len(ledger) != 0:
            numOfKeys = len(ledger)
            balancesSum = 0
            for balance in ledger.values():
                balancesSum += balance
            if balancesSum / numOfKeys != 10000000:
                return False
    return True


class PacketParser:
    def __init__(self, packet = None):
        self.packet = packet
        self.type = None
        self.data = None
        self.errorMessage = None
    
    def setPacket(self, packet):
        self.packet = packet

    def getData(self):
        return self.data

    def getType(self):
        return self.type

    def isPacketValid(self):
        # Check for dict type
        if type(self.packet) is not dict:
            self.errorMessage = 'It is not dict'
            return False
        # Check for packet keys
        if not set(['Type', 'Data']) == set(list(self.packet.keys())):
            self.errorMessage = 'Wrong keys in the packet'
            return False

        # Check for correct types
        validTypes = ['HELLO', 'REQ_LEDGER', 'RESP_LEDGER', 'REQ_INTRO_KEY',
                      'RESP_INTRO_KEY', 'REQ_INTRO_KEY_END', 'REQ_PAY',
                      'RESP_PAY', 'REQ_PAY_END']
        if self.packet['Type'] not in validTypes:
            self.errorMessage = 'Invalid type'
            return False
        
        self.type = self.packet['Type']
        self.data = self.packet['Data']
        # Check for each type exclusively
        # First check if Data is list because only type HELLO has Data of type list
        if type(self.data) is list:
            # HELLO
            if self.type == 'HELLO':
                for val in self.data:
                    if type(val) is not dict:
                        self.errorMessage = 'HELLO: element in Data list is not dict'
                        return False
                    if not set(['Fingerprint', 'ProofOfWork']) == set(list(val.keys())):
                        self.errorMessage = 'HELLO: Wrong Data keys'
                        return False
                    if type(val['Fingerprint']) is not str:
                        self.errorMessage = 'HELLO: Fingerprint value is not a string'
                        return False
                    if not isValidFingerprint(val['Fingerprint']):
                        self.errorMessage = 'HELLO: Fingerprint value has not valid format'
                        return False
                    if type(val['ProofOfWork']) is not int:
                        self.errorMessage = 'HELLO: ProofOfWork value is not int'
                        return False
                    if val['ProofOfWork'] < 0:
                        self.errorMessage = 'HELLO: ProofOfWork is negative'
                        return False
        
        elif type(self.data) is dict:     
            
            # REQ_LEDGER
            if self.type == 'REQ_LEDGER':
                if len(self.data) != 0:
                    self.errorMessage = 'REQ_LEDGER: Data is not empty'
                    return False

            # RESP_LEDGER
            if self.type == 'RESP_LEDGER':
                if not set(['Ledger', 'Signatures']) == set(list(self.data.keys())):
                    self.errorMessage = 'RESP_LEDGER: Wrong Data keys'
                    return False
                if not isValidLedger(self.data['Ledger']):
                    self.errorMessage = 'RESP_LEDGER: Invalid ledger'
                    return False
                if not isValidSignaturesDict(self.data['Signatures']):
                    self.errorMessage = 'RESP_LEDGER: fprints-signatures dict invalid'
                    return False
                
            # REQ_INTRO_KEY
            if self.type == 'REQ_INTRO_KEY':
                if not set(['Key', 'Checksum', 'Sig']) == set(list(self.data.keys())):
                    self.errorMessage = 'REQ_INTRO_KEY: Wrong Data keys'
                    return False
                if not isValidLedgerKey(self.data['Key']):
                    self.errorMessage = 'REQ_INTRO_KEY: Wrong ledger key'
                    return False
                if not isValidMD5Sum(self.data['Checksum']):
                    self.errorMessage = 'REQ_INTRO_KEY: Wrong md5sum format'
                    return False
                if type(self.data['Sig']) is not str:
                    self.errorMessage = 'REQ_INTRO_KEY: The signature is not string'
                    return False

            # RESP_INTRO_KEY and REQ_INTRO_KEY_END
            if self.type == 'RESP_INTRO_KEY' or self.type == 'REQ_INTRO_KEY_END':
                if not set(['Checksum', 'Signatures']) == set(list(self.data.keys())):
                    self.errorMessage = self.type + ': Wrong Data keys'
                    return False
                if not isValidMD5Sum(self.data['Checksum']):
                    self.errorMessage = self.type + ': Wrong md5sum format'
                    return False
                if not isValidSignaturesDict(self.data['Signatures']):
                    self.errorMessage = self.type + ': fprints-signatures dict invalid'
                    return False
                    
            # REQ_PAY
            if self.type == 'REQ_PAY':
                if not set(['Fromkey', 'Tokey', 'Amount', 'Checksum', 'Sig']) == set(list(self.data.keys())):
                    self.errorMessage = 'REQ_PAY: Wrong Data keys'
                    return False
                if not isValidFingerprint(self.data['Fromkey']): 
                    self.errorMessage = 'REQ_PAY: Invalid Fromkey value'
                    return False
                if not isValidFingerprint(self.data['Tokey']): 
                    self.errorMessage = 'REQ_PAY: Invalid Tokey value'
                    return False
                if not type(self.data['Amount']) is float:
                    self.errorMessage = 'REQ_PAY: Amount is not float'
                    return False
                if self.data['Amount'] <= 0:
                    self.errorMessage = 'REQ_PAY: Amount is not larger than 0'
                    return False
                if not isValidMD5Sum(self.data['Checksum']):
                    self.errorMessage = 'REQ_PAY: Invalid checksum value'
                    return False
                if not type(self.data['Sig'] is str):
                    self.errorMessage = 'REQ_PAY: Signature is not string'
                    return False
                    
            # RESP_PAY and REQ_PAY_END
            if self.type == 'RESP_PAY' or self.type == 'REQ_PAY_END':
                if not set(['Checksum', 'Signatures']) == set(list(self.data.keys())):
                    self.errorMessage = self.type + ': Wrong Data keys'
                    return False
                if not isValidMD5Sum(self.data['Checksum']): 
                    self.errorMessage = self.type + ': Invalid checksum value'
                    return False
                if not isValidSignaturesDict(self.data['Signatures']):
                    self.errorMessage = self.type + ': fprints-signatures dict invalid'
                    return False
        else:
            return False
        return True

