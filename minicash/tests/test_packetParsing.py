import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils.parsers import PacketParser
from utils.parsers import isValidLedgerKey


class TestLedgerKey(unittest.TestCase):
    def test_ledgerKey(self):
        correctCases = [
            'C4ED6700DFB2A1DF_2514606',
            'A22F2D8422520966_23753504'
        ]

        wrongCases = [
            'C4ED6700DFB2A1DT_2514606',  # wrong key format
            'A22F2D8422520966_2375504',  # wrong proof
            'C4ED6700DFB2A1DF&2514606',
            'A22F2D842252096_23753504',
            'C4ED6700DFB2A1DF_-30',
            'A22F2D842252096623753504'
        ]
        
        for case in correctCases:
            self.assertTrue(isValidLedgerKey(case))
        for case in wrongCases:
            self.assertFalse(isValidLedgerKey(case))


class TestValidPacket(unittest.TestCase):

    def test_string(self):
        packet = 'kdlfdfjdklfjldf'
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_True(self):
        packet = True
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_None(self):
        packet = None
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_int(self):
        packet = 34441
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_emptyDict(self):
        packet = {}
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_list(self):
        packet = ['Aris', 4554]
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_key(self):
        packet = {
                'hype': 'HELLO',
                'Data': [
                    {'Fingerprint':'C4ED6700DFB2A1DF', 'ProofOfWork':2514606},
                    {'Fingerprint':'A22F2D8422520966', 'ProofOfWork':23753504}
                ]           
        }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_type_val(self):
        packet = {
                'Type':'RSP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2514606':45423343,
                        'A22F2D8422520966_23753504':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
            }
        }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_dataKey(self):
        packet = {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledge':{
                        'C4ED6700DFB2A1DF_2514606':10000000,
                        'A22F2D8422520966_23753504':10000000
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_invalidTokey(self):
        packet = {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520T66',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_longChecksum(self):
        packet = {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba8517663f0ff4a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_invalidDataKey(self):
        packet = {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    30:'A22F2D8422520966',
                    'Amount':4545446.43,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_invalidAmountType(self):
        packet = {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':'4545446',
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_extraKeyResult(self):
        packet = {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                },
                'Result':{}
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_typeMissing(self):
        packet = {
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_ledgerNonIntVal(self):
        packet = {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2514606':100000000.34,
                        'A22F2D8422520966_23753504':99999999.66
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_wrongProof(self):
        packet = {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2513606':100000000,
                        'A22F2D8422520966_23753504':100000000
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_wrong_separator(self):
        packet = {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF&2514606':100000000,
                        'A22F2D8422520966_23753504':100000000
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))
        
    def test_negativeProof(self):
        packet = {
                'Type': 'HELLO',
                'Data': [
                    {'Fingerprint':'C4ED6700DFB2A1DF', 'ProofOfWork':-2514606},
                    {'Fingerprint':'A22F2D8422520966', 'ProofOfWork':23753504}
                ]           
            }
        parser = PacketParser(packet)
        self.assertFalse(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

## TEST CORRECT PACKETS
        
    def test_correctHello(self):
        message = {
            'Type': 'HELLO',
            'Data': [
                {'Fingerprint':'C4ED6700DFB2A1DF', 'ProofOfWork':2514606},
	            {'Fingerprint':'A22F2D8422520966', 'ProofOfWork':23753504}
            ]           
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctReqLedger(self):
        message = {
            'Type':'REQ_LEDGER',
            'Data': {}
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctRespLedger(self):
        message = {
            'Type':'RESP_LEDGER',
            'Data':{
	            'Ledger':{
			        'C4ED6700DFB2A1DF_2514606':10000000,
			        'A22F2D8422520966_23753504':10000000
			    },
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	   		    }
	        }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctReqIntroKey(self):
        message = {
            'Type':'REQ_INTRO_KEY',
            'Data':{
	            'Key':'C4ED6700DFB2A1DF_2514606',
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Sig':'-----BEGIN PGP...'
	        }    
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctRespIntroKey(self):
        message = {
            'Type':'RESP_INTRO_KEY',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctReqIntroKeyEnd(self):
        message = {
            'Type':'REQ_INTRO_KEY_END',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctReqPay(self):
        message = {
            'Type':'REQ_PAY',
            'Data': {
                'Fromkey':'C4ED6700DFB2A1DF',
                'Tokey':'A22F2D8422520966',
                'Amount':4545446.45,
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Sig':'-----BEGIN PGP...'
            }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctRespPay(self):
        message = {
            'Type':'RESP_PAY',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))

    def test_correctReqPayEnd(self):
        message = {
            'Type':'REQ_PAY_END',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }
        parser = PacketParser(message)
        self.assertTrue(parser.isPacketValid())
        if parser.errorMessage != None:
            print('Error: {}'.format(parser.errorMessage))








