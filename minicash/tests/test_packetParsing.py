import unittest
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils.parsers import PacketParser


class TestValidPacket(unittest.TestCase):
    def setup(self):
        self.helloExample = {
            'Type': 'HELLO',
            'Data': [
                {'Fingerprint':'C4ED6700DFB2A1DF', 'ProofOfWork':2514606},
	            {'Fingerprint':'A22F2D8422520966', 'ProofOfWork':722303}
            ]           
        }

        self.reqLedgerExample = {
            'Type':'REQ_LEDGER',
            'Data': {}
        }

        self.respLedgerExample = {
            'Type':'RESP_LEDGER',
            'Data':{
	            'Ledger':{
			        'C4ED6700DFB2A1DF_2514606':45423343,
			        'A22F2D8422520966_3454529':45560343
			    },
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	   		    }
	        }
        }

        self.reqIntroKeyExample = {
            'Type':'REQ_INTRO_KEY',
            'Data':{
	            'Key':'C4ED6700DFB2A1DF_2514606',
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Sig':'-----BEGIN PGP...'
	        }    
        }

        self.respIntroKeyExample = {
            'Type':'RESP_INTRO_KEY',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }

        self.reqIntroKeyEndExample = {
            'Type':'REQ_INTRO_KEY_END',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }

        self.reqPayExample = {
            'Type':'REQ_PAY',
            'Data': {
                'Fromkey':'C4ED6700DFB2A1DF',
                'Tokey':'A22F2D8422520966',
                'Amount':4545446,
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Sig':'-----BEGIN PGP...'
            }
        }

        self.respPayExample = {
            'Type':'RESP_PAY',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }

        self.reqPayEndExample = {
            'Type':'REQ_PAY_END',
            'Data':{
	            'Checksum':'e811ba851763f04a1c54591bb748a424',
	            'Signatures':{
				    'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
				    'A22F2D8422520966':'-----BEGIN PGP...'
	            }
            }
        }

    def test_validity(self):
        casesUndumped = [
            'dlfjdfjdlfjl',
            True,
            None,
            2305340,
            {},
            ['dkfldjf', 32424]
        ]
        casesToDump = [
            {
                'hype': 'HELLO',
                'Data': [
                    {'Fingerprint':'C4ED6700DFB2A1DF', 'ProofOfWork':2514606},
                    {'Fingerprint':'A22F2D8422520966', 'ProofOfWork':722303}
                ]           
            },
            {
                'Type':'RSP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2514606':45423343,
                        'A22F2D8422520966_3454529':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            },
            # wrong Data key
            {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledge':{
                        'C4ED6700DFB2A1DF_2514606':45423343,
                        'A22F2D8422520966_3454529':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            },
            # invalid key (Tokey)
            {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520T66',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            },
            # longer checksum
            {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba8517663f0ff4a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            },
            # wrong Data key (str)
            {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    30:'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            },
            # invalid Amount type
            {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':'4545446',
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            },
            # extra key (Result)
            {
                'Type':'REQ_PAY',
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                },
                'Result':{}
            },
            # Type missing
            {
                'Data': {
                    'Fromkey':'C4ED6700DFB2A1DF',
                    'Tokey':'A22F2D8422520966',
                    'Amount':4545446,
                    'Checksum':'e811ba851763f04a1c54591bb748a424',
                    'Sig':'-----BEGIN PGP...'
                }
            },
            {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2514606':45423343.34,
                        'A22F2D8422520966_3454529':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            },
            # wrong proof of work
            {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF_2513606':45423343,
                        'A22F2D8422520966_3454529':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            },
            # wrong address separator
            {
                'Type':'RESP_LEDGER',
                'Data':{
                    'Ledger':{
                        'C4ED6700DFB2A1DF&2514606':45423343,
                        'A22F2D8422520966_3454529':45560343
                    },
                    'Signatures':{
                        'C4ED6700DFB2A1DF':'-----BEGIN PGP...',
                        'A22F2D8422520966':'-----BEGIN PGP...'
                    }
                }
            }
        ]


        # Test for wrong inputs
        toTest = []
        for case in casesUndumped:
            toTest.append(case)
        for case in casesToDump:
            toTest.append(json.dumps(case))

        for case in toTest:
            parser = PacketParser(case)
            self.assertFalse(parser.isPacketValid())

        # Test for correct inputs
        toTest = [self.helloExample, self.reqLedgerExample, self.respLedgerExample, 
                  self.reqIntroKeyExample, self.respIntroKeyExample, self.reqIntroKeyEndExample,
                  self.reqPayExample, self.respPayExample, reqPayEndExample]
        toTestDumped = []
        for case in toTest:
            toTestDumped.append(json.dumps(case))
        for case in toTestDumped:
            parser = PacketParser(case)
            self.assertTrue(parser.isPacketValid())









