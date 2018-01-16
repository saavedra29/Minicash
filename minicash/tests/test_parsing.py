import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
from utils.parsers import isValidLedger
from utils.parsers import isValidLedgerResponseFormat

class TestValidLedger(unittest.TestCase):
    
    def testValidLedger(self):
        validLedgers = [
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':3242434120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':0, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {},
            {'8D972AA78B46CBF7_124625':98},
            {'8D972AA78B46CBF7_124625':0}
                ]

        invalidLedgers = [
            {'CC0504FD53A5A5E7_279327':120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793472':120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':-120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':None, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':True, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {34335234:120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, True:23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120.454, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':103.0, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':'jdfkjldjf', '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E6_2793272':120, 'C4ED6700DFB2A1DF_2514606':23, '0FC085CAAB8059F0_802809':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':0.3432, '1BE0B920ABB6D44A_3208670':47, '8D972AA78B46CBF7_124625':98},
            {'CC0504FD53A5A5E7_2793272':120, 'C4ED6700DFB2A1DF_2514606':23, '1BE0B900ABB6D44A_320860':47, '8D972AA78B46CBF7_124625':-98},
            'kdfjldkjfkl', 2342434, True
                ]

            
        for v in validLedgers:
            self.assertTrue(isValidLedger(v))
        for v in invalidLedgers:
            self.assertFalse(isValidLedger(v))

    def testValidResponseFormat(self):
        validResponses = [
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'34224324', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{}, 'Type': 'RESP_LEDGER'}
        ]

        invalidResponses = [
            {'Leder':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Sigatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B4ZCBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER', 'extra_thing':'dfjdlfkj'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Hype': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':2344}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', 49:'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'klfjldj', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': {}},
            '{}',
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':3234, 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESP_LEDGER'},
            {'Ledger':{}, 'Signatures':{'8D972AA78B46CBF7':'dkfjldjk', 'CC0504FD53A5A5E7':'', '3EE3FD7A50CBD975':'kdjfljdklj'}, 'Type': 'RESPLEDGER'}
        ]

        for v in validResponses:
            self.assertTrue(isValidLedgerResponseFormat(v))
        for v in invalidResponses:
            self.assertFalse(isValidLedgerResponseFormat(v))


if __name__ == '__main__':
    unittest.main()
