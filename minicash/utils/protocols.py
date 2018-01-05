import asyncio
import json

class LedgerRequestProtocol(asyncio.Protocol):
    def __init__(self, message, future, nonce):
        self.message = message
        self.future = future
        self.nonce = nonce

    def connection_made(self, transport):
        self.transport = transport
        messageText = {'Type': 'REQ_LEDGER', 'Nonce': self.nonce}
        messageJson = json.dumps(messageText)
        transport.write(messageJson.encode('utf-8'))

    def data_received(self, data):
        response = json.loads(data.decode('utf-8'))
        self.transport.close()
        self.future.set_result(response)
    
    
