import asyncio
import json

class LedgerRequestProtocol(asyncio.Protocol):
    def __init__(self, future):
        self.future = future

    def connection_made(self, transport):
        self.transport = transport
        messageText = {'Type': 'REQ_LEDGER', 'Data': {}}
        messageJson = json.dumps(messageText)
        transport.write(messageJson.encode('utf-8'))

    def data_received(self, data):
        response = json.loads(data.decode('utf-8'))
        self.transport.close()
        self.future.set_result(response)
    
    
