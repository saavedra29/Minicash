import asyncio
import json

class RequestProtocol(asyncio.Protocol):
    def __init__(self, message):
        self.message = message

    def connection_made(self, transport):
        self.transport = transport
        messageJson = json.dumps(self.message)
        transport.write(messageJson.encode('utf-8'))
        transport.write_eof()

    
class RequestResponseProtocol(asyncio.Protocol):
    def __init__(self, future, message):
        self.future = future
        self.message = message
        self.fullMessage = bytes()
        self.response = bytes()

    def connection_made(self, transport):
        self.transport = transport
        messageJson = json.dumps(self.message)
        self.transport.write(messageJson.encode('utf-8'))
        self.transport.write_eof()

    def data_received(self, data):
        self.fullMessage += data

    def eof_received(self):
        try:
            res = json.loads(self.fullMessage.decode('utf-8'))
        except json.decoder.JSONDecodeError:
            res = None
        self.future.set_result(res)
    
    def connection_lost(self, exc):
        self.transport.close()

    
def sendReceiveToMany(message, ips):
    async def connect(ip, loop):
        future = asyncio.Future()
        try:
            await loop.create_connection(lambda: RequestResponseProtocol(future, message), ip , 2222)
        except (OSError, ConnectionRefusedError):
            return
        await future
        return future

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = []
    for ip in ips:
        task = asyncio.ensure_future(connect(ip, loop))
        tasks.append(task)
    results = loop.run_until_complete(asyncio.gather(*tasks))   
    loop.close()
    while None in results:
        results.remove(None)
    rawResults = []
    for res in results:
        rawResults.append(res.result())
    return rawResults


def sendToMany(message, ips):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    tasks = []
    for ip in ips:
        task = loop.create_connection(lambda: RequestProtocol(message), ip , 2222) 
        tasks.append(task)
    try:
        results = loop.run_until_complete(asyncio.gather(*tasks))   
    except ConnectionRefusedError:
        pass
    loop.close()

