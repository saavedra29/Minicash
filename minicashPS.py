import json
import socketserver
import re
import argparse

peersMap = {}

class PeerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global peersMap
        try:
            peerRequest = json.loads(self.request.recv(1024).decode('utf-8'))
        except json.JSONDecodeError as e:
            self.request.sendall(json.dumps({'RESPONSE': 'Fail', \
                                             'Reason': 'JsonDecode error'}).encode('utf-8'))
            return
        if not 'Type' in peerRequest:
            self.request.sendall(json.dumps({'RESPONSE': 'Fail', \
                                 'Reason': 'No Type entry'}).encode('utf-8'))
            return
        if peerRequest['Type'] == 'REG':
            update = False
        elif peerRequest['Type'] == 'REGUP':
            update = True
        else:
            self.request.sendall(json.dumps({'RESPONSE': 'Fail', 
                                             'Reason': 'Wrong request type'}).encode('utf-8'))
            return

        if not 'Keys' in peerRequest:
            self.request.sendall(json.dumps({'RESPONSE': 'Fail', 'Reason': \
                                             'No Keys entry'}).encode('utf-8'))
            return
        if not type(peerRequest['Keys']) == list:
            self.request.sendall(json.dumps({'RESPONSE': 'Fail', \
                                            'Reason': 'Keys element is not list'}).encode('utf-8'))
            return

        clientAddress = self.client_address[0]
        partial = False
        for key in peerRequest['Keys']:
            fprint = key['Fingerprint']
            proof = key['ProofOfWork']
            if (type(fprint) is not str) or (type(proof) is not str):
                partial = True
                continue
            # Check for correct fingerprint format
            res = re.match('^[a-fA-F0-9]{16}$', fprint)
            if res == None or not proof.isdigit():
                partial = True
                continue
            peersMap[fprint] = {'Proof':proof, 'Ip':clientAddress}

        if partial == False:
            response = {'RESPONSE': 'Success'}
        else:
            response = {'RESPONSE': 'Partial-Success'}
        if update == True:
            response['Maps'] = peersMap

        # Write data to disk
        try:
            with open('peersFile.txt', 'w') as peersFile:
                try:
                    peersFile.write(json.dumps(peersMap, indent=4))
                except json.JSONDecodeError as e:
                    print('JSONDecodeError while writting peers file: {}'.format(e))
        except IOError as e:
            print('IOError while writting peers file: {}'.format(e))

        self.request.sendall(json.dumps(response).encode('utf-8'))



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-locally', action='store_true',
                        help='Be accesible only from localhost')
    # Load from the memory existing ip peers file
    try:
        with open('peersFile.txt', 'r') as peersFile:
            try:
                peersMap = json.load(peersFile)
            except json.JSONDecodeError as e:
                print('Json Error loading peersFile.txt: {}'.format(e))
                exit()
    except IOError as e:
        print('IOError opening peersFile.txt: {}'.format(e))
        exit()

    args = parser.parse_args()
    if args.run_locally:
        host = '127.0.0.1'
    else:
        host = ''
    port = 9999
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((host, port), PeerHandler) as server:
        server.serve_forever()
