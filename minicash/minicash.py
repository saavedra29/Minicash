import argparse
import json
import socket
import pprint as pp
import inspect
from utils.pow import POWGenerator


def getResponse(command):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2223))
        s.send(command.encode('utf-8'))
        response = s.recv(64000)
        s.close()
    except ConnectionError:
        print('Connection problem with the server. Probably the server is offline')
        exit()
    return str(response, 'utf-8')


def getPayload(command, params):
    payload = {
        'method': command,
        'params': params,
        'jsonrpc': '2.0',
        'id': 0,
    }
    return payload


def runCommand(commandName, args):
    params = dict(vars(args))
    _ = params.pop('func')
    datatosend = json.dumps(getPayload(commandName, [params]))
    try:
        datatosend = json.dumps(getPayload(commandName, [params]))
        response = json.loads(getResponse(datatosend))
    except json.decoder.JSONDecodeError as e:
        return {'Fail': {'Reason': 'JSONDecodeError', 'Message': e}}
    if 'error' in response:
        return {'Fail': {'Reason': 'json-rpc', 'Message': response['error']['message']}}
    return response['result']


def init(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))


def listLocalKeys(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))


def listPeers(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))


def getBalances(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))


def pay(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))


def genPow(args):
    powGenerator = POWGenerator(args.key, args.difficulty, args.cores)
    result = powGenerator.getSolution()
    print('The solution is {}'.format(result))


def addKey(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))

def getLogInfo(args):
    pp.pprint(runCommand(inspect.stack()[0][3], args))

def stop(args):
    payload = {
        'method': 'stop',
        'params': [],
        'jsonrpc': '2.0',
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2223))
        data = json.dumps(payload)
        s.send(data.encode('utf-8'))
        s.close()
    except ConnectionError:
        print('Connection problem with the server. Probably the server is offline')
        exit()


## COMMAND LINE PARSER
parser = argparse.ArgumentParser()
subparser = parser.add_subparsers()
# init subcommand
init_cmd = subparser.add_parser('init', help='Create new, fresh file structure')
init_cmd.set_defaults(func=init)
# list-nodes subcommand
listnodes_cmd = subparser.add_parser('listpeers', help='List all online nodes in the network')
listnodes_cmd.add_argument('--with-keys', action='store_true',
                           help='Show also the keys assigned to them')
listnodes_cmd.set_defaults(func=listPeers)
# getloginfo subcommand
init_cmd = subparser.add_parser('getloginfo', help='Read the log file')
init_cmd.set_defaults(func=getLogInfo)
# listlocalkeys subcommand
listlocalkeys_cmd = subparser.add_parser('listlocalkeys', help='List all local keys fingerprints')
listlocalkeys_cmd.set_defaults(func=listLocalKeys)
# gen-pow subcommand
pow_cmd = subparser.add_parser('gen-pow', help='Create proof of work')
pow_cmd.add_argument('--cores', type=int, choices=range(1, 65), help='How many cores to use',
                     default=8, metavar='<1-64>')
pow_cmd.add_argument('difficulty', type=int, choices=range(1, 21), help='How many leading zeros \
    at pow', metavar='<1-20>')
pow_cmd.add_argument('key', help='The gpg key fingerprint')
pow_cmd.set_defaults(func=genPow)
# add-key subcommand
addkey_cmd = subparser.add_parser('add-key', help='Add existing key in the node')
addkey_cmd.add_argument('--upload', action='store_true', help='Upload key to keyserver')
addkey_cmd.add_argument('key', help='The gpg fingerprint')
addkey_cmd.add_argument('pow', help='The proof of work number')
addkey_cmd.set_defaults(func=addKey)
# get-balances subcommand
getbalances_cmd = subparser.add_parser('getbalances', help='Get the balances')
getbalances_cmd.set_defaults(func=getBalances)
# stop subcommand
stop_cmd = subparser.add_parser('stop', help='Stop the server')
stop_cmd.set_defaults(func=stop)
# pay_subcommand
pay_cmd = subparser.add_parser('pay', help='Pay to other key')
pay_cmd.add_argument('from', help='The output fingerprint')
pay_cmd.add_argument('to', help='The input fingerprint')
pay_cmd.add_argument('amount', help='The amount to pay')
pay_cmd.set_defaults(func=pay)

if __name__ == '__main__':
    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        print('You haven\'t entered any subcommand or argument')
