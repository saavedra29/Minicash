import socket

def simpleSend(data, remoteaddrs, port, waitResponse=False, timeout=None):
    result = []
    for addr in remoteaddrs:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((addr, port))
            s.sendall(data.encode('utf-8'))
            if waitResponse == True:
                s.settimeout(timeout)
                response = str(s.recv(1024), 'utf-8')
                result.append(response)
        except (socket.timeout, OSError):
            continue
        finally:
            s.close()
    return result




if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('data', type=str, help='Text to send')
    parser.add_argument('remoteaddrs', type=str, help='Comma separated ips')
    parser.add_argument('port', type=int, help='Port to connect')
    parser.add_argument('--wait', dest='wait', action='store_true')
    parser.add_argument('--no-wait', dest='wait', action='store_false')
    parser.set_defaults(wait=True)
    parser.add_argument('timeout', type=float, default=None, help='Timeout if waiting for response')
    args = parser.parse_args()

    remotes = set(args.remoteaddrs.split(','))
    simpleSend(args.data, remotes, args.port, args.wait, args.timeout)

