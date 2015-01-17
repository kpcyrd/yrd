import socket
import json


def generate_key(length):
    key = ''
    with open('/dev/urandom') as f:
        while len(key) < length:
            x = f.read(1)
            if x.isalnum():
                key += x
    return key


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('1.2.3.4', 0))
    return s.getsockname()[0]


def to_credstr(ip, port, publicKey, password, **kwargs):
    addr = '%s:%d' % (ip, int(port))
    kwargs['password'] = password
    kwargs['publicKey'] = publicKey
    return json.dumps({addr: kwargs})[1:-1]
