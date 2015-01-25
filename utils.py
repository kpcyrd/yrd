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


def grep_ns(ns, ip):
    return [x for x in ns if x['ip'] == ip]


def get_from_route(route, key, default):
    return route[0][key] if route else default


def get_version(route):
    return get_from_route(route, 'version', '??')


def get_path(route):
    return get_from_route(route, 'path', 'NO ROUTE TO HOST')


def dns_resolve(addr):
    addr = addr.split(':')
    addr[0] = socket.gethostbyname(addr[0])
    return ':'.join(addr)


def load_conf(path):
    try:
        with open(path) as f:
            return json.load(f)
    except ValueError:
        raise Exception('failed to load cjdroute.conf as json')
