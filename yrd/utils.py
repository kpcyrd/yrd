from subprocess import Popen, PIPE
from datetime import datetime
import socket
import json


def ts2time(ts):
    return datetime.fromtimestamp(ts).strftime('%H:%M:%S')


def raise_on_error(resp):
    if 'error' in resp and resp['error'] != 'none':
        raise Exception(resp['error'])


def generate_key(length):
    key = b''
    with open('/dev/urandom', 'rb') as f:
        while len(key) < length:
            x = f.read(1)
            if x.isalnum():
                key += x
    return str(key, 'ascii')


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('1.2.3.4', 0))
    return s.getsockname()[0]


def to_credstr(ip, port, publicKey, password, strict=False, **kwargs):
    addr = '%s:%d' % (ip, int(port))
    kwargs['password'] = password
    kwargs['publicKey'] = publicKey
    cred = json.dumps({addr: kwargs})
    return cred if strict else cred[1:-1]


def grep_ns(ns, addr):
    return [x for x in ns if x['addr'] == addr]


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


def load_conf(conf, bin):
    try:
        with open(conf, 'rb') as f:
            conf = f.read()

        p = Popen([bin, '--cleanconf'], stdin=PIPE, stdout=PIPE)
        conf = p.communicate(conf)[0]
        try:
            conf = str(conf, 'ascii')
        except:
            pass
        return json.loads(conf)
    except ValueError:
        raise Exception('failed to load cjdroute.conf as json')


def speed(b):
    for unit in ['B', 'Kb', 'Mb', 'Gb', 'Tb']:
        if b < 1024:
            break
        b = round(b / 1024, 2)

    return '%d %s/s' % (b, unit)


def get_nodeinfo(ip, hub=False):
    import requests

    if hub:
        url = 'http://api.hyperboria.net/v0/node/info.json?ip=%s' % ip
        title = 'hub.hyperboria.net'
    else:
        url = 'http://[%s]/nodeinfo.json' % ip
        title = 'nodeinfo.json'

    j = requests.get(url).json
    if not type(j) is dict:
        j = j()
    return j, title
