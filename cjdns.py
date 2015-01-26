from bencode import bencode, bdecode
from hashlib import sha512, sha256
import socket

BUFFER_SIZE = 69632


class Cjdroute(object):
    def __init__(self, ip='127.0.0.1', port=11234, password=''):
        self.password = password

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.connect((ip, port))
        self.s.settimeout(7)

        if not self.ping():
            raise Exception('Not a cjdns socket? (%s:%d)' % (ip, port))

    def disconnect(self):
        self.s.close()

    def recv(self):
        res = bdecode(self.s.recv(BUFFER_SIZE))
        if 'error' in res and res['error'] != 'none':
            raise Exception(repr(res))
        # print(repr(res)) # DEBUG SWITCH
        return res

    def _send(self, **kwargs):
        self.s.send(bencode(kwargs))

    def send(self, **kwargs):
        if self.password:
            self._send(q='cookie')
            cookie = self.recv()['cookie']

            kwargs['hash'] = sha256(self.password + cookie).hexdigest()
            kwargs['cookie'] = cookie

            kwargs['aq'] = kwargs['q']
            kwargs['q'] = 'auth'
            kwargs['hash'] = sha256(bencode(kwargs)).hexdigest()

        self._send(**kwargs)

    def poll(self, **kwargs):
        if 'args' not in kwargs:
            kwargs['args'] = {}
        kwargs['args']['page'] = 0

        while True:
            self.send(**kwargs)
            resp = self.recv()

            yield resp

            if 'more' not in resp:
                break

            kwargs['args']['page'] += 1

    def ping(self):
        self.send(q='ping')
        resp = self.recv()
        return 'q' in resp and resp['q'] == 'pong'

    def nodeForAddr(self, ip=None):
        q = dict(q='NodeStore_nodeForAddr')
        if ip:
            q['ip'] = ip
        self.send(**q)
        return self.recv()

    def dumpTable(self):
        for page in self.poll(q='NodeStore_dumpTable'):
            for route in page['routingTable']:
                yield route

    def genericPing(self, q, path, timeout=5000):
        self.send(q=q, args={'path': path, 'timeout': timeout})
        return self.recv()

    def routerPing(self, *args, **kwargs):
        return self.genericPing('RouterModule_pingNode', *args, **kwargs)

    def switchPing(self, *args, **kwargs):
        return self.genericPing('SwitchPinger_ping', *args, **kwargs)

    def nextHop(self, target, lastNode):
        self.send(q='RouterModule_nextHop',
                  args={'target': target, 'nodeToQuery': lastNode})
        return self.recv()

    def getLink(self, target, num):
        self.send(q='NodeStore_getLink', args={'parent': target,
                                               'linkNum': num})
        return self.recv()

    def addPassword(self, name, password):
        self.send(q='AuthorizedPasswords_add',
                  args={'user': str(name), 'password': str(password)})

    def listPasswords(self):
        self.send(q='AuthorizedPasswords_list')
        return self.recv()

    def removePassword(self, user):
        self.send(q='AuthorizedPasswords_remove', args={'user': user})
        return self.recv()

    def udpBeginConnection(self, addr, pk, password):
        self.send(q='UDPInterface_beginConnection', args={'password': password,
                  'publicKey': pk, 'address': addr})
        return self.recv()

    def peerStats(self):
        for page in self.poll(q='InterfaceController_peerStats'):
            for i, args in page.items():
                if i == 'peers':
                    for peer in args:
                        yield Peer(**peer)


class Peer(object):
    def __init__(self, **kwargs):
        if 'ip' not in kwargs and 'publicKey' in kwargs:
            kwargs['ip'] = pk2ipv6(kwargs['publicKey'])

        for x, y in kwargs.items():
            setattr(self, x, y)


def connect(ip='127.0.0.1', port=11234, password=''):
    return Cjdroute(ip, port, password)


# see util/Base32.h
def Base32_decode(input):
    output = bytearray(len(input))
    numForAscii = [
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99, 99, 99, 99, 99, 99,
        99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19, 20, 99,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99,
        99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19, 20, 99,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99,
    ]

    outputIndex = 0
    inputIndex = 0
    nextByte = 0
    bits = 0

    while inputIndex < len(input):
        o = ord(input[inputIndex])
        if o & 0x80:
            raise ValueError
        b = numForAscii[o]
        inputIndex += 1
        if b > 31:
            raise ValueError("bad character " + input[inputIndex])

        nextByte |= b << bits
        bits += 5

        if bits >= 8:
            output[outputIndex] = nextByte & 0xff
            outputIndex += 1
            bits -= 8
            nextByte >>= 8

    if bits >= 5 or nextByte:
        raise ValueError("bits is %d and nextByte is %d" % (bits, nextByte))

    return buffer(output, 0, outputIndex)


def pk2ipv6(pubKey):
    if pubKey[-2:] != ".k":
        raise ValueError("key does not end with .k")

    keyBytes = Base32_decode(pubKey[:-2])
    hashOne = sha512(keyBytes).digest()
    hashTwo = sha512(hashOne).hexdigest()

    return ":".join([hashTwo[i:i+4] for i in range(0, 32, 4)])
