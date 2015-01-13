from bencode import bencode, bdecode
from hashlib import sha512
import socket

BUFFER_SIZE = 69632


class Cjdroute(object):
    def __init__(self, ip='127.0.0.1', port=11234, password=''):
        self.funcs = {}

        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.connect((ip, port))
        self.s.settimeout(2)

        if not self.ping():
            raise Exception('Not a cjdns socket? (%s:%d)' % (ip, port))

        self.registerFunctions()

    def recv(self):
        return bdecode(self.s.recv(BUFFER_SIZE))

    def send(self, **kwargs):
        self.s.send(bencode(kwargs))

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

    def registerFunctions(self):
        for page in self.poll(q='Admin_availableFunctions'):
            for func, opts in page['availableFunctions'].items():
                self.funcs[func] = opts

    def getPeers(self):
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


def pk2ipv6(publicKey):
    return 'fcc7:f439:fe7e:2c87:8bc9:caee:87a7:79ec'


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
