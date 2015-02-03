import nacl.secret
import nacl.utils
from nacl.public import PublicKey, PrivateKey, Box
from nacl.encoding import Base64Encoder
from urlparse import urlparse, parse_qs
from urllib import urlencode
import json

WRBT_VERSION = 1
PREFIX = 'http://wrbt.hyperboria.net/'


def encode(k):
    return k.encode(encoder=Base64Encoder)


def decode(url):
    fragment = urlparse(url).fragment
    return parse_qs(fragment)


def request():
    pk = PrivateKey.generate()
    query = {'type': 'peer', 'interface': 'udp', 'pk': encode(pk.public_key),
             'wrbtVersion': WRBT_VERSION}
    url = PREFIX + '#' + urlencode(query)
    return url, encode(pk)


def confirm(request, addr, publicKey, password):
    public = PublicKey(request['pk'][0], encoder=Base64Encoder)
    response = {'credentials': {('%s:%s' % addr): {'publicKey': publicKey,
                'password': password}}}
    response = json.dumps(response)

    private = PrivateKey.generate()
    box = Box(private, public)
    nonce = nacl.utils.random(Box.NONCE_SIZE)
    encrypted = box.encrypt(response, nonce)

    offer = {'type': 'credentials', 'interface': 'udp', 'message': encrypted,
             'pk': encode(private.public_key), 'wrbtVersion': WRBT_VERSION}

    return PREFIX + '#' + urlencode(offer)


def decrypt(pk, offer):
    private = PrivateKey(pk, encoder=Base64Encoder)
    public = PublicKey(offer['pk'][0], encoder=Base64Encoder)

    box = Box(private, public)
    return json.loads(box.decrypt(offer['message'][0]))
