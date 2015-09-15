import libnacl
import libnacl.utils
from urlparse import urlparse, parse_qs
from urllib import urlencode
from base64 import b64encode, b64decode
import json

WRBT_VERSION = 1
PREFIX = 'http://wrbt.hyperboria.net/'


def encode(k):
    return k.encode(encoder=Base64Encoder)


def decode(url):
    fragment = urlparse(url).fragment
    return parse_qs(fragment)


def request():
    my_public, my_private = libnacl.crypto_box_keypair()
    query = {'type': 'peer', 'interface': 'udp', 'pk': b64encode(my_public),
             'wrbtVersion': WRBT_VERSION}
    url = PREFIX + '#' + urlencode(query)
    return url, b64encode(my_private)


def confirm(request, addr, publicKey, password):
    her_public = b64decode(request['pk'][0])
    response = {'credentials': {('%s:%s' % addr): {'publicKey': publicKey,
                'password': password}}}
    response = json.dumps(response)

    my_public, my_private = libnacl.crypto_box_keypair()
    nonce = libnacl.utils.rand_nonce()
    encrypted = b64encode(libnacl.crypto_box(response, nonce,
                                             her_public, my_private))

    offer = {'type': 'credentials', 'interface': 'udp', 'message': encrypted,
             'n': b64encode(nonce), 'pk': b64encode(my_public),
             'wrbtVersion': WRBT_VERSION}

    return PREFIX + '#' + urlencode(offer)


def decrypt(pk, offer):
    my_private = b64decode(pk)
    her_public = b64decode(offer['pk'][0])

    msg = b64decode(offer['message'][0])
    nonce = b64decode(offer['n'][0])
    msg = libnacl.crypto_box_open(msg, nonce, her_public, my_private)
    return json.loads(msg)
