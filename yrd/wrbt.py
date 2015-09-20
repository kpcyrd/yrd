from .arg import arg, wrap_errors, named
from . import utils
try:
    from urlparse import urlparse, parse_qs
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlparse, parse_qs, urlencode
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
    import libnacl
    my_public, my_private = libnacl.crypto_box_keypair()
    query = {'type': 'peer', 'interface': 'udp', 'pk': b64encode(my_public),
             'wrbtVersion': WRBT_VERSION}
    url = PREFIX + '#' + urlencode(query)
    return url, b64encode(my_private)


def _confirm(request, addr, publicKey, password):
    import libnacl
    import libnacl.utils
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
    import libnacl
    my_private = b64decode(pk)
    her_public = b64decode(offer['pk'][0])

    msg = b64decode(offer['message'][0])
    nonce = b64decode(offer['n'][0])
    msg = libnacl.crypto_box_open(msg, nonce, her_public, my_private)
    return json.loads(msg)


def seek():
    'create a peering request'
    url, pk = request()
    yield 'Import offer: yrd wrbt import "%s" <offer>' % pk
    yield url


def confirm(name, url):
    'confirm a peering request'
    request = decode(url)

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)

    host = utils.get_ip()
    port = conf['interfaces']['UDPInterface'][0]['bind'].split(':')[1]
    publicKey = conf['publicKey']
    password = utils.generate_key(31)

    # TODO: authorize

    yield _confirm(request, (host, port), publicKey, password)


@arg('-d', '--display', help='display only')
@named('import')
def _import(pk, url, display=False):
    'import a peering offer'
    offer = decode(url)
    msg = decrypt(pk, offer)

    if display:
        yield msg
    else:
        for addr, creds in msg['credentials'].items():
            name = addr.split(':')[0]
            from .peer import add
            add(name, addr, creds['publicKey'], creds['password'])
            yield '[+] peered with %s' % addr


cmd = [seek, confirm, _import]
