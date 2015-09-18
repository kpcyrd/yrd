from argh import arg, wrap_errors
from . import utils
from .peer import add
from random import shuffle
import time


class DhtPeer(object):
    def __init__(self, ip, port, publicKey, password, ts=None, **kwargs):
        self.ip = ip
        self.port = port
        self.publicKey = publicKey
        self.password = password
        self.kwargs = kwargs

    def credentialstr(self):
        return utils.to_credstr(self.ip, self.port, self.publicKey,
                                self.password, **self.kwargs)


def request_peers(desired, tracker):
    import requests
    response = requests.get(tracker).json

    if not type(response) is list:
        response = response()

    for peer in shuffle(response)[:desired]:
        try:
            yield DhtPeer(**peer)
        except TypeError:
            pass


def _announce(tracker, **kwargs):
    import requests
    resp = requests.post(tracker, json=kwargs).json()
    return resp['status'] == 'success'


def get(desired, *trackers):
    'query public peers'
    for tracker in trackers:
        for peer in request_peers(desired, tracker):
            yield peer.credentialstr()


def auto(desired, *trackers):
    'connect to public peers'
    for tracker in trackers:
        for peer in request_peers(desired, tracker):
            addr = '%s:%d' % (peer.ip, peer.port)
            add(peer.ip, addr, peer.publicKey, peer.password)
            yield '[+] peered with %s' % addr


@arg('tracker', help='the tracker you want to announce on')
@arg('password', help='the password you want to share')
@arg('-1', '--oneshot', help='if you want to announce per cronjob')
@arg('contact', nargs='?', help='if you want to allow contact')
@wrap_errors([KeyboardInterrupt, IOError])
def announce(tracker, password, contact, oneshot=False):
    'announce yourself as public peer'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)

    addr = conf['interfaces']['UDPInterface'][0]['bind']
    peer = {
        'port': int(addr.split(':')[1]),
        'publicKey': conf['publicKey'],
        'password': password
    }

    if contact:
        peer['contact'] = contact

    while True:
        try:
            if _announce(tracker, **peer):
                yield '[+] Told the tracker we\'re here'
        except (IOError, ValueError) as e:
            yield '[-] %s' % e

        if oneshot:
            break

        time.sleep(120)


cmd = [get, auto, announce]
