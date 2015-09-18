from argh import arg, dispatch, wrap_errors, aliases, named, ArghParser
from subprocess import Popen, PIPE
from . import utils
from . import peer
from .const import YRD_FOLDER, YRD_PEERS, CJDROUTE_CONF, CJDROUTE_BIN
import json
import time
import os


@arg('--attach', help='configure running cjdroute')
@arg('--boot', help='bootstraps network access')
@wrap_errors([KeyboardInterrupt, IOError])
def start(attach=False, boot=False):

    if not attach:
        p = Popen(['cjdroute'], stdin=PIPE)
        conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
        p.communicate(json.dumps(conf))

    for peer in os.listdir(YRD_PEERS):
        yield '[*] adding %r' % peer
        try:
            with open(os.path.join(YRD_PEERS, peer)) as f:
                info = json.load(f)
        except ValueError:
            yield '[-] invalid json'
        else:
            if info['type'] == 'in':
                try:
                    list(peer_auth(info['name'], info['password'], live=True))
                except KeyError:
                    yield '[-] key error'
            elif info['type'] == 'out':
                list(peer_add(peer, info['addr'], info['pk'], info['password'], live=True))

    if boot:
        bootstrap()


def bootstrap():
    'bootstraps network access'
    import bootstrap as boot
    nf_peer(boot.DESIRED, [x + boot.TOPIC + '/seek/' for x in bootstrap.trackers])


from .core import a
from .core import ping
from .core import r
from .core import n
from .core import top
from .core import mon
from .core import uplinks
from .core import whois

from .peer import auth as peer_auth
from .peer import add as peer_add
from .peer import ls as peer_ls
from .peer import remove as peer_remove


@named('get')
def nf_get(desired, *trackers):
    'query public peers'
    from . import nf
    for tracker in trackers:
        for peer in nf.request_peers(desired, tracker):
            yield peer.credentialstr()


@named('peer')
def nf_peer(desired, *trackers):
    'connect to public peers'
    from . import nf
    for tracker in trackers:
        for peer in nf.request_peers(desired, tracker):
            addr = '%s:%d' % (peer.ip, peer.port)
            peer_add(peer.ip, addr, peer.publicKey, peer.password)
            yield '[+] peered with %s' % addr


@arg('tracker', help='the tracker you want to announce on')
@arg('password', help='the password you want to share')
@arg('-1', '--oneshot', help='if you want to announce per cronjob')
@arg('contact', nargs='?', help='if you want to allow contact')
@named('announce')
@wrap_errors([KeyboardInterrupt, IOError])
def nf_announce(tracker, password, contact, oneshot=False):
    'announce yourself as public peer'
    from . import nf

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
            if nf.announce(tracker, **peer):
                yield '[+] Told the tracker we\'re here'
        except (IOError, ValueError) as e:
            yield '[-] %s' % e

        if oneshot:
            break

        time.sleep(120)


@named('seek')
def wrbt_seek():
    'create a peering request'
    from . import wrbt
    url, pk = wrbt.request()
    yield 'Import offer: yrd wrbt import "%s" <offer>' % pk
    yield url


@named('confirm')
def wrbt_confirm(name, url):
    'confirm a peering request'
    from . import wrbt
    request = wrbt.decode(url)

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)

    host = utils.get_ip()
    port = conf['interfaces']['UDPInterface'][0]['bind'].split(':')[1]
    publicKey = conf['publicKey']
    password = utils.generate_key(31)

    # TODO: authorize

    yield wrbt.confirm(request, (host, port), publicKey, password)


@arg('-d', '--display', help='display only')
@named('import')
def wrbt_import(pk, url, display=False):
    'import a peering offer'
    from . import wrbt
    offer = wrbt.decode(url)
    msg = wrbt.decrypt(pk, offer)

    if display:
        yield msg
    else:
        for addr, creds in msg['credentials'].items():
            name = addr.split(':')[0]
            peer_add(name, addr, creds['publicKey'], creds['password'])
            yield '[+] peered with %s' % addr


parser = ArghParser()
parser.add_commands([start, bootstrap] + core.cmd)
parser.add_commands(peer.cmd, namespace='peer', title='ctrl peers')
parser.add_commands([nf_get, nf_peer, nf_announce],
                    namespace='nf', title='ctrl inet auto-peering')
parser.add_commands([wrbt_seek, wrbt_confirm, wrbt_import],
                    namespace='wrbt', title='wrbt implementation')


def main():
    dispatch(parser)

if __name__ == '__main__':
    main()
