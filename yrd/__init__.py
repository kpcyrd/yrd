from subprocess import Popen, PIPE, check_output
from argh import arg, dispatch, wrap_errors, aliases, named, ArghParser
import itertools
import socket
from . import xcjdns as cjdns
from . import cjdns as cj
from . import utils
import json
import time
import sys
import os

YRD_FOLDER = os.environ.get('YRD_FOLDER', '/etc/yrd')
YRD_PEERS = os.path.join(YRD_FOLDER, 'peers.d/')

CJDROUTE_CONF = os.environ.get('CJDROUTE_CONF')
if not CJDROUTE_CONF:
    for d in [YRD_FOLDER, '/etc']:
        path = os.path.join(d, 'cjdroute.conf')
        try:
            os.stat(path)
        except OSError:
            pass
        else:
            break
    CJDROUTE_CONF = path
CJDROUTE_BIN = os.environ.get('CJDROUTE_BIN', 'cjdroute')


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


@arg('-i', '--ip', help='format as ipv6')
@wrap_errors([socket.error, IOError])
def a(ip=False):
    'show address of cjdroute'
    c = cjdns.connect()

    res = c.nodeForAddr()['result']
    if ip:
        yield res['bestParent']['ip']
    else:
        yield 'v%s.%s.%s' % (res['protocolVersion'], res['routeLabel'], res['key'])

    c.disconnect()


@arg('ip', help='the cjdns ipv6')
@arg('-c', '--count', metavar='count', help='stop after `count` packets')
@arg('-s', '--switch', help='do a switch ping instead of a router ping')
@wrap_errors([KeyboardInterrupt, socket.error, IOError])
def ping(ip, count=0, switch=False):
    'ping a node'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])

    ping = c.switchPing if switch else c.routerPing

    for _ in xrange(count) if count else itertools.repeat(None):
        try:
            resp = ping(ip)
        except Exception as e:
            resp = {'error': e}

        if 'error' in resp:
            yield 'Error: %s' % resp['error']
        elif resp['result'] == 'pong' and switch:
            yield 'Reply from %s %dms' % (resp['path'], resp['ms'])
        elif resp['result'] == 'pong':
            yield 'Reply from %s %dms' % (resp['from'], resp['ms'])
        elif resp['result'] == 'timeout':
            yield 'Timeout from %s after %dms' % (ip, resp['ms'])

        time.sleep(1)

    c.disconnect()


@arg('-i', '--ip', help='format as ipv6')
@arg('-f', '--follow', help='show new nodes while they\'re discovered')
@wrap_errors([KeyboardInterrupt, socket.error])
def r(ip=False, follow=False):
    'access the nodestore'
    c = cjdns.connect()

    known = []
    FMT = '%s %s  v%d %11d %7d'

    while True:
        for node in c.dumpTable():
            if node['ip'] not in known:
                if ip:
                    yield FMT % (node['ip'], node['path'], node['version'],
                                 node['link'], node['time'])
                else:
                    yield node['addr']
                known.append(node['ip'])

        if not follow:
            break

        time.sleep(3)

    c.disconnect()


@arg('-i', '--ip', help='format as ipv6')
@arg('-n', '--neighbours', help='show neighbours peers')
@aliases('neighbours')
@wrap_errors([socket.error, IOError, KeyboardInterrupt])
def n(ip=False, neighbours=False):
    'shows your neighbours'
    c = cjdns.connect()

    if ip:
        STAT_FORMAT = '%s %19s  v%-2d  in %4dkb/s out %4dkb/s  %12s  %d/%d/%d  '
    else:
        STAT_FORMAT = '%s  in %4dkb/s out %4dkb/s  %12s  %d/%d/%d  '
    nodestore = list(c.dumpTable())

    connections = {}

    try:
        for peer in os.listdir(YRD_PEERS):
            with open(os.path.join(YRD_PEERS, peer)) as f:
                info = json.load(f)
                try:
                    connections[info['pk']] = str(info['name'])
                except KeyError:
                    pass
    except OSError:
        pass

    for peer in c.peerStats():
        result = c.nodeForAddr(peer.ip)['result']

        if ip:
            route = utils.grep_ns(nodestore, peer.addr)
            path = utils.get_path(route)

            setattr(peer, 'path', path)

            line = STAT_FORMAT % (peer.ip, peer.path, peer.version,
                                  peer.recvKbps, peer.sendKbps, peer.state,
                                  peer.duplicates, peer.lostPackets,
                                  peer.receivedOutOfRange)
        else:
            line = STAT_FORMAT % (peer.addr,
                                  peer.recvKbps, peer.sendKbps, peer.state,
                                  peer.duplicates, peer.lostPackets,
                                  peer.receivedOutOfRange)

        if hasattr(peer, 'user'):
            line += repr(peer.user)
        elif peer.publicKey in connections:
            line += repr(connections[peer.publicKey])

        yield line

        if neighbours:
            for i in range(result['linkCount']):
                try:
                    link = c.getLink(peer.ip, i)

                    if link and 'child' in link['result']:
                        child = link['result']['child']
                        if ip:
                            route = utils.grep_ns(nodestore, child)

                            ip = cjdns.addr2ip(child)
                            version = utils.get_version(route)
                            path = utils.get_path(route)

                            yield '   %s   %s  v%s' % (ip, path, version)
                        else:
                            yield '   ' + child
                    else:
                        yield '   -'
                except:
                    # TODO remove this
                    pass

    c.disconnect()


neighbours = n


@arg('-n', help='number of routes displayed')
@arg('-r', '--routing', help='show routing only')
@wrap_errors([KeyboardInterrupt])
def top(n=25, routing=False):
    'much colors'
    from .top import Session

    s = Session()

    while True:
        print(s.output([] if routing else neighbours(ip=True), r(ip=True), n))
        time.sleep(1)


@arg('-l', '--level', help='filter by log level')
@arg('-f', '--file', help='filter by source file')
@arg('-n', '--line', help='filter by line number')
@wrap_errors([KeyboardInterrupt])
def mon(level=None, file=None, line=0):
    'monitor cjdroute'

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, conf['admin']['password'])

    kwargs = {}

    if level:
        kwargs['level'] = level

    if file:
        kwargs['file'] = file

    if line:
        kwargs['line'] = line

    resp = c.AdminLog_subscribe(**kwargs)
    streamId = resp['streamId']

    try:
        while True:
            x = c.getMessage(resp['txid'])
            x['ftime'] = utils.ts2time(x['time'])
            yield '{ftime} {level} {file}:{line} {message}'.format(**x)
    except:
        c.AdminLog_unsubscribe(streamId)
        raise


@wrap_errors([IOError])
def uplinks(ip, trace=False):
    'show uplinks of a node'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])
    nodestore = list(c.dumpTable())

    result = c.nodeForAddr(ip)['result']
    for i in range(result['linkCount']):
        link = c.getLink(ip, i)

        if link and 'child' in link['result']:
            child = link['result']['child']
            route = utils.grep_ns(nodestore, child)

            version = utils.get_version(route)
            path = utils.get_path(route)

            yield '%s   %s  v%d' % (child, path, version)
        else:
            yield('-')

    c.disconnect()


@arg('-b', '--hub', help='query hub.hyperboria.net')
@wrap_errors([socket.error, KeyboardInterrupt])
def whois(ip, hub=False):
    'asks the remote server for whois information'
    try:
        j, title = utils.nodeinfo(ip, hub)
    except:
        yield 'couldn\'t get node info'
    else:
        def show(path, x):
            if type(x) is dict:
                for a, b in x.items():
                    for line in show('%s/%s' % (path, a), b):
                        yield line
            elif type(x) is list:
                for a, b in enumerate(x):
                    for line in show('%s/%s' % (path, a), b):
                        yield line
            else:
                yield '%-40s: %s' % (path, x)

        yield '%% %s %s whois information' % (ip, title)
        yield '%'

        for line in show('', j):
            yield line


@named('auth')
@arg('password', nargs='?', help='Set peering password')
@arg('-l', '--live', help='Don\'t write to disk')
@arg('-c', '--cjdroute', help='Show cjdroute output only')
@arg('-y', '--yrd', help='Show yrd output only')
@arg('-j', '--json', dest='json_output', help='Show json output only')
@wrap_errors([socket.error, IOError])
def peer_auth(name, password, live=False, cjdroute=False, yrd=False,
              json_output=False):
    'add a password for inbound connections'

    if '/' in name:
        yield 'nope'
        exit(1)

    path = os.path.join(YRD_PEERS, name)
    if os.path.exists(path):
        with open(path) as f:
            password = json.load(f)['password']
    else:
        if not password:
            password = utils.generate_key(31)

        info = {
            'type': 'in',
            'name': name,
            'password': password
        }

        if not live:
            with open(path, 'w') as f:
                f.write(json.dumps(info))

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, conf['admin']['password'])
    resp = c.AuthorizedPasswords_add(user=name, password=password)
    utils.raise_on_error(resp)
    c.disconnect()

    publicKey = conf['publicKey']
    port = conf['interfaces']['UDPInterface'][0]['bind'].split(':')[1]

    if json_output:
        yield json.dumps({'ip': utils.get_ip(), 'port': port,
                         'pk': publicKey, 'password': password})
    else:
        if (not cjdroute and not yrd) or cjdroute:
            yield utils.to_credstr(utils.get_ip(), port, publicKey, password)
        if not cjdroute and not yrd:
            yield ''
        if (not cjdroute and not yrd) or yrd:
            yield 'yrd peer add namehere %s:%s %s %s' % (utils.get_ip(), port,
                                                         publicKey, password)


@named('ls')
@wrap_errors([IOError])
def peer_ls():
    'list passwords for inbound connections'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])
    for user in c.listPasswords()['users']:
        yield user
    c.disconnect()


@arg('name', help='the peers name')
@arg('addr', help='the peers address (ip:port)')
@arg('pk', help='the peers public key')
@arg('password', nargs='?', help='the password')
@arg('-l', '--live', help='Don\'t write to disk')
@named('add')
@wrap_errors([IOError])
def peer_add(name, addr, pk, password, live=False):
    'add an outbound connection'
    if '/' in name:
        yield 'nope'
        exit(1)

    if not password:
        password = raw_input('Password: ')

    path = os.path.join(YRD_PEERS, name)

    info = {
        'type': 'out',
        'name': name,
        'addr': addr,
        'pk': pk,
        'password': password
    }

    if not live:
        with open(path, 'w') as f:
            f.write(json.dumps(info))

    addr = utils.dns_resolve(addr)

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, conf['admin']['password'])
    resp = c.UDPInterface_beginConnection(address=addr,
                                          publicKey=pk,
                                          password=password)
    utils.raise_on_error(resp)
    c.disconnect()


@named('remove')
@wrap_errors([IOError])
def peer_remove(user):
    'unpeer a node'
    if '/' in user:
        yield 'nope'
        exit(1)

    path = os.path.join(YRD_PEERS, user)
    if os.path.exists(path):
        os.unlink(path)
    else:
        yield 'user not found'

    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])
    c.removePassword(user)
    c.disconnect()


@named('get')
def nf_get(desired, *trackers):
    'query public peers'
    import nf
    for tracker in trackers:
        for peer in nf.request_peers(desired, tracker):
            yield peer.credentialstr()


@named('peer')
def nf_peer(desired, *trackers):
    'connect to public peers'
    import nf
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
    import nf

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
    import wrbt
    url, pk = wrbt.request()
    yield 'Import offer: yrd wrbt import "%s" <offer>' % pk
    yield url


@named('confirm')
def wrbt_confirm(name, url):
    'confirm a peering request'
    import wrbt
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
    import wrbt
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
parser.add_commands([start, bootstrap, a, n, ping, top, mon, r, uplinks, whois])
parser.add_commands([peer_auth, peer_add, peer_ls, peer_remove],
                    namespace='peer', title='ctrl peers')
parser.add_commands([nf_get, nf_peer, nf_announce],
                    namespace='nf', title='ctrl inet auto-peering')
parser.add_commands([wrbt_seek, wrbt_confirm, wrbt_import],
                    namespace='wrbt', title='wrbt implementation')


def main():
    dispatch(parser)

if __name__ == '__main__':
    main()
