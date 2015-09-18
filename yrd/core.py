from argh import arg, wrap_errors, aliases, named
from .const import YRD_PEERS, CJDROUTE_CONF, CJDROUTE_BIN
from . import xcjdns as cjdns
from . import cjdns as cj
from . import utils
import itertools
import socket
import time
import os


@arg('-i', '--ip', help='format as ipv6')
@wrap_errors([socket.error, IOError])
def a(ip=False):
    'show address of cjdroute'
    c = cjdns.connect()

    res = c.nodeForAddr()['result']
    if ip:
        yield res['bestParent']['ip']
    else:
        # TODO: add 'addr' to nodeForAddr
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
            yield 'Reply from %s %dms' % (resp['addr'], resp['ms'])
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
            if ip:
                if node['ip'] not in known:
                    yield FMT % (node['ip'], node['path'], node['version'],
                                 node['link'], node['time'])
                    known.append(node['ip'])
            else:
                if node['addr'] not in known:
                    yield node['addr']
                    known.append(node['addr'])

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
        nodestore = list(c.dumpTable())
    else:
        STAT_FORMAT = '%s  in %4dkb/s out %4dkb/s  %12s  %d/%d/%d  '

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
        if ip:
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
            links = c.nodeForAddr(peer.addr)['result']['linkCount']
            for i in range(links):
                try:
                    link = c.getLink(peer.ip, i)

                    if link and 'child' in link['result']:
                        child = link['result']['child']
                        if ip:
                            x = cjdns.Peer(addr=child)
                            yield '   %s   %s  v%s' % (x.ip, x.path, x.version)
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


@arg('-i', '--ip', help='format as ipv6')
@wrap_errors([IOError])
def uplinks(addr, ip=False):
    'show uplinks of a node'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])

    result = c.nodeForAddr(addr)['result']

    try:
        x = cjdns.Peer(addr=addr)
    except ValueError:
        x = cjdns.Peer(ip=addr)

    for i in range(result['linkCount']):
        link = c.getLink(x.ip, i)

        if link and 'child' in link['result']:
            child = link['result']['child']
            if ip:
                y = cjdns.Peer(addr=child)
                yield '%s   %s  v%s' % (y.ip, y.path, y.version)
            else:
                yield child
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


cmd = [a, n, ping, top, mon, r, uplinks, whois]
