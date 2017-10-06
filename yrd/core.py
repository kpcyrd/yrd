from .arg import arg, wrap_errors, aliases
from .const import CJDROUTE_CONF, CJDROUTE_BIN
from . import xcjdns as cjdns
from . import cjdns as cj
from . import utils
import itertools
import socket
import time
import os


@arg('-i', '--ip', help='show as ipv6')
@arg('-k', '--key', help='show as key')
@arg('-p', '--path', help='show as path')
@arg('addr', nargs='?', help='address to convert')
@aliases('a')
@wrap_errors([socket.error, IOError, ValueError])
def address(addr, ip=False, key=False, path=False):
    'show cjdroute addresses'

    if addr:
        addrs = cjdns.collect_from_address(addr)

        try:
            if path:
                addr = addrs['path']

            if key:
                addr = addrs['key']

            if ip:
                addr = addrs['ip']
        except KeyError:
            raise ValueError('not enough info')

        return addr
    else:
        c = cjdns.connect()

        res = c.nodeForAddr()['result']
        # TODO: add 'addr' to nodeForAddr
        my_path = 'v%s.%s.%s' % (res['protocolVersion'], res['routeLabel'], res['key'])

        c.disconnect()
        return address(my_path, ip=ip, key=key, path=path)


@arg('ip', help='the cjdns ipv6')
@arg('-c', '--count', metavar='count', help='stop after `count` packets')
@arg('-s', '--switch', help='do a switch ping instead of a router ping')
@wrap_errors([KeyboardInterrupt, socket.error, IOError])
def ping(ip, count=0, switch=False):
    'ping a node'
    admin_pw = utils.load_admin_pw(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=admin_pw)

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
@aliases('r')
@wrap_errors([KeyboardInterrupt, socket.error])
def route(ip=False, follow=False):
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
@aliases('n')
@wrap_errors([socket.error, IOError, KeyboardInterrupt])
def neighbours(ip=False, neighbours=False):
    'shows your neighbours'
    c = cjdns.connect()

    if ip:
        STAT_FORMAT = '%s %19s  v%-2s  in %4dkb/s out %4dkb/s  %12s  %d/%d/%d  '
        nodestore = list(c.dumpTable())
    else:
        STAT_FORMAT = '%s  in %4dkb/s out %4dkb/s  %12s  %d/%d/%d  '

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


@arg('-n', help='number of routes displayed')
@arg('-r', '--routing', help='show routing only')
@wrap_errors([KeyboardInterrupt])
def top(n=25, routing=False):
    'much colors'
    from .top import Session

    s = Session()

    while True:
        print(s.output([] if routing else neighbours(ip=True), route(ip=True), n))
        time.sleep(1)


@arg('-l', '--level', help='filter by log level')
@arg('-f', '--file', help='filter by source file')
@arg('-n', '--line', help='filter by line number')
@arg('-@', dest='about', metavar='pub.k', help='logs related to node')
@wrap_errors([KeyboardInterrupt, IOError])
def mon(level=None, file=None, line=0, about=None):
    'monitor cjdroute'

    admin_pw = utils.load_admin_pw(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, admin_pw)

    kwargs = {}

    if level:
        kwargs['level'] = level

    if file:
        kwargs['file'] = file

    if line:
        kwargs['line'] = line

    resp = c.AdminLog_subscribe(**kwargs)
    streamId = resp['streamId']

    if about:
        key = address(about, key=True)
        ip = address(about, ip=True)
        topic = [key, key[:-2], ip]
    else:
        topic = []

    try:
        while True:
            msg = c.getMessage(resp['txid'])
            msg['ftime'] = utils.ts2time(msg['time'])
            if not topic or any([x in msg['message'] for x in topic]):
                yield '{ftime} {level} {file}:{line} {message}'.format(**msg)
    except:
        c.AdminLog_unsubscribe(streamId)
        raise


@wrap_errors([socket.error, IOError])
def sessions():
    'show established sessions'
    admin_pw = utils.load_admin_pw(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, admin_pw)

    for session in c.sessionStats():
        yield '{addr} {state} {handle} {sendHandle}'.format(**session)


@arg('-c', '--count')
@wrap_errors([socket.error, IOError])
def search(addr, count=-1):
    'search dht for node'
    admin_pw = utils.load_admin_pw(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, admin_pw)

    count = -1
    for x in c.search(addr, count):
        x['num'] = len(x['nodes'])
        yield '{from} {ms}ms {num} results'.format(**x)
        for y in x['nodes']:
            yield '    %s' % y


@arg('-i', '--ip', help='format as ipv6')
@wrap_errors([IOError])
def uplinks(addr, ip=False):
    'show uplinks of a node'
    admin_pw = utils.load_admin_pw(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cj.connect('127.0.0.1', 11234, admin_pw)

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
        ip = cjdns.pk2ipv6(ip)
    except ValueError:
        pass  # already ip address

    j, title = utils.nodeinfo(ip, hub)

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


cmd = [address, neighbours, ping, top, mon, route,
       sessions, search, uplinks, whois]
