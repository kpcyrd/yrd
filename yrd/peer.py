from argh import arg, wrap_errors
from . import xcjdns as cjdns
from . import cjdns as cj
from . import utils
from .const import CJDROUTE_CONF, CJDROUTE_BIN
import socket
import json
import os


@arg('password', nargs='?', help='Set peering password')
@arg('-l', '--live', help='Don\'t write to disk')
@arg('-c', '--cjdroute', help='Show cjdroute output only')
@arg('-y', '--yrd', help='Show yrd output only')
@arg('-j', '--json', dest='json_output', help='Show json output only')
@wrap_errors([socket.error, IOError])
def auth(name, password, live=False, cjdroute=False, yrd=False,
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


@arg('name', help='the peers name')
@arg('addr', help='the peers address (ip:port)')
@arg('pk', help='the peers public key')
@arg('password', nargs='?', help='the password')
@arg('-l', '--live', help='Don\'t write to disk')
@wrap_errors([IOError])
def add(name, addr, pk, password, live=False):
    'add an outbound connection'
    if '/' in name:
        yield 'nope'
        exit(1)

    if not password:
        password = raw_input('Password: ')  # TODO: python3

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


@wrap_errors([IOError])
def ls():
    'list passwords for inbound connections'
    conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
    c = cjdns.connect(password=conf['admin']['password'])
    for user in c.listPasswords()['users']:
        yield user
    c.disconnect()


@wrap_errors([IOError])
def remove(user):
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


cmd = [auth, add, ls, remove]
