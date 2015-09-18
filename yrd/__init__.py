from argh import arg, dispatch, named, ArghParser
from . import utils
from .const import YRD_FOLDER, YRD_PEERS, CJDROUTE_CONF, CJDROUTE_BIN


from . import start

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

from .nf import get as nf_get
from .nf import auto as nf_peer
from .nf import announce as nf_announce


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
parser.add_commands(start.cmd + core.cmd)
parser.add_commands(peer.cmd, namespace='peer', title='ctrl peers')
parser.add_commands(nf.cmd, namespace='nf', title='ctrl inet auto-peering')
parser.add_commands([wrbt_seek, wrbt_confirm, wrbt_import],
                    namespace='wrbt', title='wrbt implementation')


def main():
    dispatch(parser)

if __name__ == '__main__':
    main()
