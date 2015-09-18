from argh import arg, dispatch, named, ArghParser


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

from . import wrbt


parser = ArghParser()
parser.add_commands(start.cmd + core.cmd)
parser.add_commands(peer.cmd, namespace='peer', title='ctrl peers')
parser.add_commands(nf.cmd, namespace='nf', title='ctrl inet auto-peering')
parser.add_commands(wrbt.cmd, namespace='wrbt', title='wrbt implementation')


def main():
    dispatch(parser)

if __name__ == '__main__':
    main()
