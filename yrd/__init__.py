from .arg import ArghParser, dispatch
from . import start
from . import core
from . import peer
from . import nf


parser = ArghParser(description='cjdns swiss army knife')
parser.add_commands(start.cmd + core.cmd)
parser.add_commands(peer.cmd, namespace='peer', title='ctrl peers')
parser.add_commands(nf.cmd, namespace='nf', title='ctrl inet auto-peering')


def main():
    dispatch(parser)


if __name__ == '__main__':
    main()
