from .arg import arg, wrap_errors
from subprocess import Popen, PIPE
from .const import YRD_INBOUND, YRD_OUTBOUND, CJDROUTE_CONF, CJDROUTE_BIN
from . import utils
import json
import os


@arg('--attach', help='configure running cjdroute')
@wrap_errors([KeyboardInterrupt, IOError])
def start(attach=False, boot=False):
    'start and/or configure cjdroute'

    if not attach:
        p = Popen([CJDROUTE_BIN], stdin=PIPE)
        conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
        p.communicate(json.dumps(conf).encode('utf-8'))

    from .peer import add
    for peer in os.listdir(YRD_OUTBOUND):
        yield '[*] connecting to %r' % peer
        list(add(peer, None, live=True))

    from .peer import auth
    for peer in os.listdir(YRD_INBOUND):
        yield '[*] adding %r' % peer
        list(auth(peer, None, silent=True, live=True))


cmd = [start]
