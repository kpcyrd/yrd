from .arg import arg, wrap_errors
from subprocess import Popen, PIPE
from .const import YRD_INBOUND, YRD_OUTBOUND, CJDROUTE_CONF, CJDROUTE_BIN
import json
import os


@arg('--attach', help='configure running cjdroute')
@arg('--boot', help='bootstraps network access')
@wrap_errors([KeyboardInterrupt, IOError])
def start(attach=False, boot=False):
    'start and/or configure cjdroute'

    if not attach:
        p = Popen(['cjdroute'], stdin=PIPE)
        conf = utils.load_conf(CJDROUTE_CONF, CJDROUTE_BIN)
        p.communicate(json.dumps(conf))

    from .peer import add
    for peer in os.listdir(YRD_OUTBOUND):
        yield '[*] connecting to %r' % peer
        list(add(peer, None, live=True))

    from .peer import auth
    for peer in os.listdir(YRD_INBOUND):
        yield '[*] adding %r' % peer
        list(auth(peer, None, silent=True, live=True))

    if boot:
        bootstrap()


def bootstrap():
    'bootstraps network access'
    import bootstrap as boot
    from . import nf
    nf.peer(boot.DESIRED, [x + boot.TOPIC + '/seek/' for x in bootstrap.trackers])


cmd = [start, bootstrap]
