from .arg import arg, wrap_errors
from subprocess import Popen, PIPE
from .const import YRD_PEERS, CJDROUTE_CONF, CJDROUTE_BIN
import json
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
                    from .peer import auth
                    list(auth(info['name'], info['password'], live=True))
                except KeyError:
                    yield '[-] key error'
            elif info['type'] == 'out':
                from .peer import add
                list(add(peer, info['addr'], info['pk'], info['password'], live=True))

    if boot:
        bootstrap()


def bootstrap():
    'bootstraps network access'
    import bootstrap as boot
    from . import nf
    nf.peer(boot.DESIRED, [x + boot.TOPIC + '/seek/' for x in bootstrap.trackers])



cmd = [start, bootstrap]
