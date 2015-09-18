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
