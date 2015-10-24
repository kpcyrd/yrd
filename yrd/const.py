import os

YRD_FOLDER = os.environ.get('YRD_FOLDER', '/etc/yrd')


def yrd(path):
    return os.path.join(YRD_FOLDER, path)


YRD_INBOUND = yrd('inbound.d/')
YRD_OUTBOUND = yrd('outbound.d/')

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
