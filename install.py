#!/usr/bin/env python2
from subprocess import call
import yrd
import os

CJDNS_GIT_REPO = 'https://github.com/cjdelisle/cjdns.git'
CJDNS_CLONE_DIR = '/opt/cjdns'

YRD_CLONE_DIR = '/opt/yrd'
YRD_GIT_REPO = 'https://github.com/kpcyrd/yrd.git'


def main():
    yield '[*] checking permissions'
    if os.geteuid():
        yield '[-] you need to be root'
        return

    yield '[*] checking if we have git and gcc'
    if call(['which', 'git']) or call(['which', 'gcc']):
        yield '[/] somethings missing, checking if we can install it'
        if not call(['which', 'apt-get']):
            yield '[*] installing what\'s missing'

            if call(['apt-get', 'install', 'build-essential', 'git']):
                yield '[-] installation failed, please install them yourself'
                return
        else:
            yield '[-] we can\'t do this automatically on your system'
            return

    yield '[*] checking if cjdroute is there'
    if call(['which', 'cjdroute']):
        yield '[/] not found, continuing'

        if not os.path.exists(CJDNS_CLONE_DIR):
            yield '[*] cloning cjdns'
            if call(['git', 'clone', CJDNS_GIT_REPO, CJDNS_CLONE_DIR]):
                yield '[-] clone failed'
                return

        yield '[*] compiling cjdns'
        if call(['sh', '-c', 'cd "%s" && ./do' % CJDNS_CLONE_DIR]):
            yield '[-] compile failed'

        yield '[*] creating symlink'
        os.symlink(os.path.join(CJDNS_CLONE_DIR, 'cjdroute'),
                   '/usr/bin/cjdroute')
    else:
        yield '[+] already installed, skipping'

    yield '[*] checking if yrd is in your path'
    if call(['which', 'yrd']):
        yield '[/] not in your path, doing a proper install from scratch'
        if not os.path.exists(YRD_CLONE_DIR):
            yield '[*] cloning yrd'
            if call(['git', 'clone', YRD_GIT_REPO, YRD_CLONE_DIR]):
                yield '[-] clone failed'
                return

        yield '[*] creating symlink'
        os.symlink(os.path.join(YRD_CLONE_DIR, 'yrd.py'),
                   '/usr/bin/yrd')
    else:
        yield '[+] already installed, skipping'

    yield '[*] checking folders for internal files'
    for folder in [(yrd.YRD_FOLDER, 710), (yrd.YRD_PEERS, 770)]:
        if not os.path.exists(folder[0]):
            yield '[*] creating ' + folder[0]
            os.mkdir(folder[0], folder[1])

    yield '[*] checking cjdroute.conf'
    if not os.path.exists(yrd.CJDROUTE_CONF):
        yield '[*] generating cjdroute'
        conf = check_output(['cjdroute', '--genconf', '--eth'])

        with open(yrd.CJDROUTE_CONF, 'w') as f:
            f.write(conf)

    yield '[+] installation complete'

if __name__ == '__main__':
    for line in main():
        print(line)
