#!/usr/bin/env python
# You may redistribute this program and/or modify it under the terms of
# the GNU General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""python-cjdns is a library for communicating with the cjdns admin interface"""

from __future__ import print_function

import os
import sys
import socket
import hashlib
import json
import threading
import time
try:
    import queue
except ImportError:
    import Queue as queue
import random
import string
from hashlib import sha512
from .bencode import bencode, bdecode

BUFFER_SIZE = 69632
KEEPALIVE_INTERVAL_SECONDS = 2


class Session(object):
    """Current cjdns admin session"""

    def __init__(self, s):
        self.socket = s
        self.queue = queue.Queue()
        self.messages = {}

    def disconnect(self):
        """Disconnects the socket"""
        self.socket.close()

    def getMessage(self, txid):
        """Retreives the message associatd with txid"""
        return _getMessage(self, txid)

    def functions(self):
        """Prints a list of functions available"""
        print(self._functions)


def _randomString():
    """Random string for message signing"""

    return ''.join(
        random.choice(string.ascii_uppercase + string.digits)
        for x in range(10))


def _callFunc(session, funcName, password, args):
    """Call custom cjdns admin function"""

    txid = _randomString()
    sock = session.socket
    sock.send(bytearray('d1:q6:cookie4:txid10:%se' % txid, 'utf-8'))
    msg = _getMessage(session, txid)
    cookie = msg['cookie']
    txid = _randomString()
    tohash = (password + cookie).encode('utf-8')
    req = {
        'q': funcName,
        'hash': hashlib.sha256(tohash).hexdigest(),
        'cookie': cookie,
        'args': args,
        'txid': txid
    }

    if password:
        req['aq'] = req['q']
        req['q'] = 'auth'
        reqBenc = bencode(req).encode('utf-8')
        req['hash'] = hashlib.sha256(reqBenc).hexdigest()

    reqBenc = bencode(req)
    sock.send(bytearray(reqBenc, 'utf-8'))
    return _getMessage(session, txid)


def _receiverThread(session):
    """Receiving messages from cjdns admin server"""

    timeOfLastSend = time.time()
    timeOfLastRecv = time.time()
    try:
        while True:
            if timeOfLastSend + KEEPALIVE_INTERVAL_SECONDS < time.time():
                if timeOfLastRecv + 10 < time.time():
                    raise Exception("ping timeout")
                session.socket.send(
                    b'd1:q18:Admin_asyncEnabled4:txid8:keepalive')
                timeOfLastSend = time.time()

            try:
                data = session.socket.recv(BUFFER_SIZE)
            except socket.timeout:
                continue

            try:
                benc = bdecode(data)
            except (KeyError, ValueError):
                print("error decoding [" + data + "]")
                continue

            if benc['txid'] == 'keepaliv':
                if benc['asyncEnabled'] == 0:
                    raise Exception("lost session")
                timeOfLastRecv = time.time()
            else:
                # print "putting to queue " + str(benc)
                session.queue.put(benc)

    except KeyboardInterrupt:
        print("interrupted")
        import thread
        thread.interrupt_main()


def _getMessage(session, txid):
    """Getting message associated with txid"""

    while True:
        if txid in session.messages:
            msg = session.messages[txid]
            del session.messages[txid]
            return msg
        else:
            # print "getting from queue"
            try:
                # apparently any timeout at all allows the thread to be
                # stopped but none make it unstoppable with ctrl+c
                nextMessage = session.queue.get(timeout=100)
            except queue.Empty:
                continue
            if 'txid' in nextMessage:
                session.messages[nextMessage['txid']] = nextMessage
                # print "adding message [" + str(next) + "]"
            else:
                print("message with no txid: %s" % nextMessage)


def _functionFabric(func_name, argList, oargList, password):
    """Function fabric for Session class"""

    def functionHandler(self, *args, **kwargs):
        call_args = {}

        for (key, value) in oargList.items():
            call_args[key] = value

        for i, arg in enumerate(argList):
            if i < len(args):
                call_args[arg] = args[i]

        for (key, value) in kwargs.items():
            call_args[key] = value

        return _callFunc(self, func_name, password, call_args)

    functionHandler.__name__ = str(func_name)
    return functionHandler


def connect(ipAddr, port, password):
    """Connect to cjdns admin with this attributes"""

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect((ipAddr, port))
    sock.settimeout(2)

    # Make sure it pongs.
    sock.send(b'd1:q4:pinge')
    data = sock.recv(BUFFER_SIZE)
    if not data.endswith(b'1:q4:ponge'):
        raise Exception(
            "Looks like " + ipAddr + ":" + str(port) +
            " is to a non-cjdns socket.")

    # Get the functions and make the object
    page = 0
    availableFunctions = {}
    while True:
        sock.send(bytearray(
            'd1:q24:Admin_availableFunctions4:argsd4:pagei%seee' % page,
            'utf-8'))
        data = sock.recv(BUFFER_SIZE)
        benc = bdecode(data)
        for func in benc['availableFunctions']:
            availableFunctions[func] = benc['availableFunctions'][func]
        if 'more' not in benc:
            break
        page = page+1

    funcArgs = {}
    funcOargs = {}

    for (i, func) in availableFunctions.items():
        items = func.items()

        # grab all the required args first
        # append all the optional args
        rargList = [arg for arg, atts in items if atts['required']]
        argList = rargList + [
            arg for arg, atts in items if not atts['required']]

        # for each optional arg setup a default value with
        # a type which will be ignored by the core.
        oargList = {}
        for (arg, atts) in items:
            if not atts['required']:
                oargList[arg] = (
                    "''" if func[arg]['type'] == 'Int'
                    else "")

        setattr(Session, i, _functionFabric(
            i, argList, oargList, password))

        funcArgs[i] = rargList
        funcOargs[i] = oargList

    session = Session(sock)

    kat = threading.Thread(target=_receiverThread, args=[session])
    kat.setDaemon(True)
    kat.start()

    # Check our password.
    ret = _callFunc(session, "ping", password, {})
    if 'error' in ret:
        raise Exception(
            "Connect failed, incorrect admin password?\n" + str(ret))

    session._functions = ""

    funcOargs_c = {}
    for func in funcOargs:
        funcOargs_c[func] = list([
            key + "=" + str(value) for (key, value) in funcOargs[func].items()
        ])

    for func in availableFunctions:
        session._functions += (
            func + "(" + ', '.join(funcArgs[func] + funcOargs_c[func]) + ")\n")

    # print session.functions
    return session


def connectWithAdminInfo(path=None):
    """Connect to cjdns admin with data from user file"""

    if path is None:
        path = os.path.expanduser('~/.cjdnsadmin')
    try:
        with open(path, 'r') as adminInfo:
            data = json.load(adminInfo)
    except IOError:
        print('~/.cjdnsadmin not found; using default credentials', file=sys.stderr)
        data = {
            'password': 'NONE',
            'addr': '127.0.0.1',
            'port': 11234,
        }

    return connect(data['addr'], data['port'], data['password'])


def Base32_decode(decodeme):
    output = bytearray(len(decodeme))
    numForAscii = [
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99, 99, 99, 99, 99, 99,
        99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19, 20, 99,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99,
        99, 99, 10, 11, 12, 99, 13, 14, 15, 99, 16, 17, 18, 19, 20, 99,
        21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 99, 99, 99, 99, 99,
    ]

    outputIndex = 0
    inputIndex = 0
    nextByte = 0
    bits = 0

    while inputIndex < len(decodeme):
        o = ord(decodeme[inputIndex])
        if o & 0x80:
            raise ValueError
        b = numForAscii[o]
        inputIndex += 1
        if b > 31:
            raise ValueError("bad character " + decodeme[inputIndex])

        nextByte |= (b << bits)
        bits += 5

        if bits >= 8:
            output[outputIndex] = nextByte & 0xff
            outputIndex += 1
            bits -= 8
            nextByte >>= 8

    if bits >= 5 or nextByte:
        raise ValueError("bits is %s and nextByte is %s" % (bits, nextByte))

    return memoryview(output)[0:outputIndex]


def PublicToIp6(pubKey):
    if pubKey[-2:] != ".k":
        raise ValueError("key does not end with .k")
    keyBytes = Base32_decode(pubKey[0:-2])
    hashOne = sha512(keyBytes).digest()
    hashTwo = sha512(hashOne).hexdigest()
    first16 = hashTwo[0:32]
    out = ''
    for i in range(0, 8):
        out += first16[i*4: i*4+4] + ":"
    return out[:-1]
