from random import shuffle
import requests
import utils
import json


class DhtPeer(object):
    def __init__(self, ip, port, publicKey, password, ts=None, **kwargs):
        self.ip = ip
        self.port = port
        self.publicKey = publicKey
        self.password = password
        self.kwargs = kwargs

    def credentialstr(self):
        return utils.to_credstr(self.ip, self.port, self.publicKey,
                                self.password, **self.kwargs)


def request_peers(desired, tracker):
    response = requests.get(tracker).json

    if not type(response) is list:
        response = response()

    for peer in shuffle(response)[:desired]:
        try:
            yield DhtPeer(**peer)
        except TypeError:
            pass


def announce(tracker, **kwargs):
    resp = requests.post(tracker, json=kwargs).json()
    return resp['status'] == 'success'
