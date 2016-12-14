# encoding: utf-8
#
# Andre Silva Santos
# Pedro Toipa Coelho

# vim setings:
# :set expandtab ts=4

import random


def generate_nonce(length=4):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def connect(phase, name, id, cipher, data):
    return {'type': 'connect', 'phase': phase, 'name': name, 'id': id, 'ciphers': cipher, 'data': data}


def secure(sadata, payload):
    return {'type': 'secure', 'sa-data': sadata, 'payload': payload}


def lista(data):
    return {'type': 'list', 'data': data}


def clientConnect(src, dst, phase, cipher, data):
    return {'type': 'client-connect', 'src': src, 'dst': dst, 'phase': phase, 'ciphers': cipher, 'data': data}


def clientDisconnect(src, dst, data):
    return {'type': 'client-disconnect', 'src': src, 'dst': dst, 'data': data}


def clientCom(src, dst, data):
    return {'type': 'client-com', 'src': src, 'dst': dst, 'data': data}


def ack(src, dst, data):
    return {'type': 'ack', 'src': src, 'dst': dst, 'data': data}
