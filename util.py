import random


def generate_nonce(length=4):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def connect(phase, name, id, cipher, data):
    return {'type': 'connect', 'phase': phase, 'name': name, 'id': id, 'ciphers': [cipher], 'data': data}


def secure(sadata, payload):
    return {'type': 'secure', 'sa-data': sadata, 'payload': payload}


def lista(sadata, data):
    return secure(sadata, {'type': 'list', 'data': data})


def clientConnect(sadata, src, dst, phase, cipher, data):
    return secure(sadata,
                  {'type': 'client-connect', 'src': src, 'dst': dst, 'phase': phase, 'ciphers': [cipher], 'data': data})


def clientDisconnect(sadata, src, dst, data):
    return secure(sadata, {'type': 'client-disconnect', 'src': src, 'dst': dst, 'data': data})


def clientCom(sadata, src, dst, data):
    return secure(sadata, {'type': 'client-com', 'src': src, 'dst': dst, 'data': data})


def ack(sadata, src, dst, data):
    return secure(sadata, {'type': 'ack', 'src': src, 'dst': dst, 'data': data})
