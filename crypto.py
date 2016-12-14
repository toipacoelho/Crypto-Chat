import os, base64, sys, json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding

BACKEND = default_backend()


def genKeyPair(alg):
    if alg == 'ECDHE':
        pk = ec.generate_private_key(ec.SECP256R1(), BACKEND)
        puk = pk.public_key()
        puk = serialize(puk)

    elif alg == 'RSA':
        pk = rsa.generate_private_key(public_exponent=655537, key_size=2048, backend=BACKEND)
        puk = pk.public_key()
        puk = serialize(puk)

    else:
        print "unknown" + alg
        sys.exit(1)

    return pk, puk


def serialize(key):
    return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def deserialize(serialized_key):
    return serialization.load_pem_public_key(serialized_key, BACKEND)


def exchange(pk, puk):
    return pk.exchange(ec.ECDH, puk)


def encrypt(key, sk, data):
    if isinstance(data, dict) or isinstance(data, str):
        try:
            data = json.dumps(data)
        except:
            cipherText = key.encrypt(data,  mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None)
            return base64.b64decode(cipherText)
        else:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(sk), modes.CTR(iv), BACKEND)
            encryptor = cipher.encryptor()
            out = encryptor.update(data) + encryptor.finalize()
            return base64.b64encode(out), base64.b64encode(iv)


def decrypt(key, sk, iv, data):
    data = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(sk), modes.CTR(iv), BACKEND)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def derivekey(key):
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=None, backend=BACKEND)


def genhmac(sk, msg):
    msg = json.dumps(msg)
    h = hmac.HMAC(sk, hashes.SHA512, BACKEND)
    h.update(msg)
    return base64.b64encode(h.finalize())


def checkhmac(sk, msg, rch):
    h = hmac.HMAC(sk, hashes.SHA512(), BACKEND)

    try:
        del msg['sa-data']['hash']
    except:
        print "Error in dict"
    else:
        msg = json.dumps(msg)
        h.update(msg)
        mh = base64.b64encode(h.finalize())
        return mh == rch