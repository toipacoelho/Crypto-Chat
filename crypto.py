import PyKCS11
import base64

import datetime

import cc_util
import hashlib
import json
import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import NameOID
from cryptography import x509
from OpenSSL import crypto

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


def cert():
    one_day = datetime.timedelta(1, 0, 0)
    pk = genKeyPair('RSA')[0]
    puk = pk.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name((x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'p3g2')])))
    builder = builder.issuer_name((x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u'p3g2')])))
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime(2018, 8, 2))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(puk)
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    certificate = builder.sign(private_key=pk, algorithm=hashes.SHA256(), backend=BACKEND)

    f = open('server_cert.pem', 'wr+')
    f.write(str(certificate.public_bytes(serialization.Encoding.PEM)))


def verSELFcert(cert):
    cer = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

    storX = crypto.X509Store()

    storX.add_cert(cer)

    context = crypto.X509StoreContext(storX, cer)

    context.set_store(storX)

    try:
        context.verify_certificate()
    except:
        return False
    else:
        return True