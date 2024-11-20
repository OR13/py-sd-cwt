from pycose.keys import EC2Key, curves
from pycose.algorithms import Es256

from cbor2 import CBORTag, dumps
import hashlib

def thumbprint(cose_key: EC2Key):
    thumbprint_params = {
        1 : 2,  # kty EC2
        -1 : 1, # crv P-256
        -2 : cose_key.x, # X
        -3 : cose_key.y  # Y
    }
    m = hashlib.sha256()
    m.update(dumps(thumbprint_params, canonical=True))
    return m.digest()

def gen():
    cose_key = EC2Key.generate_key(crv=curves.P256)
    cose_key.alg = Es256
    cose_key.kid = thumbprint(cose_key)
    return cose_key