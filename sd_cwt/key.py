from pycose.keys import EC2Key, curves
from pycose.algorithms import Es256
from pycose.keys.keyparam import KpKty, KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKid
from cbor2 import dumps

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

def public_from_private(cose_key: EC2Key):
    return EC2Key.from_dict({
        KpKid: cose_key.kid,
        KpKty: cose_key.kty,
        EC2KpCurve: cose_key.crv,
        KpAlg: cose_key.alg,
        EC2KpX: cose_key.x,
        EC2KpY: cose_key.y,
    })