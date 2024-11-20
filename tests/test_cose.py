
from pycose.keys import EC2Key
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message
from pycose.algorithms import Es256


def test_cose_sign1():
  cose_key = EC2Key.generate_key(crv='P_256')
  msg = Sign1Message(
      phdr = {
         Algorithm: Es256, 
         KID: b'kid2'
      },
      payload = 'signed message'.encode('utf-8'))
  msg.key = cose_key
  encoded = msg.encode()
  decoded = Sign1Message.decode(encoded)
  decoded.key = cose_key
  assert decoded.verify_signature() == True 