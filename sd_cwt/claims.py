
import hashlib
from time import time 
from cbor2 import CBORTag, dumps, loads

from pycose.keys import EC2Key
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message
from pycose.keys import EC2Key, curves
from pycose.algorithms import Es256
from pycose.keys.keyparam import KpKty, KpAlg, EC2KpX, EC2KpY, EC2KpCurve, KpKid

# cwt claims
issuer = 1
subject = 2
audience = 3
expires_at = 4
not_before = 5
issued_at = 6
nonce = 39

confirmation = 8


# CWT Confirmation Methods
key_confirmation = 1

# cose header parameters
sd_claims = 17

# cbor tags
REDACTED_KEY_TAG = 59
REDACTED_VALUE_TAG = 60

redacted_claim_key = CBORTag(REDACTED_KEY_TAG, 0)

class RedactableKey:
  def __init__(self, value):
    self.value = value

class RedactableValue:
  def __init__(self, value):
    self.value = value

def redaction_encoder(encoder, redactable):
  if (isinstance(redactable, RedactableKey)):
      return encoder.encode(CBORTag(REDACTED_KEY_TAG, redactable.value))
  if (isinstance(redactable, RedactableValue)):
      return encoder.encode(CBORTag(REDACTED_VALUE_TAG, redactable.value))

def blind_claim(value, key = None):
  salted_disclosure = ['salt']
  if (key != None):
    if (isinstance(key, RedactableKey)):
      salted_disclosure.append(key.value)
    else:
      salted_disclosure.append(key)
  salted_disclosure.append(value)
  m = hashlib.sha256()
  encoded_salted_disclosure = dumps(salted_disclosure, default=redaction_encoder)
  m.update(encoded_salted_disclosure)
  digested_disclosure = m.digest()
  return digested_disclosure, encoded_salted_disclosure

def redact_list(array, disclosures = []):
  for index in range(0, len(array)):
    item = array[index]
    if (isinstance(item, RedactableValue)):
      if (isinstance(item.value, list)):
        redact_list(item.value, disclosures)
      if (isinstance(item.value, dict)):
        redact_map(item.value, disclosures)
      digest, disclosure = blind_claim(item.value)
      array[index] =  RedactableValue(digest)
      disclosures.append(disclosure)
    elif (isinstance(item, dict)):
      redact_map(item, disclosures)

def redact_map(map, disclosures = []):
  for k, v in list(map.items()):
    if(isinstance(v, dict)):
      redact_map(v, disclosures)
    elif (isinstance(v, list)):
      redact_list(v, disclosures)
    
    if (isinstance(k, RedactableKey)):
      if (map.get(redacted_claim_key)):
        digest, disclosure = blind_claim(v, k)
        disclosures.append(disclosure)
        map[redacted_claim_key].append(digest)
      else:
        digest, disclosure = blind_claim(v, k)
        disclosures.append(disclosure)
        map[redacted_claim_key] =  [ digest ]
      if map.get(k) != None:
        del map[k]
    
  return map, disclosures

def issue(payload, issuer_private_key: EC2Key):
  redacted, disclosures = redact_map(payload, [])
  msg = Sign1Message(
    phdr = {
        Algorithm: issuer_private_key.alg, 
        KID: issuer_private_key.kid
    },
    uhdr = {
       sd_claims: dumps(disclosures) 
    },
    payload = dumps(redacted, default=redaction_encoder)
  )
  msg.key = issuer_private_key
  return msg 


def reveal_list(array, hashed_disclosures):
  for index in range(0, len(array)):
    if (isinstance(array[index], CBORTag)):
      found = hashed_disclosures.get(array[index].value)
      if (found != None):
        array[index] = found[1]
      else:
        array[index] = None
    if(isinstance(array[index], dict)):
      reveal_map(array[index], hashed_disclosures)
    elif (isinstance(array[index], list)):
      reveal_list(array[index], hashed_disclosures)
  return array

def reveal_map(map, hashed_disclosures): 
  for k, v in list(map.items()):
    if (isinstance(k, CBORTag)):
      for digest in v:
        found = hashed_disclosures.get(digest)
        if (found):
          [_, redacted_key, redacted_value] = found
          map[redacted_key] = redacted_value
          if(isinstance(redacted_value, dict)):
            reveal_map(redacted_value, hashed_disclosures)
          elif (isinstance(redacted_value, list)):
            reveal_list(redacted_value, hashed_disclosures)
        if map.get(k) != None:
          del map[k]

    if(isinstance(v, dict)):
      reveal_map(v, hashed_disclosures)
    elif (isinstance(v, list)):
      reveal_list(v, hashed_disclosures)
  return map

def produce_hashed_disclosures(disclosures):
  hashed_disclosures = {}
  for d in disclosures:
    m = hashlib.sha256()
    m.update(d)
    digested_disclosure = m.digest()
    hashed_disclosures[digested_disclosure] = loads(d)
  return hashed_disclosures

def verify_issuer_signed(token, issuer_public_key: EC2Key): 
  decoded = Sign1Message.decode(token)
  decoded.key = issuer_public_key
  if (decoded.verify_signature() == False):
    raise Exception("Issuer signature verification failed")
  issuer_signed_claims = loads(decoded.payload)
  disclosures = loads(decoded.uhdr[sd_claims])
  hashed_disclosures = produce_hashed_disclosures(disclosures)
  verified_claims = reveal_map(issuer_signed_claims, hashed_disclosures)
  return verified_claims

def present(issued_claims, reveal_disclosures_by_hash, verifier, holder_private_key):
  decoded_issuer_signed_cwt = Sign1Message.decode(issued_claims)
  disclosures = loads(decoded_issuer_signed_cwt.uhdr[sd_claims])
  revealed_disclosures = []
  for d in disclosures:
    m = hashlib.sha256()
    m.update(d)
    digested_disclosure = m.digest()
    if (digested_disclosure in reveal_disclosures_by_hash):
      revealed_disclosures.append(d)
    if len(revealed_disclosures) == len(reveal_disclosures_by_hash):
      break

  decoded_issuer_signed_cwt.uhdr[sd_claims] = dumps(revealed_disclosures)
  redacted_issuer_signed_cwt = decoded_issuer_signed_cwt.encode(sign=False)

  kbt_claims = {
    issued_at: int(time()), # now in seconds since epoch
    expires_at: int(time()) + 2*60, # 2 minutes from now
    audience: verifier['audience'],
    nonce: verifier['nonce'],
    "sd_cwt": redacted_issuer_signed_cwt
  }
  msg = Sign1Message(
    phdr = {
        Algorithm: holder_private_key.alg, 
        KID: holder_private_key.kid
    },
    uhdr = {},
    payload = dumps(kbt_claims)
  )
  msg.key = holder_private_key
  return msg.encode()

def verify_holder_presented(holder_presented_claims, verifier, issuer_public_key):
  key_binding_token = Sign1Message.decode(holder_presented_claims)
  holder_claims = loads(key_binding_token.payload)
  verified_issued_claims = verify_issuer_signed(holder_claims['sd_cwt'], issuer_public_key)
  holder_presentation_key = EC2Key.from_dict({
      KpKid: verified_issued_claims[8][1][2],
      KpKty: verified_issued_claims[8][1][1],
      EC2KpCurve: verified_issued_claims[8][1][-1],
      KpAlg: verified_issued_claims[8][1][3],
      EC2KpX: verified_issued_claims[8][1][-2],
      EC2KpY: verified_issued_claims[8][1][-3],
  })
  key_binding_token.key = holder_presentation_key

  if (key_binding_token.verify_signature() == False):
    raise Exception("Holder signature verification failed")
  
  now = int(time())

  if holder_claims[audience] != verifier['audience']:
    raise Exception("Presentation audience is not correct")
  if holder_claims[nonce] != verifier['nonce']:
    raise Exception("Presentation nonce is not correct")
  
  if holder_claims.get(not_before) != None:
    if now < holder_claims[not_before]:
      raise Exception("Presentation not yet valid")
    
  if holder_claims.get(issued_at) != None:
    if now < holder_claims[issued_at]:
      raise Exception("Presentation not yet valid")
    
  if holder_claims.get(expires_at) != None:
    if now > holder_claims[expires_at]:
      raise Exception("Presentation has expired")

  return verified_issued_claims
