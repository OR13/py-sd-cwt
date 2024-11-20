
import hashlib

from cbor2 import CBORTag, dumps

from pycose.keys import EC2Key
from pycose.headers import Algorithm, KID
from pycose.messages import Sign1Message
from pycose.algorithms import Es256

# cwt claims
issuer = 1
subject = 2
issued_at = 6

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