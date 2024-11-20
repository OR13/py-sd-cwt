

import hashlib

def sha256(data):
  m = hashlib.sha256()
  m.update(data)
  return m.digest()