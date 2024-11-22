import yaml
from sd_cwt import key, claims
from time import time 
from cbor2 import loads
from pycose.messages import Sign1Message
def test_generate_case_0():
    issuer_private_key = key.gen()
    issuer_public_key = key.public_from_private(issuer_private_key)

    holder_private_key = key.gen()
    holder_public_key = key.public_from_private(holder_private_key)

    issued_at = int(time()) # seconds
    redactable_claims = {
      claims.confirmation: {
        claims.key_confirmation: {
          key.kid: holder_public_key.kid,
          key.alg: key.ES256,
          key.type: key.EC2,
          key.curve: key.P256,
          key.x: holder_public_key.x,
          key.y: holder_public_key.y
        }
      },
      claims.issuer : "https://issuer.example",
      claims.subject : "https://subject.example",
      claims.issued_at : issued_at, 
      claims.RedactableKey("amount"): 100,
      claims.RedactableKey("origin"): "KE",
      "destination": [ claims.RedactableValue("US"), "DE" ]
    }
    issuer_signed_cwt = claims.issue(redactable_claims, issuer_private_key).encode()

    decoded_issuer_signed_cwt = Sign1Message.decode(issuer_signed_cwt)
    disclosures = loads(decoded_issuer_signed_cwt.uhdr[claims.sd_claims])
    hashed_disclosures = claims.produce_hashed_disclosures(disclosures)
    hashes = list(hashed_disclosures.keys())
    assert hashed_disclosures[hashes[0]] == ['salt', 'amount', 100]
    # only disclose amount
    reveal_disclosures_by_hash = [hashes[0]]
    verifier = {
      'audience' : 'https://verifier.example',
      'nonce' : b'nonce'
    }
    holder_presented_cwt = claims.present(issuer_signed_cwt, reveal_disclosures_by_hash, verifier, holder_private_key) 
    verified_holder_presented = claims.verify_holder_presented(holder_presented_cwt, verifier, issuer_public_key)
    assert verified_holder_presented['destination'][0] == None
    assert verified_holder_presented.get('origin') == None
  
    with open('fixtures/case_0.yml', 'w') as outfile:
      yaml.dump(dict(
        issuer_private_key = issuer_private_key.encode().hex(),
        holder_private_key = holder_private_key.encode().hex(),
        issuer_signed = issuer_signed_cwt.hex(),
        holder_presented = holder_presented_cwt.hex()
      ), outfile, default_flow_style=False)

    
