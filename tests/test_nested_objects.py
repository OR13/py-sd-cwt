
from sd_cwt import key, claims, hash
from cbor2 import loads

def test_nested_objects():
    issuer_private_key = key.gen()
    redactable_claims = {
      claims.RedactableKey("earth"): {
        claims.RedactableKey("north_america") : {
          claims.RedactableKey("texas") : {
            "city": "austin"
          }
        }
      }
    }
    decoded_token = loads(claims.issue(redactable_claims, issuer_private_key).encode())
    [_, header, payload, _] = decoded_token.value
    disclosures = loads(header[claims.sd_claims])
    assert len(disclosures) == 3

    issued_claims = loads(payload)
    assert (len(issued_claims.keys())) == 1

    first_disclosure = loads(disclosures[2]) 
    assert first_disclosure[0] == "salt"
    assert first_disclosure[1] == "earth"
    assert hash.sha256(disclosures[2]).hex() == issued_claims[claims.redacted_claim_key][0].hex() 

    second_disclosure = loads(disclosures[1]) 
    assert second_disclosure[0] == "salt"
    assert second_disclosure[1] == "north_america"
    assert hash.sha256(disclosures[1]).hex() == first_disclosure[2][claims.redacted_claim_key][0].hex() 
  
    third_disclosure = loads(disclosures[0]) 
    assert third_disclosure[0] == "salt"
    assert third_disclosure[1] == "texas"
    assert hash.sha256(disclosures[0]).hex() == second_disclosure[2][claims.redacted_claim_key][0].hex() 
   
