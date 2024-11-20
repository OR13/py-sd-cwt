
from sd_cwt import key, claims, hash
from cbor2 import loads

def test_nested_objects():
    issuer_private_key = key.gen()
    redactable_claims = {
      "example": "🐈‍⬛",
      "planets": [
         claims.RedactableValue({
          "name": "earth",
          claims.RedactableKey("continents"): [
            "asia", 
            claims.RedactableValue({
              "name": "africa",
              claims.RedactableKey("countries"): [
                "KE", 
                claims.RedactableValue("ZA")
              ]
            })
          ]
        }),
        "mars"
      ]
    }
    decoded_token = loads(claims.issue(redactable_claims, issuer_private_key).encode())
    [_, header, payload, _] = decoded_token.value
    disclosures = loads(header[claims.sd_claims])
    assert len(disclosures) == 5

    issued_claims = loads(payload)
    assert (len(issued_claims.keys())) == 2
    
    first_disclosure = loads(disclosures[4]) 
    assert first_disclosure[0] == "salt"
    first_disclosed_value = first_disclosure[1]
    assert first_disclosed_value['name'] == 'earth'
    assert first_disclosed_value[claims.redacted_claim_key][0].hex() == hash.sha256(disclosures[3]).hex()
   
    second_disclosure = loads(disclosures[3])
    assert second_disclosure[0] == "salt"
    assert second_disclosure[1] == "continents"
    assert second_disclosure[2][0] == 'asia'
    assert second_disclosure[2][1].tag == claims.REDACTED_VALUE_TAG
    assert second_disclosure[2][1].value.hex() == hash.sha256(disclosures[2]).hex()

    third_disclosure = loads(disclosures[2])
    assert third_disclosure[0] == "salt"
    assert third_disclosure[1]['name'] == "africa"
    assert third_disclosure[1][claims.redacted_claim_key][0].hex() == hash.sha256(disclosures[1]).hex()
    
    fourth_disclosure = loads(disclosures[1])
    assert fourth_disclosure[0] == "salt"
    assert fourth_disclosure[1] == "countries"
    assert fourth_disclosure[2][0] == "KE"
    assert fourth_disclosure[2][1].tag ==  claims.REDACTED_VALUE_TAG
    assert fourth_disclosure[2][1].value.hex() == hash.sha256(disclosures[0]).hex()

    fifth_disclosure = loads(disclosures[0])
    assert fifth_disclosure[0] == "salt"
    assert fifth_disclosure[1] == "ZA"
 