
from sd_cwt import key, claims, hash
from cbor2 import loads

def test_nested_lists():
    issuer_private_key = key.gen()
    redactable_claims = {
      "00": [ 
        claims.RedactableValue([
          '11', 
          claims.RedactableValue([
            '20', 
            '21', 
            claims.RedactableValue('22')
            ]), 
          '12'
        ]), 
      '01', 
      '02'
      ]
    }
    decoded_token = loads(claims.issue(redactable_claims, issuer_private_key).encode())
    [_, header, payload, _] = decoded_token.value
    disclosures = loads(header[claims.sd_claims])
    assert len(disclosures) == 3

    issued_claims = loads(payload)
    assert (len(issued_claims.keys())) == 1

    first_disclosure = loads(disclosures[2]) 
    assert first_disclosure[0] == "salt"
    first_disclosed_value = first_disclosure[1]
    assert first_disclosed_value[1].tag == claims.REDACTED_VALUE_TAG
    assert first_disclosed_value[1].value.hex() == hash.sha256(disclosures[1]).hex()

    second_disclosure = loads(disclosures[1]) 
    assert second_disclosure[0] == "salt"
    second_disclosed_value = second_disclosure[1]
    assert second_disclosed_value[2].tag == claims.REDACTED_VALUE_TAG
    assert second_disclosed_value[2].value.hex() == hash.sha256(disclosures[0]).hex()

    third_disclosure = loads(disclosures[0]) 
    assert third_disclosure[0] == "salt"
    third_disclosed_value = third_disclosure[1]
    assert third_disclosed_value == '22'
    
    # print("")
    # for d in disclosures:
    #   print(loads(d))

   

    
   
