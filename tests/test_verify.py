
from sd_cwt import key, claims, hash
from cbor2 import loads

def test_nested_objects():
  issuer_private_key = key.gen()
  issuer_public_key = key.public_from_private(issuer_private_key)
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
  token = claims.issue(redactable_claims, issuer_private_key).encode()
  verified_claims = claims.verify(token, issuer_public_key)

  assert verified_claims['planets'][0]['name'] == 'earth'
  assert verified_claims['planets'][0]['continents'][0] == 'asia'
  assert verified_claims['planets'][0]['continents'][1]['name'] == 'africa'
  assert verified_claims['planets'][0]['continents'][1]['countries'][0] == 'KE'
  assert verified_claims['planets'][0]['continents'][1]['countries'][1] == 'ZA'