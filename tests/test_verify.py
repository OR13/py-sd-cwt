
from sd_cwt import key, claims
from cbor2 import loads
from pycose.messages import Sign1Message

def test_verify_full_disclosure():
  issuer_private_key = key.gen()
  issuer_public_key = key.public_from_private(issuer_private_key)

  holder_private_key = key.gen()
  holder_public_key = key.public_from_private(holder_private_key)

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
  issued_claims = claims.issue(redactable_claims, issuer_private_key).encode()
  verified_issuer_signed_claims = claims.verify_issuer_signed(issued_claims, issuer_public_key)

  assert verified_issuer_signed_claims['planets'][0]['name'] == 'earth'
  assert verified_issuer_signed_claims['planets'][0]['continents'][0] == 'asia'
  assert verified_issuer_signed_claims['planets'][0]['continents'][1]['name'] == 'africa'
  assert verified_issuer_signed_claims['planets'][0]['continents'][1]['countries'][0] == 'KE'
  assert verified_issuer_signed_claims['planets'][0]['continents'][1]['countries'][1] == 'ZA' 

  verifier = {
    'audience' : 'https://verifier.example',
    'nonce' : b'nonce'
  }

  decoded_issuer_signed_cwt = Sign1Message.decode(issued_claims)
  disclosures = loads(decoded_issuer_signed_cwt.uhdr[claims.sd_claims])
  hashed_disclosures = claims.produce_hashed_disclosures(disclosures)
  hashes = list(hashed_disclosures.keys())

  # 4th hash reveals first element of the planets array
  assert hashed_disclosures[hashes[4]][1]['name'] == 'earth' 
  # 3rd hash reveals continents key of the earth map
  assert hashed_disclosures[hashes[3]][1] == 'continents' 

  reveal_disclosures_by_hash = [
    hashes[4],
    hashes[3]
    # the rest remain redacted
  ]

  presented_claims = claims.present(issued_claims, reveal_disclosures_by_hash, verifier, holder_private_key) 
  verified_holder_presented = claims.verify_holder_presented(presented_claims, verifier, issuer_public_key)

  assert verified_holder_presented['planets'][0]['name'] == 'earth'
  assert verified_holder_presented['planets'][0]['continents'][0] == 'asia'
  assert verified_holder_presented['planets'][0]['continents'][1] == None
