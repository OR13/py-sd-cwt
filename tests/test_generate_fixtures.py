import yaml
from sd_cwt import key, claims
from time import time 
from cbor2 import loads

def test_generate_case_0():
    issuer_private_key = key.gen()
    issued_at = int(time()) # seconds
    redactable_claims = {
       claims.issuer : "https://issuer.example",
       claims.subject : "https://subject.example",
       claims.issued_at : issued_at, 
       claims.RedactableKey("amount"): 100,
       claims.RedactableKey("origin"): "KE",
       "destination": [ claims.RedactableValue("US"), "DE" ]
    }
    token = claims.issue(redactable_claims, issuer_private_key).encode()
    
    decoded_token = loads(token)
    assert decoded_token.tag == 18
    [protected, header, payload, _] = decoded_token.value
    protected_header = loads(protected)
    assert protected_header[1] == -7 # alg ES256
    issuer_signed_claims = loads(payload)
    assert len(issuer_signed_claims[claims.redacted_claim_key]) == 2 # 2 redacted claims
    disclosures = loads(header[claims.sd_claims])
    assert len(disclosures) == 3 # 3 disclosures

    assert issuer_signed_claims["destination"][1] == "DE"
    assert issuer_signed_claims["destination"][0].tag == claims.REDACTED_VALUE_TAG

    hex_encoded_token = token.hex()
    hex_encoded_issuer_private_key = issuer_private_key.encode().hex()

    with open('fixtures/case_0.yml', 'w') as outfile:
      yaml.dump(dict(
        issuer_private_key = hex_encoded_issuer_private_key,
        token = hex_encoded_token
      ), outfile, default_flow_style=False)

    
