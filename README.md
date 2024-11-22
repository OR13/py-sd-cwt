## Not safe to use

🚧 Experimental implementation

### Example Issuer Signed CWT

``` cbor-diag
18([
  <<{
    / alg ES256 / 1: -7, 
    / kid issuer ckt / 4: h'108B6E367F3C036B7AA0821B1384626CE0E55F4140184E29203E3C00E4DA42FB'
  }>>, 
  {
    / disclosures / 17: <<[
      <<["salt", "amount", 100]>>, 
      <<["salt", "origin", "KE"]>>,
      <<["salt", "US"]>>
    ]>>
  }, 
  <<{
    / confirmation / 8: {
      / cose key / 1: {
        / kid holder ckt / 2: h'82DCB410B0503CC8C793E91C2DD92E7E3725150DD15A0E71572909D73EEA23F0', 
        / alg ES256 / 3: -7, 
        / kty EC2 / 1: 2, 
        / crv P256 / -1: 1, 
        / x coordinate / -2: h'BA6075BFD8D4E0C1EACE5A52D963C60FF62B8D5374A53ECD6AE8332438454B13', 
        / y coordinate / -3: h'5216549B87FF2D2B2BD15462EF984ADDA2D7418F77F40DDFB6DBC558F23B098E'
      }
    }, 
    / issuer / 1: "https://issuer.example", 
    / subject / 2: "https://subject.example", 
    / issued at / 6: 1732301500, 
    "destination": [
      / redacted array element / 60(h'651DDC5DB7343266320B0BB289B3A58B54FB2FF2C4B2E1A1662DE99769EA7A02'), 
      "DE"
    ], 
    / redacted map keys (2) / 59(0): [
      h'8DC1AC36B5F2AE8FAA82F823C2EC20AC19D8FB63D2743FEBD05994F058C79BDC', 
      h'CCDF3047F3ADE1364BA1D7B9D55443A71E03C7179055F8867ABDA84630D78A53'
    ]
  }>>, 
  h'F7B7FC9576256681DF7FE1CF902C61ADDEA3131AFAB6E9C53A9B67FB54718D94620AE2383A9E09AFF4D5DFBCEDDFE7CBB5204D23C3E8F267074ECA628AE19739'
])
```

### Example Holder Presented CWT

``` cbor-diab
18([
  <<{
    / alg ES256 / 1: -7, 
    / kid holder ckt / 4: h'82DCB410B0503CC8C793E91C2DD92E7E3725150DD15A0E71572909D73EEA23F0'
  }>>, 
  {}, 
  <<{
    / issued at  / 6: 1732301500, 
    / expires at / 4: 1732301620, 
    / audience / 3: "https://verifier.example", 
    / cnonce / 39: h'6E6F6E6365', 
    "sd_cwt": <<18([
      <<{
        / alg ES256 / 1: -7, 
        / kid issuer ckt / 4: h'108B6E367F3C036B7AA0821B1384626CE0E55F4140184E29203E3C00E4DA42FB'
      }>>, 
      {
        / disclosures / 17: <<[
          <<["salt", "amount", 100]>>
        ]>>
      }, <<{
        / confirmation / 8: {
          / cose key / 1: {
            / kid ckt / 2: h'82DCB410B0503CC8C793E91C2DD92E7E3725150DD15A0E71572909D73EEA23F0', 
            / alg ES256 / 3: -7, 
            / kty EC2 / 1: 2, 
            / crv P256 / -1: 1, 
            / x coordinate / -2: h'BA6075BFD8D4E0C1EACE5A52D963C60FF62B8D5374A53ECD6AE8332438454B13', 
            / y coordinate / -3: h'5216549B87FF2D2B2BD15462EF984ADDA2D7418F77F40DDFB6DBC558F23B098E'
          }
        }, 
        / issuer /  1: "https://issuer.example", 
        / subject / 2: "https://subject.example", 
        / issued at / 6: 1732301500, 
        "destination": [
          / redacted array element / 60(h'651DDC5DB7343266320B0BB289B3A58B54FB2FF2C4B2E1A1662DE99769EA7A02'), 
          "DE"
        ], 
        / redacted map keys (2) / 59(0): [
          h'8DC1AC36B5F2AE8FAA82F823C2EC20AC19D8FB63D2743FEBD05994F058C79BDC', 
          h'CCDF3047F3ADE1364BA1D7B9D55443A71E03C7179055F8867ABDA84630D78A53'
        ]
      }>>, 
      h'F7B7FC9576256681DF7FE1CF902C61ADDEA3131AFAB6E9C53A9B67FB54718D94620AE2383A9E09AFF4D5DFBCEDDFE7CBB5204D23C3E8F267074ECA628AE19739'
    ])>>
  }>>,
  h'282FE5F33E4E3BEFB24A6FF9669F9751C28F22E76B344813CEE5B9E5C4814A70054BCC4DD654C6E688860B93BA2687779A87F0E3FC01D47B44A3DA04A1215284'
])
```


### Setup

```
python3 -m venv venv
source venv/bin/activate
pip install wheel setuptools twine
pip install --upgrade pip
```