

from cbor2 import dumps, loads, CBORTag, CBORSimpleValue
class RedactableKey:
    def __init__(self, value):
        self.value = value
class RedactableValue:
    def __init__(self, value):
        self.value = value

def redaction_encoder(encoder, redactable):
    if (isinstance(redactable, RedactableKey)):
        return encoder.encode(CBORTag(59, redactable.value))
    if (isinstance(redactable, RedactableValue)):
        return encoder.encode(CBORTag(60, redactable.value))
        
def test_annotated_map():
    map = { 
        RedactableKey(0): 'fake ',
        "list": [0, RedactableValue(b'fake'), 2]
    }
    assert dumps(map, default=redaction_encoder).hex() == "a2d83b006566616b6520646c6973748300d83c4466616b6502" 

def test_simple_value():
    redacted_claim_key = CBORSimpleValue(59)
    map = {
        redacted_claim_key: [ b'fake' ],
        "list": [0, RedactableValue(b'fake'), 2]
    }
    encoded = dumps(map, default=redaction_encoder)
    assert encoded.hex() == 'a2f83b814466616b65646c6973748300d83c4466616b6502'
    # tagged 'a2d83b006566616b6520646c6973748300d83c4466616b6502'
    # {59(0): "fake ", "list": [0, 60(h'66616B65'), 2]}
    # simple 'a2f83b814466616b65646c6973748300d83c4466616b6502'
    # {simple(59): [h'66616B65'], "list": [0, 60(h'66616B65'), 2]}
    decoded = loads(encoded)
    assert decoded[redacted_claim_key] == [ b'fake' ]
