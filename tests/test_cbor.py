

from cbor2 import dumps, CBORTag

def test_annotated_map():
    class RedactableKey:
        def __init__(self, value):
            self.value = value
    class RedactableValue:
        def __init__(self, value):
            self.value = value

    def redaction_encoder(encoder, redactable):
        if (isinstance(redactable, RedactableKey)):
            return encoder.encode(CBORTag(123, redactable.value))
        if (isinstance(redactable, RedactableValue)):
            return encoder.encode(CBORTag(456, redactable.value))
    map = { 
        RedactableKey(0): 'fake ',
        "list": [0, RedactableValue(1), 2]
    }
    assert dumps(map, default=redaction_encoder).hex() == "a2d87b006566616b6520646c6973748300d901c80102" 

   