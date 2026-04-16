import json
def create_message(msg_type, payload, seq, hmac_val=None, signature=None):
    return json.dumps({
        "type": msg_type,
        "seq": seq,
        "payload": payload,
        "hmac": hmac_val,
        "signature": signature
    })
def parse_message(msg):
    return json.loads(msg)
