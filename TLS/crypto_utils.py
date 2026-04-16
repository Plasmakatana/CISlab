import os
import json
import base64
import hashlib
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
# ================= RSA =================
def generate_rsa_keys():
    key = RSA.generate(2048)
    return key, key.publickey()
def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)
def rsa_decrypt(private_key, data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)
# ================= AES =================
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()
def aes_decrypt(key, ciphertext):
    try:
        raw = base64.b64decode(ciphertext)
    except Exception:
        raise ValueError("Invalid ciphertext format (possible tampering)")
    nonce = raw[:16]
    tag = raw[16:32]
    data = raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag).decode()
# ================= HMAC =================
def generate_hmac(key, message):
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()
def verify_hmac(key, message, received_hmac):
    expected = generate_hmac(key, message)
    return hmac.compare_digest(expected, received_hmac)
# ================= SIGNATURE =================
def sign_data(private_key, message):
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()
def verify_signature(public_key, message, signature):
    try:
        h = SHA256.new(message.encode())
        pkcs1_15.new(public_key).verify(h, base64.b64decode(signature))
        return True
    except:
        return False
# ================= SESSION KEY =================
def derive_session_key(premaster, client_random, server_random):
    return hashlib.sha256(premaster + client_random + server_random).digest()[:16]
