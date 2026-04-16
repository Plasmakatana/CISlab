import socket
import os
import struct
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
CHUNK_SIZE = 1024
# CLIENT RSA KEYS
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
# CONNECT
client = socket.socket()
client.connect(("localhost", 5001))
# RECEIVE SERVER KEY
server_pub = serialization.load_pem_public_key(client.recv(2048))
# SEND CLIENT PUBLIC KEY
client.send(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))
# AES KEY
aes_key = os.urandom(32)
enc_key = server_pub.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
client.send(enc_key)
# SELECT FILE
filepath = input("Enter file path: ")
filename = os.path.basename(filepath)
with open(filepath, "rb") as f:
    file_data = f.read()
# AES ENCRYPTION
iv = os.urandom(16)
padder = sym_padding.PKCS7(128).padder()
padded = padder.update(file_data) + padder.finalize()
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()
# HMAC
h = hmac.HMAC(aes_key, hashes.SHA256())
h.update(ciphertext)
hmac_val = h.finalize()
# SIGNATURE
signature = private_key.sign(
    ciphertext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
#  TAMPERING OPTIONS
print("\n--- Tampering ---")
if input("Modify file data? (y/n): ") == 'y':
    temp = bytearray(ciphertext)
    temp[0] ^= 1
    ciphertext = bytes(temp)
if input("Modify HMAC? (y/n): ") == 'y':
    temp = bytearray(hmac_val)
    temp[0] ^= 1
    hmac_val = bytes(temp)
if input("Modify signature? (y/n): ") == 'y':
    signature = signature[:-1] + b'0'
# SEND METADATA
client.send(struct.pack("I", len(filename)))
client.send(filename.encode())
client.send(struct.pack("Q", len(ciphertext)))
client.send(iv)



# SEND FILE (CHUNKS)

sent = 0
while sent < len(ciphertext):
    chunk = ciphertext[sent:sent+CHUNK_SIZE]
    client.send(chunk)
    sent += len(chunk)



# SEND HMAC + SIGNATURE

client.send(hmac_val)
client.send(signature)

print("[CLIENT] File sent securely")

client.close()
