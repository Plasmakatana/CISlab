import socket
import os
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
# 1. Generate Client RSA Keys
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
client_public_key = client_private_key.public_key()
print("[CLIENT] RSA keys generated")
# 2. Connect to Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 5000))
print("[CLIENT] Connected to server")
# 3. Receive Server Public Key
server_pub_bytes = client.recv(2048)
server_public_key = serialization.load_pem_public_key(server_pub_bytes)
print("[CLIENT] Received server public key")
# 4. Send Client Public Key
client_pub_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
client.send(client_pub_bytes)
# 5. Generate AES Key
aes_key = os.urandom(32)
# 6. Encrypt AES Key
enc_key = server_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
client.send(enc_key)
# 7. Input Message
message = input("Enter message: ").encode()
iv = os.urandom(16)
padder = sym_padding.PKCS7(128).padder()
padded = padder.update(message) + padder.finalize()
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded) + encryptor.finalize()
# 8. Generate HMAC
h = hmac.HMAC(aes_key, hashes.SHA256())
h.update(ciphertext)
hmac_val = h.finalize()
# 9. Sign Ciphertext
signature = client_private_key.sign(
    ciphertext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
#  10. Tampering Options
print("\n--- Tampering Options ---")
tamper_ct = input("Modify ciphertext? (y/n): ").lower()
tamper_hmac = input("Modify HMAC? (y/n): ").lower()
tamper_sig = input("Modify signature? (y/n): ").lower()

# Modify ciphertext
if tamper_ct == 'y':
    print("[CLIENT] Tampering ciphertext...")
    temp = bytearray(ciphertext)
    temp[0] ^= 1
    ciphertext = bytes(temp)
# Modify HMAC
if tamper_hmac == 'y':
    print("[CLIENT] Tampering HMAC...")
    temp = bytearray(hmac_val)
    temp[0] ^= 1
    hmac_val = bytes(temp)
# Modify Signature
if tamper_sig == 'y':
    print("[CLIENT] Tampering signature...")
    signature = signature[:-1] + b'0'
# 11. Send Packet
packet = iv + hmac_val + signature + ciphertext
client.send(packet)
print("[CLIENT] Packet sent")
client.close()
