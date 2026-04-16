import socket
import struct
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
CHUNK_SIZE = 1024
passmsg = '\x1b[38;2;0;200;0mPASS\x1b[0m'
failmsg = '\x1b[38;2;200;0;0mFAIL\x1b[0m'
# RSA KEYS
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
# SOCKET SETUP
server = socket.socket()
server.bind(("localhost", 5001))
server.listen(1)
print("[SERVER] Waiting...")
conn, addr = server.accept()
print("[SERVER] Connected:", addr)
# SEND PUBLIC KEY
conn.send(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))
# RECEIVE CLIENT PUBLIC KEY
client_pub = serialization.load_pem_public_key(conn.recv(2048))
# RECEIVE AES KEY
enc_key = conn.recv(256)
aes_key = private_key.decrypt(
    enc_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# RECEIVE METADATA
filename_len = struct.unpack("I", conn.recv(4))[0]
filename = conn.recv(filename_len).decode()
filesize = struct.unpack("Q", conn.recv(8))[0]
iv = conn.recv(16)
print(f"[SERVER] Receiving file: {filename}, size: {filesize}")
# RECEIVE FILE (CHUNKS)
ciphertext = b""
received = 0
while received < filesize:
    chunk = conn.recv(min(CHUNK_SIZE, filesize - received))
    if not chunk:
        break
    ciphertext += chunk
    received += len(chunk)
# RECEIVE HMAC + SIGNATURE
hmac_recv = conn.recv(32)
signature = conn.recv(256)
print("\n====== VERIFICATION ======")
# HMAC VERIFY
hmac_status = passmsg
try:
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(hmac_recv)
except:
    hmac_status = failmsg
print("HMAC:", hmac_status)
# SIGNATURE VERIFY
sig_status = passmsg
try:
    client_pub.verify(
        signature,
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
except:
    sig_status = failmsg
print("Signature:", sig_status)
# DECRYPT (ONLY IF VALID)
if hmac_status == passmsg and sig_status == passmsg:
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    with open("received_" + filename, "wb") as f:
        f.write(plaintext)
    print("Decryption: PASS (file saved)")
else:
    print("Decryption: SKIPPED")
conn.close()
server.close()
