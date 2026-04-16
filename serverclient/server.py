import socket
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
passmsg = '\x1b[38;2;0;200;0mPASS\x1b[0m'
failmsg = '\x1b[38;2;200;0;0mFAIL\x1b[0m'
# 1. Generate RSA Keys
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()
print("[SERVER] RSA keys generated")
# 2. Start server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 5000))
server.listen(1)
print("[SERVER] Listening...")
conn, addr = server.accept()
print("[SERVER] Connected:", addr)
# 3. Send Public Key
pub_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
conn.send(pub_bytes)
# 4. Receive Client Public Key
client_pub_bytes = conn.recv(2048)
client_public_key = serialization.load_pem_public_key(client_pub_bytes)
# 5. Receive AES Key
enc_aes_key = conn.recv(256)
aes_key = server_private_key.decrypt(
    enc_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# 6. Receive Data
data = conn.recv(4096)
iv = data[:16]
hmac_recv = data[16:48]
signature = data[48:304]
ciphertext = data[304:]
print("\n========== VERIFICATION REPORT ==========")
# 7. HMAC Verification
hmac_status = passmsg
try:
    h = hmac.HMAC(aes_key, hashes.SHA256())
    h.update(ciphertext)
    h.verify(hmac_recv)
except Exception:
    hmac_status = failmsg
print(f"HMAC Verification: {hmac_status}")
# 8. Signature Verification
sig_status = passmsg
try:
    client_public_key.verify(
        signature,
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
except Exception:
    sig_status = failmsg
print(f"Signature Verification: {sig_status}")
# 9. Decryption (only if valid)
if hmac_status == passmsg and sig_status == passmsg:
    try:
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        print("Decryption: PASS")
        print("Message:", plaintext.decode())
    except Exception:
        print("Decryption: FAIL")
else:
    print("Decryption: SKIPPED (Integrity/Auth failed)")
print("========================================")
conn.close()
server.close()
