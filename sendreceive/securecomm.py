from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
print("\n=== SECURE COMMUNICATION SYSTEM ===\n")
# RSA Key Generation
receiver_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
receiver_public = receiver_private.public_key()
sender_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sender_public = sender_private.public_key()
# USER INPUT MESSAGE
message = input("Enter message to send: ").encode()
# AES Encryption
aes_key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
# HMAC
h = hmac.HMAC(aes_key, hashes.SHA256())
h.update(ciphertext)
mac = h.finalize()
# RSA Encrypt AES Key
encrypted_key = receiver_public.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# DIGITAL SIGNATURE
digest = hashes.Hash(hashes.SHA256())
digest.update(ciphertext)
hash_value = digest.finalize()
signature = sender_private.sign(
    hash_value,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
#  TAMPERING OPTIONS
# Ciphertext tampering
choice = input("\nTamper ciphertext? (y/n): ")
if choice.lower() == 'y':
    extra = input("Enter text to append: ").encode()
    ciphertext += extra
    print(" Ciphertext modified!")
# HMAC tampering
choice = input("\nTamper HMAC? (y/n): ")
if choice.lower() == 'y':
    mac = b"fake_mac"
    print(" HMAC modified!")
# Signature tampering
choice = input("\nTamper Signature? (y/n): ")
if choice.lower() == 'y':
    signature = b"fake_signature"
    print(" Signature modified!")
# Wrong key simulation
choice = input("\nUse wrong RSA key? (y/n): ")
use_wrong_key = choice.lower() == 'y'
# RECEIVER SIDE
print("\n=== RECEIVER SIDE ===")
# Step 1: Decrypt AES key
try:
    if use_wrong_key:
        fake_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        decrypted_key = fake_private.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    else:
        decrypted_key = receiver_private.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    print("\x1b[38;2;0;200;0m AES key decrypted successfully\x1b[0m")
except Exception as e:
    print("\x1b[38;2;200;0;0m AES key decryption failed (wrong key)\x1b[0m")
    exit()
# Step 2: Verify Signature
try:
    sender_public.verify(
        signature,
        hash_value,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("\x1b[38;2;0;200;0m Signature verification PASSED\x1b[0m")
except Exception:
    print("\x1b[38;2;200;0;0m Signature verification FAILED\x1b[0m")
# Step 3: Verify HMAC
try:
    h2 = hmac.HMAC(decrypted_key, hashes.SHA256())
    h2.update(ciphertext)
    h2.verify(mac)
    print("\x1b[38;2;0;200;0m HMAC verification PASSED\x1b[0m")
except Exception:
    print("\x1b[38;2;200;0;0m HMAC verification FAILED\x1b[0m")
# Step 4: Decrypt Message
try:
    cipher = Cipher(algorithms.AES(decrypted_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    print("\x1b[38;2;0;200;0m Decryption successful\x1b[0m")
    print(" Message received:", plaintext.decode(errors='ignore'))
except Exception:
    print("\x1b[38;2;200;0;0m Decryption FAILED\x1b[0m")
print("\n=== END ===")
