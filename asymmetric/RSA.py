from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

# Task 1: RSA Key GENERATION
print("----- TASK 1: RSA KEY GENERATION -----")
# Generate RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
print("Key Size:", private_key.key_size, "bits")
# Save Private Key
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
# Save Public Key
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
print("Keys saved to files.\n")
# Task 2: RSA Encryption & Decryption
print("----- TASK 2: ENCRYPTION & DECRYPTION -----")
msg = input("Enter message:")
message =bytes(msg,'utf-8')
# Encrypt using Public Key
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Ciphertext (hex):", ciphertext.hex())
# Decrypt using Private Key
decrypted_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted Message:", decrypted_message.decode(), "\n")
# Task 3: Digital Signature
print("----- TASK 3: DIGITAL SIGNATURE -----")
msg = input("Enter secure message:")
messgae = bytes(msg,'utf-8')
# Sign Message using Private Key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("Signature created.")
# Verify Signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature verification: SUCCESS")
except InvalidSignature:
    print("Signature verification: FAILED")
# Modify message
t_msg = input("Enter modified message: ")
tampered_message=bytes(t_msg,'utf-8')
print("\nTesting with modified message...")
try:
    public_key.verify(
        signature,
        tampered_message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Verification: SUCCESS")
except InvalidSignature:
    print("Verification after tampering: FAILED (Expected)")
# Task 4: Analysis
print("\n----- TASK 4: ANALYSIS -----")
print("\n1. Why RSA is slower than AES?")
print("RSA uses complex mathematical operations with very large numbers.")
print("AES uses symmetric encryption which is computationally faster.")
print("\n2. Difference between encryption and signing:")
print("Encryption ensures confidentiality of data.")
print("Digital signing ensures authenticity and integrity of the sender.")
print("\n3. Property provided by digital signatures:")
print("Authentication, Integrity, and Non-repudiation.")
