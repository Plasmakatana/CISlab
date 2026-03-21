import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

# Helper Functions

def pad_data(data):
    padder = PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

def unpad_data(padded_data):
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def encrypt_AES(key, iv, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_data = pad_data(plaintext.encode())
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def decrypt_AES(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    decrypted = unpad_data(decrypted_padded)

    return decrypted.decode()

# Task 1: AES Message Encryption

print("----- TASK 1: AES MESSAGE ENCRYPTION -----")

plaintext = input("Enter plaintext message: ")

# Generate AES 128-bit key and IV
key = os.urandom(16)   # 16 bytes = 128 bits
iv = os.urandom(16)

ciphertext = encrypt_AES(key, iv, plaintext)
decrypted_text = decrypt_AES(key, iv, ciphertext)

print("\nAES Key (hex):", key.hex())
print("IV:", iv.hex())
print("Ciphertext:", ciphertext.hex())
print("Decrypted Text:", decrypted_text)

# Task 2: File Encryption System

print("\n----- TASK 2: FILE ENCRYPTION SYSTEM -----")

# Create sample file
sample_text = "This is a sample file for AES encryption demo."
with open("sample.txt", "w") as f:
    f.write(sample_text)

print("Sample file created: sample.txt")

# Read file
with open("sample.txt", "rb") as f:
    file_data = f.read()

# Encrypt file
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

padded_file = pad_data(file_data)
encrypted_file = encryptor.update(padded_file) + encryptor.finalize()

# Save encrypted file
with open("encrypted_file.bin", "wb") as f:
    f.write(encrypted_file)

print("Encrypted file saved as: encrypted_file.bin")

# Decrypt file
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
decryptor = cipher.decryptor()

decrypted_padded = decryptor.update(encrypted_file) + decryptor.finalize()
decrypted_file = unpad_data(decrypted_padded)

with open("decrypted_file.txt", "wb") as f:
    f.write(decrypted_file)

print("Decrypted file saved as: decrypted_file.txt")

# Verify correctness
if decrypted_file == file_data:
    print("File decryption verified successfully!")

# Task 3: Analysis

print("\n----- TASK 3: ANALYSIS -----")

print("\n1. Why AES is more secure than classical ciphers?")
print("AES uses complex mathematical transformations and large key sizes.")
print("Classical ciphers like Caesar or substitution are easily broken with modern computing.")

print("\n2. Why IV is required in CBC mode?")
print("The IV ensures that identical plaintext blocks produce different ciphertexts.")
print("It prevents pattern leakage in encryption.")

print("\n3. What happens if the same key & IV are reused?")
print("Using the same key and IV can reveal patterns in encrypted data.")
print("This weakens security and may allow attackers to recover information.")
