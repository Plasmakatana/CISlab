import hashlib
import os


# Task 1: Hashing a Message

def hash_message():
    print("\n=== Task 1: Hashing a Message ===")

    message = input("Enter a message: ")
    message_bytes = message.encode()

    sha256_hash = hashlib.sha256(message_bytes).hexdigest()
    sha1_hash = hashlib.sha1(message_bytes).hexdigest()

    print("\nSHA-256:", sha256_hash)
    print("SHA-1  :", sha1_hash)

# Function to compute SHA-256 hash

def compute_sha256(filename):

    sha256 = hashlib.sha256()

    with open(filename, "rb") as f:
        while True:
            data = f.read(4096)
            if not data:
                break
            sha256.update(data)

    return sha256.hexdigest()

# Task 2: File Integrity Checker

def file_integrity_checker():

    print("\n=== Task 2: File Integrity Checker ===")

    filename = "sample_data.txt"

    # Create a text file programmatically
    with open(filename, "w") as f:
        f.write("This is the original file.\n")
        f.write("Integrity should remain intact.\n")

    print("File created:", filename)

    # Compute and store SHA-256 hash
    original_hash = compute_sha256(filename)

    print("Stored SHA-256 Hash:", original_hash)

    # Modify file contents
    with open(filename, "a") as f:
        f.write("This line simulates modification.\n")

    print("File modified.")

    # Recompute the hash
    new_hash = compute_sha256(filename)

    print("New SHA-256 Hash:", new_hash)

    # Compare hashes
    if original_hash == new_hash:
        print("Integrity Status: PRESERVED")
    else:
        print("Integrity Status: VIOLATED")

# Task 3: Tampering Detection

def tampering_detection():

    print("\n=== Task 3: Tampering Detection ===")

    filename = "sample_data.txt"

    # Hash before modification
    hash_before = compute_sha256(filename)
    print("Hash BEFORE modification:", hash_before)

    # Simulate tampering
    with open(filename, "a") as f:
        f.write("Malicious change added!\n")

    # Hash after modification
    hash_after = compute_sha256(filename)
    print("Hash AFTER modification :", hash_after)

    # Integrity check
    if hash_before == hash_after:
        print("File Integrity: PRESERVED")
    else:
        print("File Integrity: VIOLATED (Tampering Detected!)")

# Main Program

def main():

    hash_message()
    file_integrity_checker()
    tampering_detection()


if __name__ == "__main__":
    main()
