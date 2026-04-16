import socket
import json
from crypto_utils import *
from protocol import *
HOST = '127.0.0.1'
PORT = 5000
def start_client():
    s = socket.socket()
    s.connect((HOST, PORT))
    # ---- CLIENT HELLO ----
    client_random = get_random_bytes(16)
    payload = {
        "client_random": client_random.hex()
    }
    msg = create_message("CLIENT_HELLO", payload, 1)
    s.send(msg.encode())
    # ---- SERVER HELLO ----
    data = s.recv(4096).decode()
    msg = parse_message(data)
    payload = msg["payload"]
    signature = msg["signature"]
    server_public = RSA.import_key(payload["server_public_key"])
    if not verify_signature(server_public, json.dumps(payload), signature):
        print("[CLIENT] Signature verification failed ")
        return
    print("[CLIENT] Server authenticated ")
    server_random = bytes.fromhex(payload["server_random"])
    # ---- KEY EXCHANGE ----
    premaster = get_random_bytes(16)
    encrypted = rsa_encrypt(server_public, premaster)
    payload = {
        "premaster": encrypted.hex()
    }
    msg = create_message("KEY_EXCHANGE", payload, 2)
    s.send(msg.encode())
    session_key = derive_session_key(premaster, client_random, server_random)
    print("[CLIENT] Session key established")
    seq = 3
    last_message = None   #  store last message
    while True:
        print("\n1. Send new message")
        print("2. Replay last message")
        choice = input("Choose option: ")
    #  REPLAY OPTION
        if choice == '2':
            if last_message:
                print("[CLIENT] Replaying last message...")
                s.send(last_message.encode())
            else:
                print("[CLIENT] No message to replay")
            continue
        #  NORMAL SEND
        text = input("Enter message: ")
        encrypted = aes_encrypt(session_key, text)    
        # Tampering feature
        modify = input("Modify message before sending? (y/n): ")
        if modify.lower() == 'y':
            # safer tampering (keeps base64 valid)
            encrypted = encrypted[:-2] + "AA"
        hmac_val = generate_hmac(session_key, encrypted)
        msg = create_message("SECURE", encrypted, seq, hmac_val)
        #  STORE MESSAGE FOR REPLAY
        last_message = msg
        s.send(msg.encode())
        # ---- RECEIVE ----
        data = s.recv(4096).decode()
        msg = parse_message(data)
        try:
            if not verify_hmac(session_key, msg["payload"], msg["hmac"]):
                print("\x1b[38;2;200;0;0m[CLIENT] HMAC FAILED\x1b[0m")
                continue
            plaintext = aes_decrypt(session_key, msg["payload"])
            print("\x1b[38;2;0;200;0m[CLIENT] Server:\x1b[0m", plaintext)
        except Exception:
            print("\x1b[38;2;200;0;0m[CLIENT] Decryption error\x1b[0m")
        seq += 1
if __name__ == "__main__":
    start_client()
