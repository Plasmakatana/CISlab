import socket
import json
from crypto_utils import *
from protocol import *
HOST = '127.0.0.1'
PORT = 5000
server_private, server_public = generate_rsa_keys()
def start_server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(1)
    print("[SERVER] Listening...")
    conn, addr = s.accept()
    print("[SERVER] Connected:", addr)
    # ---- CLIENT HELLO ----
    data = conn.recv(4096).decode()
    msg = parse_message(data)
    client_random = bytes.fromhex(msg["payload"]["client_random"])
    # ---- SERVER HELLO ----
    server_random = get_random_bytes(16)
    payload = {
        "server_random": server_random.hex(),
        "server_public_key": server_public.export_key().decode()
    }
    signature = sign_data(server_private, json.dumps(payload))
    response = create_message("SERVER_HELLO", payload, 1, signature=signature)
    conn.send(response.encode())
    # ---- KEY EXCHANGE ----
    data = conn.recv(4096).decode()
    msg = parse_message(data)
    encrypted_premaster = bytes.fromhex(msg["payload"]["premaster"])
    premaster = rsa_decrypt(server_private, encrypted_premaster)
    session_key = derive_session_key(premaster, client_random, server_random)
    print("[SERVER] Session key established")
    last_seq = 0
    # ---- SECURE COMM ----
    while True:
        data = conn.recv(4096).decode()
        if not data:
            break
        msg = parse_message(data)
        if msg["seq"] <= last_seq:
            print("\x1b[38;2;200;0;0m[SERVER] Replay detected\x1b[0m")
            continue
        last_seq = msg["seq"]
        ciphertext = msg["payload"]
        try:
            if not verify_hmac(session_key, ciphertext, msg["hmac"]):
                print("\x1b[38;2;200;0;0[SERVER] HMAC FAILED\x1b[0m")
                continue
            plaintext = aes_decrypt(session_key, ciphertext)
            print("\x1b[38;2;0;200;0m[SERVER] Received:\x1b[0m", plaintext)
        except Exception as e:
            print("\x1b[38;2;200;0;0m[SERVER] Decryption error (Tampering Detected)\x1b[0m")
        # reply
        reply = "ACK: " + plaintext
        encrypted = aes_encrypt(session_key, reply)
        hmac_val = generate_hmac(session_key, encrypted)
        response = create_message("SECURE", encrypted, last_seq+1, hmac_val)
        conn.send(response.encode())
    conn.close()
if __name__ == "__main__":
    start_server()
