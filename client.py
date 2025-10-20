import socket
import json
import argparse
import os
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.backends import default_backend
import secrets
import base64
import time

parser = argparse.ArgumentParser()
parser.add_argument('--name', required=True)
parser.add_argument('--role', choices=['sender', 'receiver'], required=True)
parser.add_argument('--server-host', default='127.0.0.1')
parser.add_argument('--server-port', type=int, default=9000)
parser.add_argument('--target', default=None, help='target name to send messages to (sender)')
args = parser.parse_args()

NAME = args.name
ROLE = args.role
SERVER = args.server_host
PORT = args.server_port
TARGET = args.target

KEY_DIR = f'keys_{NAME}'
os.makedirs(KEY_DIR, exist_ok=True)
priv_path = os.path.join(KEY_DIR, 'private_key.pem')
pub_path = os.path.join(KEY_DIR, 'public_key.pem')
MESSAGES_FILE = f'messages_{NAME}.json'

def save_messages_log(entry):
    logs = []
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE,'r') as f:
            try:
                logs = json.load(f)
            except:
                logs = []
    logs.append(entry)
    with open(MESSAGES_FILE,'w') as f:
        json.dump(logs, f, indent=2)

# generate or load RSA keys
def load_or_create_keys():
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path,'rb') as f:
            private = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path,'rb') as f:
            public_pem = f.read()
        return private, public_pem
    else:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public = private.public_key()
        public_pem = public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(priv_path,'wb') as f:
            f.write(private_pem)
        with open(pub_path,'wb') as f:
            f.write(public_pem)
        return private, public_pem

private_key, public_pem = load_or_create_keys()

def rsa_decrypt(enc_bytes):
    return private_key.decrypt(
        enc_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def rsa_encrypt(pub_pem, plaintext_bytes):
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(
        plaintext_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def aes_encrypt(aes_key, plaintext):
    iv = secrets.token_bytes(16)
    padder = sympadding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return iv + enc  # prepend iv

def aes_decrypt(aes_key, data):
    iv = data[:16]
    ct = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpad = sympadding.PKCS7(128).unpadder()
    return unpad.update(dec) + unpad.finalize()

def recv_loop(sock):
    while True:
        try:
            raw = sock.recv(65536)
            if not raw:
                time.sleep(0.1)
                continue
            envelope = json.loads(raw.decode('utf-8'))
            # If it's session key delivery
            if envelope.get('type') == 'session_key':
                enc_session_b64 = envelope['session_key_b64']
                enc_session = base64.b64decode(enc_session_b64)
                session_key = rsa_decrypt(enc_session)
                print(f"\n[{NAME}] Received encrypted session key (base64): {enc_session_b64}")
                print(f"[{NAME}] Decrypted session key (hex): {session_key.hex()}")
                # store for target
                # save to file
                save_messages_log({
                    'direction': 'received',
                    'envelope_type': 'session_key',
                    'encrypted_b64': enc_session_b64,
                    'decrypted_hex': session_key.hex(),
                    'timestamp': time.time()
                })
                # For simplicity, maintain a single session key in memory.
                global CURRENT_SESSION_KEY
                CURRENT_SESSION_KEY = session_key
            elif envelope.get('type') == 'message':
                ciphertext_b64 = envelope['ciphertext_b64']
                print(f"\n[{NAME}] Received ciphertext (base64): {ciphertext_b64}")
                save_messages_log({
                    'direction':'received',
                    'envelope_type':'message',
                    'ciphertext_b64': ciphertext_b64,
                    'timestamp': time.time()
                })
                # decrypt if we have session key
                if 'CURRENT_SESSION_KEY' in globals():
                    ct = base64.b64decode(ciphertext_b64)
                    try:
                        pt_bytes = aes_decrypt(CURRENT_SESSION_KEY, ct)
                        pt = pt_bytes.decode()
                    except Exception as e:
                        pt = f"<decryption failed: {e}>"
                    print(f"[{NAME}] Decrypted plaintext: {pt}")
                    save_messages_log({
                        'direction':'received',
                        'decrypted_plaintext': pt,
                        'timestamp': time.time()
                    })
                else:
                    print(f"[{NAME}] No session key present. Cannot decrypt.")
            else:
                print(f"[{NAME}] Unknown envelope: {envelope}")
        except Exception as e:
            print(f"[{NAME}] recv_loop error:", e)
            break

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SERVER, PORT))
    # register
    register = {'type':'register','name': NAME, 'public_key_pem': public_pem.decode('utf-8')}
    s.sendall(json.dumps(register).encode('utf-8'))
    
    t = threading.Thread(target=recv_loop, args=(s,), daemon=True)
    t.start()
    print(f"[{NAME}] Registered with server and listening for messages.")
    if ROLE == 'sender':
        if not TARGET:
            print("[sender] pass --target TARGETNAME")
            return
        # Main loop handles typing messages and sending the session key plus message.
        while True:
            text = input(f"[{NAME}] Type message to {TARGET} (or 'quit'): ")
            if text.strip().lower() == 'quit':
                break
            #  creating AES session key
            aes_key = secrets.token_bytes(32)  

            target_pub_path = f'keys_{TARGET}/public_key.pem'
            if not os.path.exists(target_pub_path):
                print("[sender] Target public key not found locally. Ensure receiver registered and public key file present at", target_pub_path)
                print("[sender] (In practice, you would request public key from server; for this simple assignment, copy the receiver's public key file into the folder.)")
                continue
            with open(target_pub_path,'rb') as f:
                target_pub = f.read()
           
            # encrypt session with target's public key
            enc_session = rsa_encrypt(target_pub, aes_key)
            enc_session_b64 = base64.b64encode(enc_session).decode('utf-8')
          # Send session_key package to target via server intermediary.
            session_envelope = {
                'type':'session_key',
                'from': NAME,
                'target': TARGET,
                'session_key_b64': enc_session_b64,
                'timestamp': time.time()
            }
            s.sendall(json.dumps(session_envelope).encode('utf-8'))
            save_messages_log({
                'direction':'sent',
                'envelope_type':'session_key',
                'encrypted_b64': enc_session_b64,
                'decrypted_hex': aes_key.hex(),
                'timestamp': time.time()
            })
           # Encrypt the message using AES and send it as a message envelope.
            ciphertext = aes_encrypt(aes_key, text)
            ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
            message_envelope = {
                'type':'message',
                'from': NAME,
                'target': TARGET,
                'ciphertext_b64': ct_b64,
                'timestamp': time.time()
            }
            s.sendall(json.dumps(message_envelope).encode('utf-8'))
            save_messages_log({
                'direction':'sent',
                'envelope_type':'message',
                'ciphertext_b64': ct_b64,
                'plaintext': text,
                'timestamp': time.time()
            })
            print(f"[{NAME}] Sent encrypted message to {TARGET}.")
    else:
       
        print(f"[{NAME}] Receiver running. Waiting for messages. (Press Ctrl+C to exit)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

if __name__ == '__main__':
    main()