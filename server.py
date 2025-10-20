import socket
import threading
import json

HOST = '127.0.0.1'
PORT = 9000

# in-memory store: name -> (conn, addr, public_key_pem)
clients = {}
clients_lock = threading.Lock()

def handle_client(conn, addr):
    try:
        with conn:
           # Ensure the first message is a JSON register message.
            data = conn.recv(65536)
            if not data:
                return
            msg = json.loads(data.decode('utf-8'))
            if msg.get('type') == 'register':
                name = msg['name']
                pubkey = msg['public_key_pem']
                with clients_lock:
                    clients[name] = {'conn': conn, 'addr': addr, 'public_key_pem': pubkey}
                print(f"[SERVER] Registered {name} from {addr}")
                # keep connection open to forward incoming messages from this client
                while True:
                    raw = conn.recv(65536)
                    if not raw:
                        break
                    envelope = json.loads(raw.decode('utf-8'))
                    # Record the received encrypted payload; server must not attempt decryption.
                    print(f"[SERVER] Received envelope from {name}: {json.dumps(envelope)[:300]}")
                    # route to target if connected
                    target = envelope.get('target')
                    if target:
                        with clients_lock:
                            target_info = clients.get(target)
                        if target_info:
                            try:
                                target_conn = target_info['conn']
                                #Forward the envelope intact, without alteration.
                                target_conn.sendall(json.dumps(envelope).encode('utf-8'))
                                print(f"[SERVER] Forwarded message from {name} to {target}")
                            except Exception as e:
                                print("[SERVER] Error forwarding:", e)
                        else:
                            print(f"[SERVER] Target {target} not connected.")
            else:
                print("[SERVER] First message wasn't registration. Closing.")
    except Exception as e:
        print("[SERVER] Client handler error:", e)
    finally:
        
        remove = None
        with clients_lock:
            for nm, info in list(clients.items()):
                if info['addr'] == addr:
                    remove = nm
                    del clients[nm]
        if remove:
            print(f"[SERVER] Removed {remove}")

def main():
    print("[SERVER] Started on", HOST, PORT)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    try:
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    finally:
        s.close()

if __name__ == '__main__':
    main()