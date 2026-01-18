import socket
import ssl
import threading
import json
from utils.PKI_utils import (
    ROOT_KEY_PATH,
    ROOT_CERT_PATH,
    SERVER_KEY_PATH,
    SERVER_CERT_PATH,
    ROOT_KEY_PASSPHRASE,
    SERVER_KEY_PASSPHRASE,
    generate_root_ca, 
    generate_server_certificate
)
from server.utils.rotateMEK import rotate_master_key
from server.controller.fileController import (
    save_file_controller,
    get_file_list_controller,
    get_encrypted_file_controller
)

HOST = '127.0.0.1'
PORT = 5001

server_running = True
server_socket = None

# ---------------- CLIENT HANDLER ----------------
def handle_client(conn, addr, server_key):
    print(f"[+] Connected: {addr}")

    try:
        while True:
            cmd = conn.recv(8)
            if not cmd:
                break

            if cmd == b"QUIT":
                print(f"[-] Client {addr} disconnected")
                break

            if cmd == b"FILE":
                length = int.from_bytes(conn.recv(8), 'big')
                data = conn.recv(length)
                payload = json.loads(data.decode())

                saved_file = save_file_controller(payload, server_key)
                print(f"[+] File saved: {saved_file}")

            if cmd == b"RECV":
                files = get_file_list_controller()
                payload = json.dumps(files).encode()
                conn.send(len(payload).to_bytes(8, 'big'))
                conn.send(payload)

                if not files:
                    continue

                fname_len = int.from_bytes(conn.recv(8), 'big')
                filename = conn.recv(fname_len).decode()

                file_data = get_encrypted_file_controller(filename)
                if file_data:
                    payload = json.dumps(file_data).encode()
                    conn.send(len(payload).to_bytes(8, 'big'))
                    conn.send(payload)
                    print(f"[+] Sent file: {filename}")
                else:
                    error_payload = json.dumps({"error": "File does not exist"}).encode()
                    conn.send(len(error_payload).to_bytes(8, 'big'))
                    conn.send(error_payload)
                    print(f"[!] Client requested nonexistent file: {filename}")

    finally:
        conn.close()


# ---------------- SERVER COMMAND THREAD ----------------
def server_command_listener():
    global server_running, server_socket
    while server_running:
        cmd = input("Server command (/shutdown, /rotate): ").strip()
        if cmd == "/shutdown":
            print("[!] Shutting down server...")
            server_running = False
            server_socket.close()
            break
        elif cmd == "/rotate":
            try:
                print("[*] Rotating Master Key (MEK)...")
                rotate_master_key()
                print("[+] Master Key rotation complete!")
            except Exception as e:
                print(f"[!] Error during MEK rotation: {e}")


# ---------------- MAIN SERVER ----------------
def main():
    global server_socket

    # Generate/load root CA and server certificate
    root_key, root_cert = generate_root_ca()
    server_key, _ = generate_server_certificate(root_key, root_cert)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=SERVER_CERT_PATH, keyfile=SERVER_KEY_PATH, password=SERVER_KEY_PASSPHRASE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        server_socket = sock
        sock.bind((HOST, PORT))
        sock.listen()
        print(f"[+] TLS server listening on {HOST}:{PORT}")

        threading.Thread(target=server_command_listener, daemon=True).start()

        while server_running:
            try:
                conn, addr = sock.accept()
                tls_conn = context.wrap_socket(conn, server_side=True)
                threading.Thread(target=handle_client, args=(tls_conn, addr, server_key), daemon=True).start()
            except OSError:
                break

    print("[+] Server shut down gracefully.")


if __name__ == "__main__":
    main()
