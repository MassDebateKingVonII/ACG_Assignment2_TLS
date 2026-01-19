import os
import socket
import ssl
import threading
import json
import base64

from utils.socket_utils import recv_all, send_resp

from utils.PKI_utils import (
    ROOT_KEY_PATH,
    ROOT_CERT_PATH,
    SERVER_KEY_PATH,
    SERVER_CERT_PATH,
    ROOT_KEY_PASSPHRASE,
    SERVER_KEY_PASSPHRASE,
    generate_root_ca, 
    generate_server_certificate,
    generate_file_signing_key
)
from server.utils.rotateMEK import rotate_master_key
from server.utils.cert import load_certificate, load_private_key
from server.utils.CSR import sign_csr

from server.controller.fileController import (
    save_file_controller,
    get_file_list_controller,
    get_encrypted_file_controller
)

from server.controller.userController import register_user, login_user, check_user_exists

HOST = '127.0.0.1'
PORT = 5001

server_running = True
server_socket = None

# ---------------- CLIENT HANDLER ----------------
def handle_client(conn, addr, file_key):
    print(f"[+] Connected: {addr}")
    user = None

    try:
        # ---------------- AUTHENTICATION ----------------
        while not user:
            try:
                conn.send(b"AUTH")
            except (ConnectionResetError, BrokenPipeError):
                print(f"[-] Client {addr} disconnected during auth")
                return

            try:
                length_bytes = recv_all(conn, 8)
                if not length_bytes:  # Client disconnected
                    print(f"[-] Client {addr} disconnected")
                    return
                    
                length = int.from_bytes(length_bytes, "big")
                data = recv_all(conn, length)
                
                if not data:  # Client disconnected
                    print(f"[-] Client {addr} disconnected")
                    return
                    
                payload = json.loads(data.decode())
            except (ConnectionResetError, BrokenPipeError, json.JSONDecodeError) as e:
                print(f"[-] Client {addr} disconnected or sent invalid data: {e}")
                return

            action = payload.get("action")

            if action == "quit":
                print(f"[-] Client {addr} quit during auth")
                return

            username = payload.get("username")
            password = payload.get("password")

            if action == "register":
                if (check_user_exists(username) == False):
                    send_resp(conn, b"REGISTERING")
                    
                    # Wait for CSR from client
                    try:
                        csr_length_bytes = recv_all(conn, 8)
                        if not csr_length_bytes:
                            print(f"[-] Client {addr} disconnected after registration")
                            return
                            
                        csr_length = int.from_bytes(csr_length_bytes, "big")
                        csr_data = recv_all(conn, csr_length)
                        
                        if not csr_data:
                            print(f"[-] Client {addr} disconnected while sending CSR")
                            return
                            
                        csr_payload = json.loads(csr_data.decode())
                        
                        if csr_payload.get("action") == "submit_csr":
                            csr_b64 = csr_payload.get("csr")
                            csr_bytes = base64.b64decode(csr_b64)
                            username = csr_payload.get("username")

                            if not csr_bytes or not username:
                                send_resp(conn, b"CSR_FAILED")
                                continue

                            try:
                                # Load root CA
                                root_key = load_private_key(ROOT_KEY_PATH, passphrase=ROOT_KEY_PASSPHRASE)
                                root_cert = load_certificate(ROOT_CERT_PATH)

                                signed_cert = sign_csr(csr_bytes, root_key, root_cert)

                                CERT_DIR = "server/certificates/clients"
                                os.makedirs(CERT_DIR, exist_ok=True)

                                cert_path = os.path.join(CERT_DIR, f"{username}.pem")
                                with open(cert_path, "wb") as f:
                                    f.write(signed_cert)

                                conn.send(len(signed_cert).to_bytes(8, "big"))
                                conn.send(signed_cert)

                                register_user(username, password, cert_path)

                                print(f"[+] Signed certificate sent to {username}")
                                print(f"[+] Certificate stored at {cert_path}")
                                
                                # After sending certificate, go back to auth menu (don't break)
                                # Client will need to login now
                                print(f"[+] Waiting for {username} to login...")
                                # Continue the loop to show auth menu again
                                continue
                                
                            except Exception as e:
                                print(f"[!] Error signing CSR for {username}: {e}")
                                error_msg = json.dumps({"error": str(e)}).encode()
                                conn.send(len(error_msg).to_bytes(8, "big"))
                                conn.send(error_msg)
                    except Exception as e:
                        print(f"[!] Error handling CSR after registration: {e}")
                        return
                        
                else:
                    send_resp(conn, b"REG_FAILED")
                
            elif action == "login":
                user_data = login_user(username, password)
                if user_data:
                    user = user_data
                    send_resp(conn, b"LOGGED_IN")
                    print(f"[+] User {username} logged in successfully")
                else:
                    send_resp(conn, b"LOGIN_FAILED")

            else:
                send_resp(conn, b"INVALID_ACTION")

        # If we have a logged-in user, proceed to file handling
        if user:
            # ---------------- FILE HANDLING ----------------
            print(f"[+] Starting file handling for user: {user['username']}")
            while True:
                try:
                    cmd = recv_all(conn, 4)
                    if not cmd:
                        print(f"[-] Client {addr} disconnected")
                        break

                    if cmd == b"QUIT":
                        print(f"[-] Client {addr} disconnected via QUIT")
                        break

                    if cmd == b"FILE":
                        length = int.from_bytes(recv_all(conn, 8), 'big')
                        data = recv_all(conn, length)
                        payload = json.loads(data.decode())
                        saved_file = save_file_controller(payload, file_key)
                        print(f"[+] File saved from {user['username']}: {saved_file}")

                    elif cmd == b"RECV":
                        files = get_file_list_controller()
                        payload = json.dumps(files).encode()
                        conn.send(len(payload).to_bytes(8, 'big'))
                        conn.send(payload)

                        if not files:
                            continue

                        fname_len = int.from_bytes(recv_all(conn, 8), 'big')
                        filename = recv_all(conn, fname_len).decode()

                        file_data = get_encrypted_file_controller(filename)
                        if file_data:
                            payload = json.dumps(file_data).encode()
                            conn.send(len(payload).to_bytes(8, 'big'))
                            conn.send(payload)
                            print(f"[+] Sent file to {user['username']}: {filename}")
                        else:
                            error_payload = json.dumps({"error": "File does not exist"}).encode()
                            conn.send(len(error_payload).to_bytes(8, 'big'))
                            conn.send(error_payload)
                            print(f"[!] {user['username']} requested nonexistent file: {filename}")
                            
                except (ConnectionResetError, BrokenPipeError):
                    print(f"[-] Client {addr} disconnected during file handling")
                    break
                except Exception as e:
                    print(f"[!] Error handling file operation for {user['username']}: {e}")
                    break

    except Exception as e:
        print(f"[!] Unexpected error handling client {addr}: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except:
            pass
        print(f"[-] Connection closed: {addr}")

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
    server_key, server_cert = generate_server_certificate(root_key, root_cert)
    file_key, file_cert = generate_file_signing_key(root_key, root_cert)

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
                threading.Thread(target=handle_client, args=(tls_conn, addr, file_key), daemon=True).start()
            except OSError:
                break

    print("[+] Server shut down gracefully.")


if __name__ == "__main__":
    main()
