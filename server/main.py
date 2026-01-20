import os
import socket
import ssl
import threading
import json
import base64

from utils.socket_utils import recv_all, send_resp

from server.utils.cert_gen import (
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
from utils.cert_utils import load_certificate, load_private_key
from server.utils.CSR import sign_csr

from server.controller.fileController import (
    save_file_controller,
    get_file_list_controller,
    get_encrypted_file_controller
)

from server.middleware.fileMiddleware import (
    verify_client_signature,
    create_upload_receipt,
    create_download_receipt
)

from server.controller.userController import (
    register_user, login_user, check_user_exists
)
from server.middleware.userMiddleware import (
    check_password_complexity
)

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
                password_result, password_feedback = check_password_complexity(password)
                
                if (password_result == False):
                    send_resp(conn, b"REG_FAILED")
                    send_resp(conn, json.dumps(password_feedback).encode("utf-8"))
                    continue
                    
                if (check_user_exists(username)):
                    send_resp(conn, b"REG_FAILED")
                    send_resp(conn, json.dumps({"error": "Username already exists"}).encode("utf-8"))
                    continue
                
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
                            
                            # After sending certificate, client can login
                            print(f"[+] {username} can login now...")
                            continue
                            
                        except Exception as e:
                            print(f"[!] Error signing CSR for {username}: {e}")
                            error_msg = json.dumps({"error": str(e)}).encode()
                            conn.send(len(error_msg).to_bytes(8, "big"))
                            conn.send(error_msg)
                except Exception as e:
                    print(f"[!] Error handling CSR after registration: {e}")
                    return
                
            elif action == "login":
                user_data = login_user(username, password)
                if user_data:
                    user = user_data
                    conn.username = user_data["username"] # bind username to the socket
                    conn.userid = user_data["id"] # bind userid to the socket
                    send_resp(conn, b"LOGGED_IN")
                    print(f"[+] User {conn.username} with id: {conn.userid} logged in successfully")
                else:
                    send_resp(conn, b"LOGIN_FAILED")
                    
            else:
                send_resp(conn, b"INVALID_ACTION")

        # If we have a logged-in user, proceed to file handling
        if user:
            # ---------------- FILE HANDLING ----------------
            print(f"[+] Starting file handling for user: {conn.username}")
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
                        length = int.from_bytes(recv_all(conn, 8), "big")
                        data = recv_all(conn, length)
                        payload = json.loads(data.decode())
                        
                        user_id = conn.userid
                        username = conn.username

                        # Middleware verification
                        if verify_client_signature(payload, user_id):
                            saved_file = save_file_controller(payload, file_key, user_id)
                            print(f"[+] File saved from {username}: {saved_file}")

                            try:
                                receipt = create_upload_receipt(payload, saved_file, username, user_id, file_key)
                                send_resp(conn, json.dumps(receipt).encode())
                                print(f"[+] Sent receipt to {username} for {saved_file}")
                            except Exception as e:
                                print(f"[!] Error sending receipt: {e}")
                                send_resp(conn, b"RECEIPT_FAILED")
                        else:
                            print(f"[!] Invalid client signature from {username}")
                            
                    elif cmd == b"PREV":
                        # Receive filename
                        fname_len_bytes = recv_all(conn, 8)
                        if not fname_len_bytes:
                            continue
                        fname_len = int.from_bytes(fname_len_bytes, "big")
                        filename_bytes = recv_all(conn, fname_len)
                        if not filename_bytes:
                            continue
                        filename = filename_bytes.decode()

                        # Load decrypted file in memory
                        try:
                            result = get_encrypted_file_controller(filename)
                            plaintext_b64 = result["content"]  # already a string       
                                                 
                        except Exception as e:
                            payload = json.dumps({"error": str(e)}).encode()
                            conn.send(len(payload).to_bytes(8, "big"))
                            conn.send(payload)
                            continue

                        # For preview, encode as Base64 (so client can handle safely)
                        payload = json.dumps({
                            "filename": filename,
                            "preview": plaintext_b64
                        }).encode()

                        conn.send(len(payload).to_bytes(8, "big"))
                        conn.send(payload)
                        print(f"[+] Sent preview for {filename} to {conn.username}")
                            
                    elif cmd == b"LIST":
                        try:
                            # Get full list of files
                            files = get_file_list_controller()  # now returns a list of dicts

                            # Send JSON-encoded length-prefixed response
                            payload = json.dumps(files, default=str).encode()  # default=str handles datetime
                            conn.send(len(payload).to_bytes(8, 'big'))  # 8-byte length prefix
                            conn.send(payload)

                            print(f"[+] Sent full file info to {conn.username}")
                            continue

                        except Exception as e:
                            print(f"[!] Error sending file list to {conn.username}: {e}")
                            # Send empty list on error
                            payload = json.dumps([]).encode()
                            conn.send(len(payload).to_bytes(8, 'big'))
                            conn.send(payload)
                            continue
                        
                    elif cmd == b"DOWN":
                        # Receive filename
                        fname_len_bytes = recv_all(conn, 8)
                        if not fname_len_bytes:
                            print("[-] Client disconnected")
                            continue
                        fname_len = int.from_bytes(fname_len_bytes, "big")
                        filename_bytes = recv_all(conn, fname_len)
                        if not filename_bytes:
                            print("[-] Client disconnected")
                            continue
                        filename = filename_bytes.decode()

                        file_data = get_encrypted_file_controller(filename)
                        if not file_data:
                            payload = json.dumps({"error": "File does not exist"}).encode()
                            conn.send(len(payload).to_bytes(8, "big"))
                            conn.send(payload)
                            continue

                        payload_bytes = json.dumps(file_data).encode()
                        conn.send(len(payload_bytes).to_bytes(8, "big"))
                        conn.send(payload_bytes)
                        
                        receipt = create_download_receipt(filename, conn.username, conn.userid, file_key)
                        receipt_bytes = json.dumps(receipt).encode()
                        conn.send(len(receipt_bytes).to_bytes(8, "big"))
                        conn.send(receipt_bytes)

                        print(f"[+] Sent file {filename} to {conn.username}")
                            
                except (ConnectionResetError, BrokenPipeError):
                    print(f"[-] Client {addr} disconnected during file handling")
                    break
                except Exception as e:
                    print(f"[!] Error handling file operation for {conn.username}: {e}")
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