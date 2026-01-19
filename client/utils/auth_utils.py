import os, json, base64

from client.utils.CSR_utils import (
    generate_csr,
    CSR_FILE_PATH,
    KEY_FILE_PATH
)

CLIENT_CERT_PATH = os.path.join("client_path", "certificates")

from utils.socket_utils import recv_all

def authenticate_client(conn):
    while True:
        # Wait for server auth request
        auth_signal = recv_all(conn, 4)
        if auth_signal != b"AUTH":
            print(f"[!] Expected AUTH request from server, got: {auth_signal}")
            return None

        print("\n--- AUTH MENU ---")
        print("1. Register")
        print("2. Login")
        print("3. /quit")
        choice = input("Choose option: ").strip()

        if choice == "3" or choice.lower() == "/quit":
            payload = {"action": "quit"}
            auth_bytes = json.dumps(payload).encode()
            conn.send(len(auth_bytes).to_bytes(8, "big"))
            conn.send(auth_bytes)
            print("[+] Exiting authentication")
            return None

        elif choice not in ["1", "2"]:
            print("[!] Invalid choice. Please select 1, 2, or 3.")
            continue

        # valid choice; ask credentials
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        payload = {"username": username, "password": password}

        if choice == "1":
            payload["action"] = "register"
            payload["public_key"] = "CLIENT_PUBLIC_KEY_PEM"
        else:
            payload["action"] = "login"

        # Send auth payload
        auth_bytes = json.dumps(payload).encode()
        conn.send(len(auth_bytes).to_bytes(8, "big"))
        conn.send(auth_bytes)

        # Receive auth response
        resp_len_bytes = recv_all(conn, 8)
        if not resp_len_bytes:
            print("[-] Server disconnected")
            return None
        resp_len = int.from_bytes(resp_len_bytes, "big")
        resp = recv_all(conn, resp_len)

        if resp == b"LOGGED_IN":
            print(f"[+] Logged in as {username}")
            return username
            
        elif resp == b"REGISTERED":
            print(f"[+] Registration successful. Generating CSR...")
            
            # Generate CSR
            csr_pem, key_pem = generate_csr(username)
            key_file = os.path.join(KEY_FILE_PATH, f"{username}_key.pem")

            # Save private key locally
            with open(key_file, "wb") as f:
                f.write(key_pem)
            print(f"[+] Private key saved: {key_file}")

            # Send CSR to server
            csr_payload = {
                "action": "submit_csr",
                "username": username,
                "csr": base64.b64encode(csr_pem).decode()
            }
            csr_bytes = json.dumps(csr_payload).encode()
            
            # Send CSR request
            conn.send(len(csr_bytes).to_bytes(8, "big"))
            conn.send(csr_bytes)
            print("[+] CSR sent to server for signing")

            # Wait for certificate from server
            try:
                # Read response length
                cert_len_bytes = recv_all(conn, 8)
                if not cert_len_bytes:
                    print("[-] Server disconnected while sending certificate")
                    return None
                
                cert_len = int.from_bytes(cert_len_bytes, "big")
                print(f"[DEBUG] Receiving certificate of {cert_len} bytes")
                
                # Validate length
                if cert_len > 100 * 1024 or cert_len < 100:
                    print(f"[!] Invalid certificate length: {cert_len} bytes")
                    # Try to read error message
                    if cert_len > 0 and cert_len < 10000:
                        error_data = recv_all(conn, cert_len)
                        try:
                            error_msg = json.loads(error_data.decode())
                            print(f"[!] Server error: {error_msg.get('error', 'Unknown error')}")
                        except:
                            print(f"[!] Raw error data: {error_data[:200]}")
                    return None
                
                # Read the certificate
                signed_cert = recv_all(conn, cert_len)
                
                # Verify it looks like a certificate
                if signed_cert.startswith(b"-----BEGIN CERTIFICATE-----"):
                    cert_file = os.path.join(CLIENT_CERT_PATH, f"{username}_cert.pem")
                    with open(cert_file, "wb") as f:
                        f.write(signed_cert)
                    print(f"[+] Received signed certificate: {cert_file}")
                    print("[+] Registration complete! You can now login.")
                    # Continue to show auth menu again
                    continue
                else:
                    # Might be JSON error
                    try:
                        error_msg = json.loads(signed_cert.decode())
                        print(f"[!] Server error: {error_msg.get('error', 'Unknown error')}")
                    except:
                        print(f"[!] Received invalid data from server")
                        print(f"[!] First 100 bytes: {signed_cert[:100]}")
                    return None
                    
            except MemoryError:
                print("[!] Memory error - certificate size too large")
                return None
            except Exception as e:
                print(f"[!] Error receiving certificate: {e}")
                import traceback
                traceback.print_exc()
                return None

        elif resp == b"LOGIN_FAILED":
            print("[!] Login failed. Try again.")
            continue
        elif resp == b"REG_FAILED":
            print("[!] Registration failed. Username may already exist.")
            continue
        else:
            print(f"[!] Unknown response from server: {resp}")
            continue