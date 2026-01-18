import socket
import ssl
import os
import json

HOST = '127.0.0.1'
PORT = 5001

UPLOAD_DIR = os.path.join('client_path', 'upload')
DOWNLOAD_DIR = os.path.join('client_path', 'download')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ---------------- SEND FILE ----------------
def send_file(conn, filepath):
    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        plaintext_bytes = f.read()

    payload = json.dumps({
        "filename": filename,
        "content": plaintext_bytes.hex()
    }).encode()

    conn.send(b"FILE")
    conn.send(len(payload).to_bytes(8, 'big'))
    conn.send(payload)
    print(f"[+] Sent file: {filename}")

# ---------------- RECEIVE FILE ----------------
def receive_file(conn):
    conn.send(b"RECV")
    length = int.from_bytes(conn.recv(8), 'big')
    data = conn.recv(length)
    files = json.loads(data.decode())

    if not files:
        print("[!] No files available")
        return

    print("[+] Files available:")
    for f in files:
        print(f" - {f}")

    filename = input("Enter filename to download: ").strip()
    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, 'big'))
    conn.send(fname_bytes)

    length = int.from_bytes(conn.recv(8), 'big')
    payload_bytes = conn.recv(length)
    payload = json.loads(payload_bytes.decode())

    if "error" in payload:
        print(f"[!] Server error: {payload['error']}")
        return

    content_bytes = bytes.fromhex(payload["content"])
    save_path = os.path.join(DOWNLOAD_DIR, payload["filename"])
    with open(save_path, 'wb') as f:
        f.write(content_bytes)

    print(f"[+] File downloaded to download/{payload['filename']}")

# ---------------- MAIN CLIENT ----------------
def main():
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations("client_path/trusted_root_store/root_cert.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with context.wrap_socket(raw_sock, server_hostname=HOST) as s:
        s.connect((HOST, PORT))
        print("[+] TLS connection established")

        while True:
            print("\n--- MENU ---")
            print("1. Send file to server")
            print("2. Receive file from server")
            print("3. /quit")

            choice = input("Choose option: ").strip()

            if choice == "3" or choice.lower() == "/quit":
                s.send(b"QUIT")
                print("[+] Client disconnected")
                break
            elif choice == "1":
                files = os.listdir(UPLOAD_DIR)
                if not files:
                    print("[!] No files to send")
                    continue

                print("[+] Files in upload/:")
                for f in files:
                    print(f" - {f}")

                fname = input("Enter filename: ").strip()
                path = os.path.join(UPLOAD_DIR, fname)
                if os.path.exists(path):
                    send_file(s, path)
                else:
                    print("[!] File not found")
            elif choice == "2":
                receive_file(s)
            else:
                print("[!] Invalid option")

if __name__ == "__main__":
    main()