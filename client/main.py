import socket
import ssl
import os

from client.utils.certificateValidation import (
    TRUSTED_ROOT_PATH,
    FILE_CERT_PATH,
    load_file_signing_public_key
)

from client.utils.auth_utils import authenticate_client
from client.utils.file_utils import send_file, download_file, get_file_list

HOST = '127.0.0.1'
PORT = 5001

UPLOAD_DIR = os.path.join('client_path', 'upload')
DOWNLOAD_DIR = os.path.join('client_path', 'download')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# ---------------- MAIN CLIENT ----------------
def main():
    file_pubkey = load_file_signing_public_key()
    if not file_pubkey:
        print("[!] Cannot continue without trusted file signing key")
        return

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(TRUSTED_ROOT_PATH)
    context.verify_mode = ssl.CERT_REQUIRED

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=HOST) as s:
            s.connect((HOST, PORT))
            print("[+] TLS connection established")

            username = authenticate_client(s)
            if not username:
                return  # user quit or failed auth

            while True:
                print("\n--- FILE MENU ---")
                print("1. Send file to server")
                print("2. List files from server")
                print("3. Download file from server")

                print("4. /quit")
                choice = input("Choose option: ").strip()

                if choice == "4" or choice.lower() == "/quit":
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
                        send_file(s, path, username)
                    else:
                        print("[!] File not found")
                        
                elif choice == "2":
                    files = get_file_list(s)
                    if files:
                        print("[+] Files on server:")
                        for f in files:
                            print(f" - {f}")
                    else:
                        print("[!] No files found")

                elif choice == "3":
                    filename = input("Enter filename to download: ").strip()
                    if filename:
                        download_file(s, filename, file_pubkey)
                        
                elif choice == "4":
                    receive_file(s, file_pubkey)

                else:
                    print("[!] Invalid option")


if __name__ == "__main__":
    main()