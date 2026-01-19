import os, base64, json, struct

from utils.socket_utils import recv_all

from utils.PKI_utils import sign_bytes, verify_bytes, load_private_key
from utils.hash_utils import sha256

UPLOAD_DIR = os.path.join('client_path', 'upload')
DOWNLOAD_DIR = os.path.join('client_path', 'download')

KEY_DIR = os.path.join('client_path', 'certificates')

# ---------------- SEND FILE ----------------
def send_file(conn, filepath, username):
    key_file = os.path.join(KEY_DIR, f"{username}_key.pem")
    filename = os.path.basename(filepath)
    
    with open(filepath, "rb") as f:
        file_bytes = f.read()
    
    # Compute hash
    file_hash = sha256(file_bytes)
    
    # Sign the hash with client's private key
    private_key = load_private_key(key_file, None)
    file_signature = sign_bytes(private_key, file_hash)
    
    payload = json.dumps({
        "filename": filename,
        "content": base64.b64encode(file_bytes).decode(),
        "signature": base64.b64encode(file_signature).decode()
    }).encode()
    
    conn.send(b"FILE")
    conn.send(len(payload).to_bytes(8, "big"))
    conn.send(payload)
    print(f"[+] Sent file: {filename}")
    
def get_file_list(conn):
    
    conn.send(b"LIST")  # command to server

    length_bytes = conn.recv(8)
    if not length_bytes:
        return []
    length = int.from_bytes(length_bytes, 'big')
    data = conn.recv(length)
    files = json.loads(data.decode())
    return files

def download_file(conn, filename, file_pubkey):
    conn.send(b"DOWN")

    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, "big"))
    conn.send(fname_bytes)

    length_bytes = recv_all(conn, 8)
    if not length_bytes:
        print("[!] Server disconnected")
        return

    length = int.from_bytes(length_bytes, "big")
    payload_bytes = recv_all(conn, length)

    payload = json.loads(payload_bytes.decode())

    if "error" in payload:
        print(f"[!] Server error: {payload['error']}")
        return

    content_bytes = base64.b64decode(payload["content"])
    file_signature = base64.b64decode(payload["file_signature"])

    file_hash = sha256(content_bytes)

    try:
        verify_bytes(file_pubkey, file_hash, file_signature)
        print("[+] File signature verified!")
    except Exception as e:
        print(f"[!] File signature verification failed: {e}")
        return

    save_path = os.path.join(DOWNLOAD_DIR, filename)
    with open(save_path, "wb") as f:
        f.write(content_bytes)

    print(f"[+] File downloaded to {save_path}")