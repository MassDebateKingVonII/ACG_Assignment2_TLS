import os, base64, json

from utils.PKI_utils import verify_bytes
from utils.hash_utils import sha256

UPLOAD_DIR = os.path.join('client_path', 'upload')
DOWNLOAD_DIR = os.path.join('client_path', 'download')

# ---------------- SEND FILE ----------------
def send_file(conn, filepath):
    filename = os.path.basename(filepath)
    with open(filepath, 'rb') as f:
        plaintext_bytes = f.read()

    payload = json.dumps({
        "filename": filename,
        "content": base64.b64encode(plaintext_bytes).decode()
    }).encode()

    conn.send(b"FILE")
    conn.send(len(payload).to_bytes(8, 'big'))
    conn.send(payload)
    print(f"[+] Sent file: {filename}")

# ---------------- RECEIVE FILE ----------------
def receive_file(conn, file_pubkey):
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

    filename = input("Enter filename to download (or /quit to cancel): ").strip()
    if filename.lower() == "/quit":
        return

    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, 'big'))
    conn.send(fname_bytes)

    length = int.from_bytes(conn.recv(8), 'big')
    payload_bytes = conn.recv(length)
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

    save_path = os.path.join(DOWNLOAD_DIR, payload["filename"])
    with open(save_path, 'wb') as f:
        f.write(content_bytes)

    print(f"[+] File downloaded to {save_path}")