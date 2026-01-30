import os, base64, json

from client.utils.CSR_utils import KEY_FILE_PATH

from utils.socket_utils import send_resp, recv_all
from utils.PKI_utils import sign_bytes, verify_bytes
from utils.hash_utils import sha256
from utils.cert_utils import load_private_key

# ---------------- SEND FILE ----------------
def send_file(conn, filepath, username, server_pubkey):
    """
    Send a file to the server and wait for a signed receipt.
    
    Args:
        conn: TLS socket
        filepath: path to local file to upload
        username: uploader username
        server_pubkey: server's public key for verifying receipt
    """

    key_file = os.path.join(KEY_FILE_PATH, f"{username}_key.pem")
    filename = os.path.basename(filepath)
    
    key_passphrase = conn.key_passphrase

    # Read file bytes
    with open(filepath, "rb") as f:
        file_bytes = f.read()

    # Compute hash
    file_hash = sha256(file_bytes)

    # Sign hash with client's private key
    private_key = load_private_key(key_file, key_passphrase)
    file_signature = sign_bytes(private_key, file_hash)

    # Build payload
    payload = json.dumps({
        "filename": filename,
        "content": base64.b64encode(file_bytes).decode(),
        "signature": base64.b64encode(file_signature).decode()
    }).encode()

    # Send file command and payload
    conn.send(b"FILE")
    send_resp(conn, payload)
    print(f"[+] Sent file: {filename}")

    # Wait for receipt from server
    try:
        length_bytes = recv_all(conn, 8)
        if not length_bytes:
            print("[!] Server disconnected before sending receipt")
            return

        length = int.from_bytes(length_bytes, "big")
        receipt_bytes = recv_all(conn, length)
        receipt = json.loads(receipt_bytes.decode())

        # Extract server signature (Base64) and verify
        receipt_signature_b64 = receipt.pop("server_signature")  # remove before verification
        receipt_signature = base64.b64decode(receipt_signature_b64)

        receipt_data = json.dumps(receipt).encode()
        receipt_hash = sha256(receipt_data)

        verify_bytes(server_pubkey, receipt_hash, receipt_signature)
        print(f"[+] Receipt verified! File {filename} uploaded successfully.")

    except Exception as e:
        print(f"[!] Failed to verify receipt: {e}")
    
def get_file_list(conn):
    conn.send(b"LIST")

    length_bytes = recv_all(conn, 8)
    if not length_bytes:
        return []

    length = int.from_bytes(length_bytes, 'big')

    data = recv_all(conn, length)
    if not data:
        return []

    files = json.loads(data.decode())
    # ensure every item is a dict with correct keys
    result = []
    for f in files:
        if isinstance(f, dict) and 'filename' in f and 'uploaded_by' in f and 'created_at' in f:
            result.append(f)
        elif isinstance(f, list) and len(f) >= 3:
            # convert list to dict
            result.append({'filename': f[0], 'uploaded_by': f[1], 'created_at': f[2]})
    return result

def download_file(conn, filename, file_pubkey, save_path):
    # ---------------- REQUEST FILE ----------------
    conn.send(b"DOWN")
    fname_bytes = filename.encode()
    send_resp(conn, fname_bytes)

    # ---------------- RECEIVE FILE ----------------
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

    # ---------------- VERIFY SIGNATURE ----------------
    file_hash = sha256(content_bytes)
    try:
        verify_bytes(file_pubkey, file_hash, file_signature)
        print("[+] File signature verified!")
    except Exception as e:
        print(f"[!] File signature verification failed: {e}")
        return

    # ---------------- SAVE FILE ----------------
    with open(save_path, "wb") as f:
        f.write(content_bytes)

    print(f"[+] File saved to: {save_path}")
    
    # ---------------- RECEIVE SERVER RECEIPT ----------------
    try:
        receipt_len_bytes = recv_all(conn, 8)
        if not receipt_len_bytes:
            print("[!] Server disconnected before sending receipt")
            return

        receipt_len = int.from_bytes(receipt_len_bytes, "big")
        receipt_bytes = recv_all(conn, receipt_len)
        receipt = json.loads(receipt_bytes.decode())

        # Verify server's signature on the receipt
        server_sig = base64.b64decode(receipt["server_signature"])
        receipt_copy = receipt.copy()
        print("Receipt sent by Server:\n", receipt_copy)
        
        del receipt_copy["server_signature"]  # remove before verification
        receipt_data = json.dumps(receipt_copy).encode()
        receipt_hash = sha256(receipt_data)

        verify_bytes(file_pubkey, receipt_hash, server_sig)
        print(f"[+] Download receipt verified! File {filename} download confirmed.")

    except Exception as e:
        print(f"[!] Failed to verify download receipt: {e}")
        
def fetch_preview_bytes(conn, filename: str, file_pubkey) -> bytes | None:
    """
    Request a preview from server, verify file signature AND verify server preview receipt.
    Returns preview plaintext bytes on success, else None.
    """
    conn.send(b"PREV")
    send_resp(conn, filename.encode())

    length_bytes = recv_all(conn, 8)
    if not length_bytes:
        print("[!] Server disconnected")
        return None

    length = int.from_bytes(length_bytes, "big")
    payload_bytes = recv_all(conn, length)

    try:
        payload = json.loads(payload_bytes.decode())
    except Exception as e:
        print(f"[!] Invalid JSON from server: {e}")
        return None

    if "error" in payload:
        print(f"[!] Server error: {payload['error']}")
        return None

    try:
        preview_bytes = base64.b64decode(payload["preview"])
        file_signature = base64.b64decode(payload["file_signature"])
    except Exception as e:
        print(f"[!] Bad preview payload format: {e}")
        return None

    # Must-pass integrity check
    file_hash = sha256(preview_bytes)
    try:
        verify_bytes(file_pubkey, file_hash, file_signature)
        print("[+] Preview file signature verified!")
    except Exception as e:
        print(f"[!] Preview file signature verification failed: {e}")
        return None

    # Best-effort receipt verification (do NOT block preview)
    try:
        receipt_len_bytes = recv_all(conn, 8)
        if not receipt_len_bytes:
            print("[!] Server disconnected before sending receipt")
            return preview_bytes

        receipt_len = int.from_bytes(receipt_len_bytes, "big")
        receipt_bytes = recv_all(conn, receipt_len)
        receipt = json.loads(receipt_bytes.decode())

        server_sig = base64.b64decode(receipt["server_signature"])
        receipt_copy = receipt.copy()
        del receipt_copy["server_signature"]

        receipt_hash = sha256(json.dumps(receipt_copy).encode())
        verify_bytes(file_pubkey, receipt_hash, server_sig)
        print(f"[+] Preview receipt verified! File {filename} preview confirmed.")
    except Exception as e:
        print(f"[!] Failed to verify preview receipt (preview still allowed): {e}")

    return preview_bytes
