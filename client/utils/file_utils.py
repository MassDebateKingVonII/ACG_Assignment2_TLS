import os, base64, json, struct

from PIL import Image, ImageTk
import tkinter as tk
import io

from utils.socket_utils import recv_all

from utils.PKI_utils import sign_bytes, verify_bytes, load_private_key
from utils.hash_utils import sha256

UPLOAD_DIR = os.path.join('client_path', 'upload')
DOWNLOAD_DIR = os.path.join('client_path', 'download')

KEY_DIR = os.path.join('client_path', 'certificates')

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

    key_file = os.path.join(KEY_DIR, f"{username}_key.pem")
    filename = os.path.basename(filepath)

    # Read file bytes
    with open(filepath, "rb") as f:
        file_bytes = f.read()

    # Compute hash
    file_hash = sha256(file_bytes)

    # Sign hash with client's private key
    private_key = load_private_key(key_file, None)
    file_signature = sign_bytes(private_key, file_hash)

    # Build payload
    payload = json.dumps({
        "filename": filename,
        "content": base64.b64encode(file_bytes).decode(),
        "signature": base64.b64encode(file_signature).decode()
    }).encode()

    # Send file command and payload
    conn.send(b"FILE")
    conn.send(len(payload).to_bytes(8, "big"))
    conn.send(payload)
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
    
    conn.send(b"LIST")  # command to server

    length_bytes = conn.recv(8)
    if not length_bytes:
        return []
    length = int.from_bytes(length_bytes, 'big')
    data = conn.recv(length)
    files = json.loads(data.decode())
    return files

def download_file(conn, filename, file_pubkey, download_dir=DOWNLOAD_DIR):
    # ---------------- REQUEST FILE ----------------
    conn.send(b"DOWN")
    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, "big"))
    conn.send(fname_bytes)

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

    # Verify file signature
    file_hash = sha256(content_bytes)
    try:
        verify_bytes(file_pubkey, file_hash, file_signature)
        print("[+] File signature verified!")
    except Exception as e:
        print(f"[!] File signature verification failed: {e}")
        return

    # Save the file locally
    save_path = os.path.join(download_dir, filename)
    with open(save_path, "wb") as f:
        f.write(content_bytes)
    print(f"[+] File downloaded to {save_path}")

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
        print(receipt_copy)
        del receipt_copy["server_signature"]  # remove before verification
        receipt_data = json.dumps(receipt_copy).encode()
        print(receipt_data)
        receipt_hash = sha256(receipt_data)

        verify_bytes(file_pubkey, receipt_hash, server_sig)
        print(f"[+] Download receipt verified! File {filename} download confirmed.")

    except Exception as e:
        print(f"[!] Failed to verify download receipt: {e}")
        
def preview_file(self, conn, filename):
    conn.send(b"PREV")
    fname_bytes = filename.encode()
    conn.send(len(fname_bytes).to_bytes(8, "big"))
    conn.send(fname_bytes)

    # Receive preview payload
    length_bytes = recv_all(conn, 8)
    if not length_bytes:
        print("[!] Server disconnected")
        return

    length = int.from_bytes(length_bytes, "big")
    payload_bytes = recv_all(conn, length)
    payload = json.loads(payload_bytes.decode())

    if "error" in payload:
        self.preview_text.insert(tk.END, f"[!] Server error: {payload['error']}\n")
        return

    preview_bytes = base64.b64decode(payload["preview"])
    self.preview_text.delete(1.0, tk.END)  # Clear previous preview

    # Text preview
    if filename.lower().endswith((".txt", ".py", ".md")):
        try:
            text = preview_bytes.decode("utf-8")
            self.preview_text.insert(tk.END, text)
        except UnicodeDecodeError:
            self.preview_text.insert(tk.END, "[!] Cannot decode file as text\n")

    # Image preview
    elif filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
        try:
            from PIL import Image, ImageTk
            import io

            img = Image.open(io.BytesIO(preview_bytes))
            img.thumbnail((400, 400))  # Resize
            self.img_preview = ImageTk.PhotoImage(img)  # Keep reference
            self.preview_text.image_create(tk.END, image=self.img_preview)
        except Exception as e:
            self.preview_text.insert(tk.END, f"[!] Failed to preview image: {e}\n")

    else:
        self.preview_text.insert(tk.END, "[!] Preview not supported for this file type\n")