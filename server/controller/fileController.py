import base64

from utils.hash_utils import sha256
from utils.PKI_utils import sign_bytes
from server.model.fileModel import store_file, list_files, load_file

def save_file_controller(payload, file_key, user_id):
    """
    1. Store the file received over TLS (Before)
    2. Checks client signature and stores who uploaded it (Before)
    3. Sever signs it for non-repudiation
    4. Uses envelope encryption for confidentiality and integrity at rest
    
    Note: The payload contains Base64-encoded bytes.
    """
    
    filename = payload["filename"]
    file_bytes = base64.b64decode(payload["content"])  # Decode Base64 payload

    # Generate file hash (Signed by server)
    file_hash = sha256(file_bytes)
    signature = sign_bytes(file_key, file_hash)
    
    # Store file, model function does envelope encryption
    store_file(filename, file_bytes, signature, user_id)
    return filename

def get_file_list_controller():
    """Return a list of available files."""
    return list_files()

def get_encrypted_file_controller(filename):
    """
    Load file from model and prepare it for sending over TLS.
    Since TLS is already secure, we send the raw bytes + signature.
    Both are Base64 encoded for safe JSON transport.
    """
    result = load_file(filename)
    if result is None:
        return None

    plaintext, file_signature = result
    if plaintext is None:
        return None

    return {
        "filename": filename,
        "content": base64.b64encode(plaintext).decode(),  # encode file content in Base64
        "file_signature": file_signature
    }