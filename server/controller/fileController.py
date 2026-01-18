from utils.hash_utils import sha256
from utils.PKI_utils import sign_bytes
from server.model.fileModel import store_file, list_files, load_file

def save_file_controller(payload, server_key):
    """
    Store the file received over TLS and sign it for non-repudiation.
    The payload contains raw bytes (not encrypted at session layer).
    """
    filename = payload["filename"]
    file_bytes = bytes.fromhex(payload["content"])  # TLS payload is raw

    # Generate file hash
    file_hash = sha256(file_bytes)
    signature = sign_bytes(server_key, file_hash)
    
    # Store file (at rest, could be encrypted separately if desired)
    store_file(filename, file_bytes, signature)
    return filename

def get_file_list_controller():
    """Return a list of available files."""
    return list_files()

def get_encrypted_file_controller(filename):
    """
    Load file from model and prepare it for sending over TLS.
    Since TLS is already secure, we just send the raw bytes + signature.
    """
    result = load_file(filename)
    if result is None:
        return None

    plaintext, file_signature = result
    if plaintext is None:
        return None

    return {
        "filename": filename,
        "content": plaintext.hex(),  # send as hex string for JSON
        "file_signature": file_signature
    }