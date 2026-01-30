import time, base64, json
from cryptography import x509
from utils.PKI_utils import verify_bytes, sign_bytes, verify_cert_signed_by_root
from utils.hash_utils import sha256

from server.utils.cert_gen import ROOT_CERT_PATH

from server.model.userModel import get_user_by_user_id

def verify_client_signature(payload, user_id):
    """
    Middleware to verify the signature sent by the client.
    Returns True if valid and certificate is trusted, False otherwise.
    """

    file_bytes = base64.b64decode(payload["content"])
    client_signature = base64.b64decode(payload["signature"])

    # Fetch user's certificate path
    user = get_user_by_user_id(user_id)
    if not user:
        return False

    cert_path = user["cert_path"]
    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    # Load the root CA certificate
    with open(ROOT_CERT_PATH, "rb") as f:
        root_cert_pem = f.read()

    # Verify that the client cert is signed by the root CA
    if not verify_cert_signed_by_root(cert_pem, root_cert_pem):
        print("[!] Client certificate not trusted")
        return False

    # Load the certificate and extract the public key
    cert = x509.load_pem_x509_certificate(cert_pem)
    public_key = cert.public_key()

    # Generate hash of the file
    file_hash = sha256(file_bytes)

    # Verify the signature
    try:
        verify_bytes(public_key, file_hash, client_signature)
        return True
    except Exception:
        print("[!] Client signature invalid")
        return False

def create_upload_receipt(payload, saved_file, username, user_id, file_key):
    """
    Generate a signed receipt dictionary for a file including the client's signature.
    Signatures are base64-encoded.
    """
    file_bytes = base64.b64decode(payload["content"])
    file_hash = sha256(file_bytes)

    receipt = {
        "filename": saved_file,
        "uploaded_by": username,
        "user_id": user_id,
        "timestamp": int(time.time()),
        "file_hash": base64.b64encode(file_hash).decode(),  # base64 instead of hex
        "client_signature": payload["signature"]  # already base64
    }

    # Sign the receipt with server's file key
    receipt_bytes = json.dumps(receipt).encode()
    receipt_signature = sign_bytes(file_key, sha256(receipt_bytes))
    receipt["server_signature"] = base64.b64encode(receipt_signature).decode()  # base64

    return receipt


def create_download_receipt(filename, username, user_id, file_key):
    """
    Generate a signed receipt for a file download.
    Signatures are base64-encoded.
    """
    receipt = {
        "filename": filename,
        "downloaded_by": username,
        "user_id": user_id,
        "timestamp": int(time.time())
    }

    receipt_bytes = json.dumps(receipt).encode()
    receipt_signature = sign_bytes(file_key, sha256(receipt_bytes))
    receipt["server_signature"] = base64.b64encode(receipt_signature).decode()  # base64

    return receipt

def create_preview_receipt(filename, username, user_id, file_key):
    """
    Generate a signed receipt for a file preview.
    Signatures are base64-encoded.
    """
    receipt = {
        "filename": filename,
        "previewed_by": username,
        "user_id": user_id,
        "timestamp": int(time.time())
    }

    receipt_bytes = json.dumps(receipt).encode()
    receipt_signature = sign_bytes(file_key, sha256(receipt_bytes))
    receipt["server_signature"] = base64.b64encode(receipt_signature).decode()

    return receipt