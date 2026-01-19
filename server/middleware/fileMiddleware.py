import base64
from cryptography import x509
from utils.PKI_utils import verify_bytes
from utils.hash_utils import sha256
from server.model.userModel import get_user_by_user_id

def verify_client_signature(payload, user_id):
    """
    Middleware to verify the signature sent by the client.
    Returns True if valid, False otherwise.
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

    # Load the certificate and extract the public key
    cert = x509.load_pem_x509_certificate(cert_pem)
    public_key = cert.public_key()

    # Generate hash of the file
    file_hash = sha256(file_bytes)

    # Verify using the public key
    try:
        verify_bytes(public_key, file_hash, client_signature)
        return True
    except Exception:
        return False