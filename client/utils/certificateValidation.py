from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

TRUSTED_ROOT_PATH = "client_path/trusted_root_store/root_cert.pem"
FILE_CERT_PATH = "client_path/trusted_root_store/file_sign_cert.pem"

def load_file_signing_public_key():
    # Load trusted root
    with open(TRUSTED_ROOT_PATH, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
        root_pubkey = root_cert.public_key()

    # Load file signing cert
    with open(FILE_CERT_PATH, "rb") as f:
        file_cert = x509.load_pem_x509_certificate(f.read())

    # Verify that file_cert is signed by root
    try:
        file_cert.signature_hash_algorithm  # ensures signature_hash_algorithm exists
        root_pubkey.verify(
            signature=file_cert.signature,
            data=file_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=file_cert.signature_hash_algorithm
        )
        print("[+] File signing certificate verified against root CA")
    except Exception as e:
        print(f"[!] File signing certificate verification failed: {e}")
        return None

    # Extract public key
    return file_cert.public_key()