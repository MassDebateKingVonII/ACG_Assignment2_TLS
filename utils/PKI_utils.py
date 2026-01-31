from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509 import KeyUsage
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
    
# ---------------- VERIFY CERTIFICATE ----------------

def verify_cert_signed_by_root(cert_pem: bytes, root_cert_pem: bytes) -> bool:
    """
    Verify that a certificate is valid and signed by the given RSA root certificate.
    Returns True if valid and signature matches, False otherwise.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    root_cert = x509.load_pem_x509_certificate(root_cert_pem)
    root_pubkey = root_cert.public_key()

    # Use UTC-aware datetimes
    now = datetime.now(timezone.utc)

    # Use the new UTC-aware properties
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        print("[!] Certificate expired or not yet valid")
        return False

    # Ensure root key is RSA
    if not isinstance(root_pubkey, rsa.RSAPublicKey):
        print("[!] Root CA key is not RSA")
        return False

    # Verify certificate signature
    try:
        root_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        print("[!] Certificate signature invalid")
        return False

# ---------------- SIGN/VERIFY FILES ----------------
def sign_bytes(private_key, data: bytes) -> bytes:
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_bytes(public_key, data: bytes, signature: bytes) -> None:
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )