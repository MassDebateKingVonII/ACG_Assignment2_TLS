from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509 import KeyUsage
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature
    
# ---------------- VERIFY CERTIFICATE ----------------
def verify_cert_signed_by_root(cert_pem: bytes, root_cert_pem: bytes) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    root_cert = x509.load_pem_x509_certificate(root_cert_pem)
    root_pubkey = root_cert.public_key()

    # Use offset-aware properties
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        print("[!] Certificate expired or not yet valid")
        return False

    try:
        if isinstance(root_pubkey, rsa.RSAPublicKey):
            root_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(root_pubkey, ec.EllipticCurvePublicKey):
            root_pubkey.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            print("[!] Unsupported CA key type")
            return False

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